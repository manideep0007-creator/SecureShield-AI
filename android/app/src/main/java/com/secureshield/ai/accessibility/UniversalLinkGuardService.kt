package com.secureshield.ai.accessibility

import android.accessibilityservice.AccessibilityService
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.view.accessibility.AccessibilityEvent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.secureshield.ai.ScanHistoryActivity
import com.secureshield.ai.background.ProcessedMessageStore
import com.secureshield.ai.history.ScanHistoryRepository
import com.secureshield.ai.network.ApiClient
import com.secureshield.ai.network.ServerSettings
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse
import com.secureshield.ai.network.UnifiedScanResponseParser
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * Universal, app-agnostic link threat detector AccessibilityService.
 * Listens to on-screen window changes across ANY app on the device without per-app special casing.
 */
class UniversalLinkGuardService : AccessibilityService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val lastWindowContentHashes = ConcurrentHashMap<Int, Int>()
    private val inFlightUrls = ConcurrentHashMap.newKeySet<String>()
    private val rateLimiter = ScanRateLimiter(maxScansPerMinute = 10)

    companion object {
        const val NOTIFICATION_CHANNEL_ID = "SS_ALERTS"
        private const val MAX_TRACKED_WINDOWS = 32
        private val THREAT_CATEGORIES = setOf("Suspicious", "Deceptive", "Phishing", "Malware")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        // 1. Strictly restrict to TYPE_WINDOW_CONTENT_CHANGED and TYPE_WINDOW_STATE_CHANGED
        val eventType = event.eventType
        if (eventType != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED &&
            eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            return
        }

        // 2. Check if user enabled the protection toggle in SecureShield
        if (!UniversalLinkGuardManager.isUserPreferenceEnabled(applicationContext)) {
            return
        }

        // 3. Skip events from SecureShield itself to avoid scan loops when showing alerts/history
        val sourcePackage = event.packageName?.toString() ?: "unknown"
        if (sourcePackage == packageName) {
            return
        }

        // 4. Retrieve active window root node (completely app-agnostic)
        val rootNode = rootInActiveWindow ?: event.source ?: return

        // 5. Walk tree and extract visible text (must run on the event thread;
        //    node trees are only valid during the callback).
        val visibleText = UniversalLinkExtractor.extractAllVisibleText(rootNode)
        if (visibleText.isBlank()) return

        // 6. Content-hash debounce: skip if text in this window is unchanged
        val contentHash = visibleText.hashCode()
        val windowId = event.windowId
        if (lastWindowContentHashes[windowId] == contentHash) {
            return
        }
        // Bound growth: window ids are recycled by the system and would otherwise
        // accumulate without limit. Clearing is safe; the URL cache still dedupes.
        if (lastWindowContentHashes.size >= MAX_TRACKED_WINDOWS && !lastWindowContentHashes.containsKey(windowId)) {
            lastWindowContentHashes.clear()
        }
        lastWindowContentHashes[windowId] = contentHash

        // 7. Regex extraction and every SharedPreferences read/write happen on the
        //    IO dispatcher below — this callback runs on the main thread and the
        //    store re-serializes up to 500 entries per mark, which risks ANRs.
        serviceScope.launch {
            processVisibleText(visibleText, sourcePackage)
        }
    }

    private suspend fun processVisibleText(visibleText: String, sourcePackage: String) {
        val urls = UniversalLinkExtractor.extractUrlsFromText(visibleText)
        if (urls.isNotEmpty()) {
            android.util.Log.d("GuardianService", "Detected ${urls.size} URL(s) in active window of package: $sourcePackage")
            for (url in urls) {
                if (!inFlightUrls.add(url)) continue
                try {
                    // Short-TTL cache: skip if seen within ~10 minutes
                    if (ProcessedMessageStore.isUrlProcessed(applicationContext, url)) {
                        continue
                    }

                    // Hard rate-limit: drop excess scans rather than queuing
                    if (!rateLimiter.tryAcquire()) {
                        android.util.Log.w("GuardianService", "Rate limit exceeded. Dropping URL: $url")
                        continue
                    }

                    // Mark before scanning to prevent retry storms on failures
                    ProcessedMessageStore.markUrlProcessed(applicationContext, url)

                    android.util.Log.i("GuardianService", "Dispatching URL scan for: $url (Source: $sourcePackage)")
                    val input = ScanInput(
                        url = url,
                        source_channel = "guardian",
                        metadata = mapOf(
                            "source_package" to sourcePackage,
                            "detector" to "SecureShieldGuardianService"
                        )
                    )
                    scanAndReport(input, sourcePackage, targetDisplay = url)
                } finally {
                    inFlightUrls.remove(url)
                }
            }
        } else {
            // Optional short suspicious text analysis when no URL is present
            val snippet = UniversalLinkExtractor.extractSuspiciousTextSnippet(visibleText)
            if (snippet != null) {
                val textKey = "text:${snippet.hashCode()}"
                if (!inFlightUrls.add(textKey)) return
                try {
                    if (ProcessedMessageStore.isUrlProcessed(applicationContext, textKey)) {
                        return
                    }
                    if (!rateLimiter.tryAcquire()) {
                        return
                    }
                    ProcessedMessageStore.markUrlProcessed(applicationContext, textKey)

                    android.util.Log.i("GuardianService", "Dispatching text scan for snippet (Source: $sourcePackage)")
                    val input = ScanInput(
                        text = snippet,
                        source_channel = "guardian",
                        metadata = mapOf(
                            "source_package" to sourcePackage,
                            "detector" to "SecureShieldGuardianService"
                        )
                    )
                    scanAndReport(input, sourcePackage, targetDisplay = snippet)
                } finally {
                    inFlightUrls.remove(textKey)
                }
            }
        }
    }

    override fun onInterrupt() {
        // Accessibility service interrupted by system
    }

    override fun onDestroy() {
        serviceScope.cancel()
        lastWindowContentHashes.clear()
        inFlightUrls.clear()
        super.onDestroy()
    }

    private suspend fun scanAndReport(scanInput: ScanInput, sourcePackage: String, targetDisplay: String) {
        try {
            ServerSettings.init(applicationContext)

            val response = ApiClient.api.scan(scanInput)
            if (response.isSuccessful) {
                val body = response.body() ?: return
                val scanResult = UnifiedScanResponseParser.parse(body)

                // Persist scan result to local scan history
                val repo = ScanHistoryRepository(applicationContext)
                repo.saveCompletedScan(scanResult, "accessibility_guard")
                repo.close()

                // Handle verdict
                handleScanVerdict(scanResult, sourcePackage, targetDisplay)
            }
        } catch (_: Exception) {
            // Fail-safe: Network or parsing failure; do not claim safe, do not crash service.
        }
    }

    private fun handleScanVerdict(result: UnifiedScanResponse, sourcePackage: String, targetDisplay: String) {
        val isThreat = THREAT_CATEGORIES.any { it.equals(result.classification, ignoreCase = true) }
        android.util.Log.i(
            "GuardianService",
            "Verdict for target: ${result.classification} (Score: ${result.risk_score}, Threat: $isThreat)"
        )

        // Safe or excluded -> no notification, do not interfere with normal experience
        if (!isThreat) {
            return
        }

        // Suspicious/Deceptive/Phishing/Malware -> fire high-priority notification on SS_ALERTS channel
        sendThreatNotification(result, sourcePackage, targetDisplay)
    }

    private fun sendThreatNotification(
        scanResult: UnifiedScanResponse,
        sourcePackage: String,
        targetDisplay: String
    ) {
        ensureNotificationChannel()

        val appLabel = try {
            val pm = packageManager
            val appInfo = pm.getApplicationInfo(sourcePackage, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (_: Exception) {
            sourcePackage
        }

        val topReason = scanResult.risk_assessment.reasons.firstOrNull()
            ?: scanResult.risk_assessment.recommended_action.ifBlank { "Potential threat detected on screen" }

        // Tapping notification opens the result in ScanHistoryActivity
        val intent = Intent(applicationContext, ScanHistoryActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("scan_id", scanResult.scan_id)
        }
        val pendingIntent = PendingIntent.getActivity(
            applicationContext,
            scanResult.scan_id.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notificationTitle = "🚨 SecureShield Alert in $appLabel"
        val alertSummary = "${scanResult.classification} detected (Risk Score: ${scanResult.risk_score.toInt()}/100)"
        val bigMessage = buildString {
            appendLine("App: $appLabel ($sourcePackage)")
            appendLine("Threat: ${scanResult.classification} (Risk: ${scanResult.risk_score.toInt()}/100)")
            appendLine("Reason: $topReason")
            append("Target: $targetDisplay")
        }

        val builder = NotificationCompat.Builder(applicationContext, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(notificationTitle)
            .setContentText(alertSummary)
            .setStyle(NotificationCompat.BigTextStyle().bigText(bigMessage))
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)

        try {
            NotificationManagerCompat.from(applicationContext)
                .notify(scanResult.scan_id.hashCode(), builder.build())
        } catch (_: SecurityException) {
            // Missing notification permission
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "SecureShield Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority alerts for detected security threats"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }
}

