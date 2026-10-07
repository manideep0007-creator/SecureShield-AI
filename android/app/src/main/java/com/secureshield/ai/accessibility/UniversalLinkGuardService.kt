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
    private val rateLimiter = ScanRateLimiter(maxScansPerMinute = 10)

    companion object {
        const val NOTIFICATION_CHANNEL_ID = "SS_ALERTS"
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

        // 5. Walk tree and extract visible text
        val visibleText = UniversalLinkExtractor.extractAllVisibleText(rootNode)
        if (visibleText.isBlank()) return

        // 6. Content-hash debounce: skip if text in this window is unchanged
        val contentHash = visibleText.hashCode()
        val windowId = event.windowId
        if (lastWindowContentHashes[windowId] == contentHash) {
            return
        }
        lastWindowContentHashes[windowId] = contentHash

        // 7. Regex extract URLs
        val urls = UniversalLinkExtractor.extractUrlsFromText(visibleText)
        if (urls.isEmpty()) return

        android.util.Log.d("UniversalLinkGuard", "Detected ${urls.size} URL(s) in active window of package: $sourcePackage")

        // 8. Deduplicate and Rate-Limit before scanning
        for (url in urls) {
            // Short-TTL cache: skip if seen within ~10 minutes
            if (ProcessedMessageStore.isUrlProcessed(applicationContext, url)) {
                android.util.Log.d("UniversalLinkGuard", "Skipping URL within 10-min cache: $url")
                continue
            }

            // Hard rate-limit: drop excess scans rather than queuing
            if (!rateLimiter.tryAcquire()) {
                android.util.Log.w("UniversalLinkGuard", "Rate limit exceeded (10 scans/min). Dropping URL: $url")
                continue
            }

            // Immediately mark as processed to prevent race conditions from rapid events
            ProcessedMessageStore.markUrlProcessed(applicationContext, url)

            // Dispatch URL scan asynchronously
            android.util.Log.i("UniversalLinkGuard", "Dispatching scan to backend for URL: $url (Source: $sourcePackage)")
            dispatchUrlScan(url, sourcePackage)
        }
    }

    override fun onInterrupt() {
        // Accessibility service interrupted by system
    }

    override fun onDestroy() {
        serviceScope.cancel()
        lastWindowContentHashes.clear()
        super.onDestroy()
    }

    private fun dispatchUrlScan(url: String, sourcePackage: String) {
        serviceScope.launch {
            try {
                val scanInput = ScanInput(
                    url = url,
                    source_channel = "universal_guard",
                    metadata = mapOf(
                        "source_package" to sourcePackage,
                        "detector" to "UniversalLinkGuardService"
                    )
                )

                val response = ApiClient.api.scan(scanInput)
                if (response.isSuccessful) {
                    val body = response.body() ?: return@launch
                    val scanResult = UnifiedScanResponseParser.parse(body)

                    // Persist scan result to local scan history
                    val repo = ScanHistoryRepository(applicationContext)
                    repo.saveCompletedScan(scanResult, "accessibility_guard")
                    repo.close()

                    // Handle verdict
                    handleScanVerdict(scanResult, sourcePackage, url)
                }
            } catch (_: Exception) {
                // Network or parsing failure; cache & rate-limiter prevent retrying in a storm
            }
        }
    }

    private fun handleScanVerdict(result: UnifiedScanResponse, sourcePackage: String, url: String) {
        val isThreat = THREAT_CATEGORIES.any { it.equals(result.classification, ignoreCase = true) }
        android.util.Log.i(
            "UniversalLinkGuard",
            "Verdict for $url: ${result.classification} (Score: ${result.risk_score}, Threat: $isThreat)"
        )

        // Safe or excluded -> no notification, no action
        if (!isThreat) {
            return
        }

        // Suspicious/Deceptive/Phishing/Malware -> fire high-priority notification on SS_ALERTS channel
        sendThreatNotification(result, sourcePackage, url)
    }

    private fun sendThreatNotification(
        scanResult: UnifiedScanResponse,
        sourcePackage: String,
        url: String
    ) {
        ensureNotificationChannel()

        android.util.Log.w(
            "UniversalLinkGuard",
            "Posting threat notification for ${scanResult.classification} from package: $sourcePackage"
        )

        val appLabel = try {
            val pm = packageManager
            val appInfo = pm.getApplicationInfo(sourcePackage, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (_: Exception) {
            sourcePackage
        }

        val topReason = scanResult.risk_assessment.reasons.firstOrNull()
            ?: scanResult.risk_assessment.recommended_action.ifBlank { "Malicious link detected on screen" }

        // Tapping notification opens the full result screen in ScanHistoryActivity
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

        val notificationTitle = "🚨 ${scanResult.classification} Link in $appLabel"
        val message = "$topReason\nURL: $url"

        val builder = NotificationCompat.Builder(applicationContext, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(notificationTitle)
            .setContentText(topReason)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
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
