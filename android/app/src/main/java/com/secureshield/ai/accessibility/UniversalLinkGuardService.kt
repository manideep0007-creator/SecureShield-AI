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
import com.secureshield.ai.network.ClientIdProvider
import com.secureshield.ai.network.ServerSettings
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse
import com.secureshield.ai.network.UnifiedScanResponseParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * Universal, app-agnostic link threat detector AccessibilityService.
 * Listens to on-screen window changes across ANY app on the device without per-app special casing.
 */
class UniversalLinkGuardService : AccessibilityService() {

    internal var serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val lastWindowContentHashes = ConcurrentHashMap<Int, Int>()
    private val inFlightUrls = ConcurrentHashMap.newKeySet<String>()
    internal var rateLimiter = ScanRateLimiter(maxScansPerMinute = 10)
    internal var retryDelayMillis: Long = 3000L
    internal var apiOverride: com.secureshield.ai.network.SecureShieldApi? = null

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

    internal suspend fun processVisibleText(visibleText: String, sourcePackage: String) {
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
                    val success = try {
                        scanAndReport(input, sourcePackage, targetDisplay = url)
                    } catch (e: Exception) {
                        if (e is CancellationException) throw e
                        android.util.Log.e("GuardianService", "Unhandled error during scan: ${e.message}", e)
                        false
                    }

                    if (!success) {
                        android.util.Log.w("GuardianService", "Scan failed for URL: $url. Unmarking to allow future scans.")
                        ProcessedMessageStore.unmarkUrl(applicationContext, url)
                    }
                } finally {
                    inFlightUrls.remove(url)
                }
            }
        } else {
            // Optional short suspicious text analysis when no URL is present
            val snippet = UniversalLinkExtractor.extractSuspiciousTextSnippet(visibleText)
            if (snippet != null) {
                // 1. Redact sensitive values (OTPs/long digits, passwords, tokens, phone numbers, emails)
                val sanitizedSnippet = UniversalLinkExtractor.sanitizeSnippet(snippet)

                // 2. If redaction removes more than half the snippet, skip the scan
                if (UniversalLinkExtractor.isMostlyRedacted(snippet, sanitizedSnippet)) {
                    android.util.Log.d("GuardianService", "Snippet mostly redacted (${snippet.length} chars). Skipping scan for privacy.")
                    return
                }

                val textKey = "text:${sanitizedSnippet.hashCode()}"
                if (!inFlightUrls.add(textKey)) return
                try {
                    if (ProcessedMessageStore.isUrlProcessed(applicationContext, textKey)) {
                        return
                    }
                    if (!rateLimiter.tryAcquire()) {
                        return
                    }
                    ProcessedMessageStore.markUrlProcessed(applicationContext, textKey)

                    android.util.Log.i("GuardianService", "Dispatching redacted text scan for snippet (Source: $sourcePackage)")
                    val input = ScanInput(
                        text = sanitizedSnippet,
                        source_channel = "guardian",
                        metadata = mapOf(
                            "source_package" to sourcePackage,
                            "detector" to "SecureShieldGuardianService"
                        )
                    )
                    val success = try {
                        scanAndReport(input, sourcePackage, targetDisplay = sanitizedSnippet)
                    } catch (e: Exception) {
                        if (e is CancellationException) throw e
                        android.util.Log.e("GuardianService", "Unhandled error during scan: ${e.message}", e)
                        false
                    }

                    if (!success) {
                        android.util.Log.w("GuardianService", "Scan failed for textKey: $textKey. Unmarking to allow future scans.")
                        ProcessedMessageStore.unmarkUrl(applicationContext, textKey)
                    }
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

    internal suspend fun scanAndReport(
        scanInput: ScanInput,
        sourcePackage: String,
        targetDisplay: String
    ): Boolean {
        try {
            ServerSettings.init(applicationContext)
        } catch (_: Exception) {
            // Best effort settings init
        }

        val api = apiOverride ?: ApiClient.api
        val resolvedInput = if (scanInput.client_id.isNullOrBlank()) {
            scanInput.copy(client_id = ClientIdProvider.getClientId(applicationContext))
        } else {
            scanInput
        }

        // 1. Initial attempt
        val firstOutcome = executeSingleScan(api, resolvedInput, sourcePackage, targetDisplay)
        if (firstOutcome is ScanAttemptOutcome.Success) {
            return true
        }

        // Do not retry on 4xx client errors or non-retryable failures
        if (firstOutcome is ScanAttemptOutcome.NonRetryableFailure) {
            android.util.Log.w("GuardianService", "Scan failed non-retryably for $targetDisplay: ${firstOutcome.reason}")
            return false
        }

        // 2. Retryable failure (5xx or connection/timeout) - backoff before retry
        val retryReason = (firstOutcome as? ScanAttemptOutcome.RetryableFailure)?.reason ?: "unknown"
        android.util.Log.w("GuardianService", "Scan attempt 1 failed ($retryReason) for $targetDisplay. Backing off for ${retryDelayMillis}ms before retry...")

        if (retryDelayMillis > 0) {
            delay(retryDelayMillis)
        }

        // Keep existing rate limiter in force across retries
        if (!rateLimiter.tryAcquire()) {
            android.util.Log.w("GuardianService", "Rate limiter blocked retry scan for $targetDisplay")
            return false
        }

        // 3. Retry attempt
        val retryOutcome = executeSingleScan(api, resolvedInput, sourcePackage, targetDisplay)
        return if (retryOutcome is ScanAttemptOutcome.Success) {
            android.util.Log.i("GuardianService", "Retry scan succeeded for: $targetDisplay")
            true
        } else {
            val failureReason = when (retryOutcome) {
                is ScanAttemptOutcome.RetryableFailure -> retryOutcome.reason
                is ScanAttemptOutcome.NonRetryableFailure -> retryOutcome.reason
                else -> "unknown"
            }
            android.util.Log.w("GuardianService", "Retry scan failed for $targetDisplay: $failureReason")
            false
        }
    }

    private suspend fun executeSingleScan(
        api: com.secureshield.ai.network.SecureShieldApi,
        scanInput: ScanInput,
        sourcePackage: String,
        targetDisplay: String
    ): ScanAttemptOutcome {
        return try {
            val response = api.scan(scanInput)
            if (response.isSuccessful) {
                val body = response.body()
                if (body == null) {
                    ScanAttemptOutcome.NonRetryableFailure("Null response body")
                } else {
                    try {
                        val scanResult = UnifiedScanResponseParser.parse(body)
                        try {
                            val repo = ScanHistoryRepository(applicationContext)
                            repo.saveCompletedScan(scanResult, "accessibility_guard")
                            repo.close()
                        } catch (e: Exception) {
                            android.util.Log.e("GuardianService", "Failed to save scan history: ${e.message}")
                        }
                        try {
                            handleScanVerdict(scanResult, sourcePackage, targetDisplay)
                        } catch (e: Exception) {
                            android.util.Log.e("GuardianService", "Failed to handle scan verdict: ${e.message}")
                        }
                        ScanAttemptOutcome.Success
                    } catch (e: Exception) {
                        ScanAttemptOutcome.NonRetryableFailure("Malformed scan response: ${e.message}")
                    }
                }
            } else {
                val code = response.code()
                if (code in 400..499) {
                    ScanAttemptOutcome.NonRetryableFailure("HTTP $code")
                } else if (code >= 500) {
                    ScanAttemptOutcome.RetryableFailure("HTTP $code")
                } else {
                    ScanAttemptOutcome.NonRetryableFailure("HTTP $code")
                }
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            ScanAttemptOutcome.RetryableFailure("Connection failure: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private sealed class ScanAttemptOutcome {
        object Success : ScanAttemptOutcome()
        data class RetryableFailure(val reason: String?) : ScanAttemptOutcome()
        data class NonRetryableFailure(val reason: String?) : ScanAttemptOutcome()
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

