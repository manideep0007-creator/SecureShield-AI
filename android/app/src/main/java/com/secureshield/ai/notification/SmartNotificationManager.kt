package com.secureshield.ai.notification

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.secureshield.ai.GuardianInterceptActivity
import com.secureshield.ai.R
import com.secureshield.ai.network.UnifiedScanResponse
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * Centralized Smart Threat Alert Decision & Notification System.
 *
 * Implements strict security notification policy:
 * - SAFE: Never sends a threat notification.
 * - LOW RISK: Never sends a threat notification.
 * - MEDIUM RISK: In-app warning only; no unsolicited push notification.
 * - HIGH RISK: Sends a security warning with corroborated threat evidence.
 * - CRITICAL / CONFIRMED MALICIOUS: Sends an immediate high-priority security notification.
 *
 * Prevents notification spam via persistent deduplication, threat ID fingerprinting,
 * and intelligent alert cooldown windows.
 */
object SmartNotificationManager {

    const val NOTIFICATION_CHANNEL_ID = "SS_ALERTS"
    const val PREFS_NAME = "smart_notification_state"
    private const val KEY_PREFIX_TIMESTAMP = "threat_ts_"
    private const val KEY_PREFIX_SEVERITY = "threat_sev_"
    private const val ALERT_COOLDOWN_MILLIS = 15 * 60 * 1000L // 15-minute cooldown for identical threat

    private val inMemoryCooldown = ConcurrentHashMap<String, Long>()
    private val inMemoryTier = ConcurrentHashMap<String, NotificationTier>()

    enum class NotificationTier {
        NONE,               // Suppress notification entirely
        IN_APP_ONLY,        // Visible in app HUD/banner, no push notification
        SECURITY_WARNING,   // High-risk alert with specific evidence
        CRITICAL_ALERT      // Immediate confirmed threat alert (Phishing, Malware)
    }

    data class NotificationDecision(
        val tier: NotificationTier,
        val shouldPostNotification: Boolean,
        val priority: Int,
        val title: String,
        val summary: String,
        val detailReason: String
    )

    /**
     * Centralized policy decision function: Evaluates classification, risk score, confidence,
     * evidence corroborated flags, and detection source reliability.
     */
    fun shouldSendThreatNotification(scanResult: UnifiedScanResponse): NotificationDecision {
        val classification = scanResult.classification.trim().lowercase()
        val score = scanResult.risk_score
        val confidence = scanResult.risk_assessment.confidence
        val flags = scanResult.risk_assessment.flags.map { it.lowercase() }
        val isFallback = scanResult.warnings.any { it.contains("offline", ignoreCase = true) || it.contains("cloud engines were not used", ignoreCase = true) }

        // 1. SAFE or LOW RISK -> Strictly NO push notification
        if (classification == "safe" || score < 35.0f) {
            return NotificationDecision(
                tier = NotificationTier.NONE,
                shouldPostNotification = false,
                priority = NotificationCompat.PRIORITY_LOW,
                title = "Safe",
                summary = "Content is clean",
                detailReason = "No threats detected."
            )
        }

        // 2. High-Confidence Confirmed Malicious / Critical Threats
        val isKnownMaliciousFeed = flags.any { it.contains("known_malicious") || it.contains("malwarebazaar") || it.contains("urlhaus") }
        val isConfirmedMalware = classification == "malware" || flags.any { it.contains("malware_detected") || it.contains("vt_malicious") }
        val isConfirmedPhishing = classification == "phishing" && (score >= 80.0f || isKnownMaliciousFeed || flags.any { it.contains("brand_impersonation") && it.contains("credential_harvesting") })

        if (isConfirmedMalware || isConfirmedPhishing || score >= 85.0f || isKnownMaliciousFeed) {
            val threatLabel = if (isConfirmedMalware) "Malware Threat" else "Phishing Threat"
            val topReason = scanResult.risk_assessment.reasons.firstOrNull()
                ?: scanResult.risk_assessment.recommended_action.ifBlank { "Confirmed active security threat detected." }
            return NotificationDecision(
                tier = NotificationTier.CRITICAL_ALERT,
                shouldPostNotification = true,
                priority = NotificationCompat.PRIORITY_MAX,
                title = "🚨 Critical $threatLabel Intercepted",
                summary = "${scanResult.classification} detected (Risk Score: ${score.toInt()}/100)",
                detailReason = topReason
            )
        }

        // 3. High Risk Security Warnings (Deceptive or score >= 70 with verified signals)
        val hasCorroboratedEvidence = flags.size >= 2 || flags.any { it.contains("homograph") || it.contains("brand_impersonation") || it.contains("double_extension") }
        if (classification == "deceptive" || (score >= 70.0f && hasCorroboratedEvidence)) {
            val topReason = scanResult.risk_assessment.reasons.firstOrNull()
                ?: "Multiple deceptive indicators detected."
            return NotificationDecision(
                tier = NotificationTier.SECURITY_WARNING,
                shouldPostNotification = true,
                priority = NotificationCompat.PRIORITY_HIGH,
                title = "⚠️ Security Warning: Deceptive Activity",
                summary = "Deceptive indicators detected (Risk Score: ${score.toInt()}/100)",
                detailReason = topReason
            )
        }

        // 4. Medium Risk / Suspicious -> In-App Warning only, NO unsolicited push notification
        // Prevents notification spam for generic login pages, university portals, or unverified links
        val inAppReason = scanResult.risk_assessment.reasons.firstOrNull()
            ?: "Suspicious structural indicators detected. Exercise caution."
        return NotificationDecision(
            tier = NotificationTier.IN_APP_ONLY,
            shouldPostNotification = false,
            priority = NotificationCompat.PRIORITY_DEFAULT,
            title = "Caution: Unverified Content",
            summary = "Suspicious attributes detected (Score: ${score.toInt()}/100)",
            detailReason = inAppReason
        )
    }

    /**
     * Computes a stable threat fingerprint to prevent duplicate notifications for the same URL or content.
     */
    fun computeThreatFingerprint(target: String, classification: String): String {
        val normalized = target.trim().lowercase().removePrefix("https://").removePrefix("http://").removeSuffix("/")
        val input = "$normalized::$classification"
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(input.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }.take(16)
    }

    /**
     * Checks if this threat was recently notified to prevent spam.
     * Escalated severity bypasses cooldown to ensure critical threats are never silenced.
     */
    @Synchronized
    fun isDuplicateOrInCooldown(context: Context? = null, threatId: String, currentTier: NotificationTier): Boolean {
        val now = System.currentTimeMillis()
        val lastTimestamp: Long
        val lastTier: NotificationTier

        if (context != null) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            lastTimestamp = prefs.getLong(KEY_PREFIX_TIMESTAMP + threatId, 0L)
            val lastSeverityName = prefs.getString(KEY_PREFIX_SEVERITY + threatId, null)
            lastTier = try {
                if (lastSeverityName != null) NotificationTier.valueOf(lastSeverityName) else NotificationTier.NONE
            } catch (_: Exception) {
                NotificationTier.NONE
            }
        } else {
            lastTimestamp = inMemoryCooldown[threatId] ?: 0L
            lastTier = inMemoryTier[threatId] ?: NotificationTier.NONE
        }

        // If the threat has escalated in severity (e.g. Warning -> Critical Alert), allow immediate notification
        if (currentTier.ordinal > lastTier.ordinal) {
            recordNotificationSent(context, threatId, currentTier, now)
            return false
        }

        // Identical or lower severity within cooldown window -> suppress spam
        if (now - lastTimestamp < ALERT_COOLDOWN_MILLIS) {
            return true
        }

        recordNotificationSent(context, threatId, currentTier, now)
        return false
    }

    private fun recordNotificationSent(context: Context? = null, threatId: String, tier: NotificationTier, timestamp: Long) {
        inMemoryCooldown[threatId] = timestamp
        inMemoryTier[threatId] = tier
        if (context != null) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit()
                .putLong(KEY_PREFIX_TIMESTAMP + threatId, timestamp)
                .putString(KEY_PREFIX_SEVERITY + threatId, tier.name)
                .apply()
        }
    }

    /**
     * Unified entry point for dispatching threat notifications from any service or activity.
     */
    fun handleScanVerdict(
        context: Context,
        scanResult: UnifiedScanResponse,
        sourcePackage: String,
        targetDisplay: String
    ): Boolean {
        val decision = shouldSendThreatNotification(scanResult)
        if (!decision.shouldPostNotification) {
            android.util.Log.i("SmartNotification", "Policy suppressed alert: Tier=${decision.tier} for $targetDisplay")
            return false
        }

        val threatId = computeThreatFingerprint(targetDisplay, scanResult.classification)
        if (isDuplicateOrInCooldown(context, threatId, decision.tier)) {
            android.util.Log.i("SmartNotification", "Deduplicator suppressed alert in cooldown: $threatId for $targetDisplay")
            return false
        }

        postNotification(context, scanResult, sourcePackage, targetDisplay, decision, threatId)
        return true
    }

    private fun postNotification(
        context: Context,
        scanResult: UnifiedScanResponse,
        sourcePackage: String,
        targetDisplay: String,
        decision: NotificationDecision,
        threatId: String
    ) {
        ensureNotificationChannel(context)

        val appLabel = try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(sourcePackage, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (_: Exception) {
            sourcePackage
        }

        val intent = Intent(context, GuardianInterceptActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("scan_id", scanResult.scan_id)
            putExtra("target_url", targetDisplay)
            putExtra("classification", scanResult.classification)
            putExtra("score", scanResult.risk_score.toInt())
            putExtra("source_app", appLabel)
            putExtra("threat_id", threatId)
        }

        val notificationId = threatId.hashCode()
        val pendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val bigMessage = buildString {
            appendLine("App: $appLabel")
            appendLine("Verdict: ${scanResult.classification} (Risk: ${scanResult.risk_score.toInt()}/100)")
            appendLine("Evidence: ${decision.detailReason}")
            append("Target: $targetDisplay")
        }

        val isCritical = decision.tier == NotificationTier.CRITICAL_ALERT

        val builder = NotificationCompat.Builder(context, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(decision.title)
            .setContentText(decision.summary)
            .setStyle(NotificationCompat.BigTextStyle().bigText(bigMessage))
            .setContentIntent(pendingIntent)
            .setPriority(decision.priority)
            .setCategory(if (isCritical) NotificationCompat.CATEGORY_ALARM else NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setAutoCancel(true)

        if (isCritical) {
            builder.setVibrate(longArrayOf(0, 250, 150, 250))
            builder.setFullScreenIntent(pendingIntent, true)
            builder.setDefaults(NotificationCompat.DEFAULT_ALL)
        } else {
            builder.setVibrate(longArrayOf(0, 150, 100))
        }

        try {
            NotificationManagerCompat.from(context).notify(notificationId, builder.build())
            android.util.Log.i("SmartNotification", "Posted alert [ID=$notificationId]: ${decision.title} for $targetDisplay")
        } catch (_: SecurityException) {
            // Missing notification permissions
        }
    }

    fun ensureNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "SecureShield Security Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority security alerts for intercepted malicious links and files"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 250, 150, 250)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                setShowBadge(true)
            }
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    /**
     * Resets notification history (used for unit tests and cache clearance).
     */
    fun resetCooldownState(context: Context) {
        inMemoryCooldown.clear()
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().clear().apply()
    }
}
