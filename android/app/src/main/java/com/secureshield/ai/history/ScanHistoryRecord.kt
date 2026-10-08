package com.secureshield.ai.history

import com.google.gson.Gson
import com.secureshield.ai.network.UnifiedScanResponse
import java.util.Locale
import java.util.UUID

data class ScanHistoryRecord(
    val scanId: String,
    val timestampMillis: Long,
    val sourceType: String,
    val classification: String,
    val riskScore: Float,
    val confidence: Float,
    val recommendedAction: String,
    val reasons: List<String>,
    val flags: List<String>,
    val evidenceKeys: List<String>,
    val feedbackState: String? = null
)

data class ScanHistoryFilter(
    val classification: String? = null,
    val sourceType: String? = null
)

object ScanHistorySanitizer {
    private val gson = Gson()
    private val urlPattern = Regex("(?i)\\b(?:https?://|www\\.)[^\\s<>]+")
    private val emailPattern = Regex("(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b")
    private val phonePattern = Regex("(?<!\\w)(?:\\+?\\d[\\d ().-]{6,}\\d)(?!\\w)")
    private val secretPattern = Regex("(?i)\\b(password|passcode|otp|one[- ]time code|token|api key)\\b\\s*(?:is\\s+|[:=]\\s*|\\s*(?=\\d{4,}))[^\\s,;]+")
    private val longTokenPattern = Regex("\\b[A-Za-z0-9_+/=-]{32,}\\b")
    private val safeKeyPattern = Regex("[^A-Za-z0-9_.()\\-]")
    private val classifications = setOf("Safe", "Suspicious", "Deceptive", "Phishing", "Malware")
    private val sourceTypes = setOf("url", "file", "share", "gmail", "accessibility_guard", "unknown")

    fun fromResponse(
        result: UnifiedScanResponse,
        sourceType: String,
        timestampMillis: Long = System.currentTimeMillis()
    ): ScanHistoryRecord? {
        if (!runCatching { UUID.fromString(result.scan_id) }.isSuccess) return null
        if (result.classification !in classifications) return null
        if (!result.risk_score.isFinite() || result.risk_score !in 0f..100f) return null
        val confidence = result.risk_assessment.confidence
        if (!confidence.isFinite() || confidence !in 0f..1f) return null

        val reasons = result.risk_assessment.reasons
            .map(::sanitizeDisplayText)
            .filter(String::isNotBlank)
            .distinct()
            .take(MAX_REASONS)
        val flags = result.risk_assessment.flags.map(::sanitizeKey).filter(String::isNotBlank).distinct().take(MAX_SUMMARY_ITEMS)
        val evidenceKeys = result.risk_assessment.evidence
            .map { sanitizeKey(it.key) }
            .filter(String::isNotBlank)
            .distinct()
            .take(MAX_SUMMARY_ITEMS)

        return ScanHistoryRecord(
            scanId = result.scan_id,
            timestampMillis = timestampMillis,
            sourceType = sourceType.lowercase(Locale.ROOT).takeIf(sourceTypes::contains) ?: "unknown",
            classification = result.classification,
            riskScore = result.risk_score,
            confidence = confidence,
            recommendedAction = sanitizeDisplayText(result.risk_assessment.recommended_action),
            reasons = reasons,
            flags = flags,
            evidenceKeys = evidenceKeys
        )
    }

    internal fun encode(values: List<String>): String = gson.toJson(values)

    internal fun decode(value: String?): List<String> = try {
        if (value.isNullOrBlank()) emptyList() else gson.fromJson(value, Array<String>::class.java)?.toList().orEmpty()
    } catch (_: Exception) {
        emptyList()
    }

    fun sanitizeDisplayText(value: String): String = value
        .replace(secretPattern, "$1: [redacted]")
        .replace(urlPattern, "[link]")
        .replace(emailPattern, "[address]")
        .replace(phonePattern, "[number]")
        .replace(longTokenPattern, "[redacted]")
        .filter { it == '\n' || it == '\t' || it >= ' ' }
        .trim()
        .take(MAX_TEXT_LENGTH)

    /**
     * Checks if redaction removed more than half of the original snippet.
     */
    fun isMostlyRedacted(original: String, sanitized: String): Boolean {
        val trimmedOriginal = original.trim()
        if (trimmedOriginal.isEmpty()) return true

        val remainingUnredacted = sanitized
            .replace("[redacted]", "")
            .replace("[link]", "")
            .replace("[address]", "")
            .replace("[number]", "")
            .trim()

        return remainingUnredacted.length < (trimmedOriginal.length * 0.5f)
    }

    private fun sanitizeKey(value: String): String = safeKeyPattern.replace(value, "_").take(MAX_KEY_LENGTH)

    const val MAX_PAGE_SIZE = 100
    const val DEFAULT_PAGE_SIZE = 25
    private const val MAX_REASONS = 12
    private const val MAX_SUMMARY_ITEMS = 40
    private const val MAX_TEXT_LENGTH = 320
    private const val MAX_KEY_LENGTH = 72
}