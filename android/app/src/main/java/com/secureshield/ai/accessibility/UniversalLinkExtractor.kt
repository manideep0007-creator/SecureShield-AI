package com.secureshield.ai.accessibility

import android.os.Build
import android.view.accessibility.AccessibilityNodeInfo
import java.util.Locale
import java.util.regex.Pattern

/**
 * Universal, app-agnostic visible text and URL extractor.
 * Walks generic AccessibilityNodeInfo hierarchies without any per-app view special-casing.
 */
object UniversalLinkExtractor {

    // Hard recursion ceiling: prevents StackOverflowError on pathologically deep view trees.
    const val MAX_TRAVERSAL_DEPTH = 64

    // Regex matching web URLs and domain-shaped strings across all visible text
    private val URL_PATTERN = Pattern.compile(
        """(?i)\b(?:https?://[^\s<>"']+|www\d{0,3}\.[^\s<>"']+|\b[a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|io|xyz|top|cc|tk|ml|ga|cf|gq|app|dev|me|info|biz|site|online|live|link|co|in|uk|ru|cn|de|jp|us|tech|club|vip|shop)(?:/[^\s<>"']*)?)""",
        Pattern.CASE_INSENSITIVE
    )

    /**
     * Traverses the AccessibilityNodeInfo tree and aggregates all visible text.
     * Treats all application hierarchies generically. Password fields and their
     * subtrees are never read. Depth is capped at [MAX_TRAVERSAL_DEPTH].
     */
    fun extractAllVisibleText(rootNode: AccessibilityNodeInfo?): String {
        if (rootNode == null) return ""
        val builder = StringBuilder()
        collectVisibleText(rootNode, builder, 0)
        return builder.toString()
    }

    private fun collectVisibleText(node: AccessibilityNodeInfo?, builder: StringBuilder, depth: Int) {
        if (node == null) return
        if (depth > MAX_TRAVERSAL_DEPTH) return

        // Privacy boundary: never read password/credential fields or anything beneath them.
        if (isSensitiveField(node)) return

        // Respect visibility to user
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            if (!node.isVisibleToUser) return
        }

        node.text?.let { text ->
            if (text.isNotBlank()) {
                builder.append(text).append('\n')
            }
        }

        node.contentDescription?.let { desc ->
            if (desc.isNotBlank() && desc != node.text) {
                builder.append(desc).append('\n')
            }
        }

        val childCount = node.childCount
        for (i in 0 until childCount) {
            val child = node.getChild(i) ?: continue
            try {
                collectVisibleText(child, builder, depth + 1)
            } finally {
                recycleQuietly(child)
            }
        }
    }

    private fun isSensitiveField(node: AccessibilityNodeInfo): Boolean {
        if (node.isPassword) return true
        val className = node.className?.toString()?.lowercase(Locale.ROOT) ?: return false
        return className.contains("password")
    }

    private fun recycleQuietly(node: AccessibilityNodeInfo) {
        // recycle() is deprecated and a no-op from API 33; only meaningful on older runtimes.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            try {
                @Suppress("DEPRECATION")
                node.recycle()
            } catch (_: Exception) {
            }
        }
    }

    /**
     * Extracts and normalizes all qualifying URLs from raw text content.
     */
    fun extractUrlsFromText(text: CharSequence): List<String> {
        if (text.isBlank()) return emptyList()

        val matcher = URL_PATTERN.matcher(text)
        val extracted = mutableListOf<String>()

        while (matcher.find()) {
            val raw = matcher.group()
            val cleaned = cleanAndNormalizeUrl(raw)
            if (cleaned.isNotBlank() && !extracted.contains(cleaned)) {
                extracted.add(cleaned)
            }
        }

        return extracted
    }

    /**
     * Strips enclosing punctuation, chat bubble delimiters, and ensures scheme is present.
     */
    fun cleanAndNormalizeUrl(raw: String): String {
        var cleaned = raw.trim()

        // Strip leading delimiters: (, [, {, <, ", ', etc.
        while (cleaned.isNotEmpty() && (cleaned.startsWith("(") || cleaned.startsWith("[") ||
                cleaned.startsWith("{") || cleaned.startsWith("<") || cleaned.startsWith("\"") ||
                cleaned.startsWith("'"))) {
            cleaned = cleaned.substring(1)
        }

        // Strip trailing punctuation: ., ,, ), ], }, !, ?, ;, :, ", ', >
        while (cleaned.isNotEmpty() && (cleaned.endsWith(".") || cleaned.endsWith(",") ||
                cleaned.endsWith(")") || cleaned.endsWith("]") || cleaned.endsWith("}") ||
                cleaned.endsWith("!") || cleaned.endsWith("?") || cleaned.endsWith(";") ||
                cleaned.endsWith(":") || cleaned.endsWith("\"") || cleaned.endsWith("'") ||
                cleaned.endsWith(">"))) {
            cleaned = cleaned.substring(0, cleaned.length - 1)
        }

        if (cleaned.isBlank()) return ""

        // Normalize protocol scheme if missing
        if (!cleaned.startsWith("http://", ignoreCase = true) && !cleaned.startsWith("https://", ignoreCase = true)) {
            cleaned = "https://$cleaned"
        }

        return cleaned
    }

    /**
     * Common high-confidence phishing/fraud urgency markers for detecting on-screen threat text
     * when an explicit URL might not be present or is obfuscated.
     */
    private val SUSPICIOUS_TEXT_KEYWORDS = listOf(
        "account suspended", "account locked", "account is locked", "account is suspended",
        "verify your account", "verify account",
        "unauthorized transaction", "unauthorized activity", "urgent action required",
        "security alert", "confirm your identity", "confirm identity", "password reset",
        "claim your reward", "won a prize", "free crypto", "wire transfer",
        "bank account blocked", "unusual activity"
    )

    /**
     * Checks if the text contains high-confidence suspicious phishing or fraud markers.
     */
    fun hasSuspiciousText(text: CharSequence): Boolean {
        if (text.isBlank() || text.length > 600) return false
        val lower = text.toString().lowercase(Locale.ROOT)
        return SUSPICIOUS_TEXT_KEYWORDS.any { lower.contains(it) }
    }

    /**
     * Extracts a compact normalized snippet of the suspicious text for scanning.
     */
    fun extractSuspiciousTextSnippet(text: CharSequence): String? {
        if (!hasSuspiciousText(text)) return null
        val trimmed = text.toString().trim()
        return if (trimmed.length > 300) trimmed.take(300) + "..." else trimmed
    }
}


