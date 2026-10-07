package com.secureshield.ai.accessibility

import android.os.Build
import android.view.accessibility.AccessibilityNodeInfo
import java.util.regex.Pattern

/**
 * Universal, app-agnostic visible text and URL extractor.
 * Walks generic AccessibilityNodeInfo hierarchies without any per-app view special-casing.
 */
object UniversalLinkExtractor {

    // Regex matching web URLs and domain-shaped strings across all visible text
    private val URL_PATTERN = Pattern.compile(
        """(?i)\b(?:https?://[^\s<>"']+|www\d{0,3}\.[^\s<>"']+|\b[a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|io|xyz|top|cc|tk|ml|ga|cf|gq|app|dev|me|info|biz|site|online|live|link|co|in|uk|ru|cn|de|jp|us|tech|club|vip|shop)(?:/[^\s<>"']*)?)""",
        Pattern.CASE_INSENSITIVE
    )

    /**
     * Traverses the AccessibilityNodeInfo tree and aggregates all visible text.
     * Treats all application hierarchies generically.
     */
    fun extractAllVisibleText(rootNode: AccessibilityNodeInfo?): String {
        if (rootNode == null) return ""
        val builder = StringBuilder()
        collectVisibleText(rootNode, builder)
        return builder.toString()
    }

    private fun collectVisibleText(node: AccessibilityNodeInfo?, builder: StringBuilder) {
        if (node == null) return

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
            collectVisibleText(child, builder)
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
}
