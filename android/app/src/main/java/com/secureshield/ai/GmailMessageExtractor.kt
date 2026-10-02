package com.secureshield.ai

import com.google.api.services.gmail.model.Message
import com.google.api.services.gmail.model.MessagePart
import com.google.api.client.util.Base64
import com.secureshield.ai.network.ScanInput
import java.nio.charset.Charset
import java.util.Locale

data class GmailEmail(
    val messageId: String,
    val sender: String?,
    val recipient: String?,
    val subject: String?,
    val bodyText: String,
    val embeddedUrls: List<String>
) {
    fun toScanInput(): ScanInput {
        val displayText = buildList {
            subject?.let { add("Subject: $it") }
            sender?.let { add("From: $it") }
            recipient?.let { add("To: $it") }
            add("")
            add(bodyText)
        }.joinToString("\n")
        val metadata = linkedMapOf<String, Any>(
            "gmail_message_id" to messageId,
            "embedded_urls" to embeddedUrls
        )
        recipient?.let { metadata["recipient"] = it }
        subject?.let { metadata["subject"] = it }
        return ScanInput(
            text = displayText,
            url = embeddedUrls.firstOrNull(),
            sender_id = sender,
            source_channel = "gmail",
            metadata = metadata
        )
    }
}

sealed class GmailMessageExtraction {
    data class Extracted(val email: GmailEmail) : GmailMessageExtraction()
    object MissingBody : GmailMessageExtraction()
    object Malformed : GmailMessageExtraction()
}

object GmailMessageExtractor {
    private val urlPattern = Regex("(?i)https?://[^\\s<>\"']+")
    private val charsetPattern = Regex("(?i)charset\\s*=\\s*[\"']?([^;\"'\\s]+)")
    private val htmlEntityPattern = Regex("&(#x[0-9a-f]+|#\\d+|amp|lt|gt|quot|apos|nbsp);", RegexOption.IGNORE_CASE)
    private val anchorPattern = Regex("(?is)<a\\b[^>]*href\\s*=\\s*([\"'])(.*?)\\1[^>]*>(.*?)</a>")

    fun extract(message: Message?): GmailMessageExtraction {
        val messageId = message?.id?.takeIf(String::isNotBlank) ?: return GmailMessageExtraction.Malformed
        val payload = message.payload ?: return GmailMessageExtraction.Malformed
        val headers = payload.headers.orEmpty().associate { header ->
            header.name.orEmpty().lowercase(Locale.ROOT) to header.value.orEmpty()
        }
        val plainParts = mutableListOf<String>()
        val htmlParts = mutableListOf<String>()
        collectTextParts(payload, plainParts, htmlParts)
        val readableHtml = htmlParts.map(::htmlToText)
        val body = plainParts.takeIf { it.isNotEmpty() }?.joinToString("\n")
            ?: readableHtml.takeIf { it.isNotEmpty() }?.joinToString("\n")
            ?: return GmailMessageExtraction.MissingBody
        val normalizedBody = body.trim()
        if (normalizedBody.isEmpty()) return GmailMessageExtraction.MissingBody
        val urls = (plainParts + readableHtml).asSequence()
            .flatMap { urlPattern.findAll(it).map { match -> match.value } }
            .map { it.trimEnd('.', ',', ';', '!', ')', ']', '}') }
            .filter(String::isNotBlank)
            .distinct()
            .toList()
        return GmailMessageExtraction.Extracted(
            GmailEmail(
                messageId = messageId,
                sender = headers["from"]?.takeIf(String::isNotBlank),
                recipient = headers["to"]?.takeIf(String::isNotBlank),
                subject = headers["subject"]?.takeIf(String::isNotBlank),
                bodyText = normalizedBody,
                embeddedUrls = urls
            )
        )
    }

    private fun collectTextParts(part: MessagePart, plainParts: MutableList<String>, htmlParts: MutableList<String>) {
        if (!part.filename.isNullOrBlank() || !part.body?.attachmentId.isNullOrBlank()) return
        val mimeType = part.mimeType.orEmpty().substringBefore(';').trim().lowercase(Locale.ROOT)
        if (mimeType == "text/plain" || mimeType == "text/html") {
            decodePart(part)?.takeIf(String::isNotBlank)?.let { decoded ->
                if (mimeType == "text/plain") plainParts += decoded else htmlParts += decoded
            }
            return
        }
        part.parts.orEmpty().forEach { collectTextParts(it, plainParts, htmlParts) }
    }

    private fun decodePart(part: MessagePart): String? {
        val encoded = part.body?.data?.takeIf(String::isNotBlank) ?: return null
        val bytes = try {
            Base64.decodeBase64(encoded)
        } catch (_: IllegalArgumentException) {
            return null
        }
        val contentType = part.headers.orEmpty().firstOrNull {
            it.name.equals("Content-Type", ignoreCase = true)
        }?.value.orEmpty()
        val charsetName = charsetPattern.find(contentType)?.groupValues?.getOrNull(1)
        val charset = try {
            charsetName?.let(Charset::forName) ?: Charsets.UTF_8
        } catch (_: Exception) {
            Charsets.UTF_8
        }
        return String(bytes, charset)
    }

    private fun htmlToText(html: String): String {
        val withoutNonContent = html
            .replace(Regex("(?is)<(script|style)\\b[^>]*>.*?</\\1>"), " ")
            .replace(anchorPattern) { match -> "${match.groupValues[3]} ${match.groupValues[2]}" }
            .replace(Regex("(?i)<br\\s*/?>|</(p|div|li|tr|h[1-6])\\s*>"), "\n")
            .replace(Regex("(?s)<[^>]*>"), " ")
        return htmlEntityPattern.replace(withoutNonContent) { match ->
            val entity = match.groupValues[1].lowercase(Locale.ROOT)
            when {
                entity == "amp" -> "&"
                entity == "lt" -> "<"
                entity == "gt" -> ">"
                entity == "quot" -> "\""
                entity == "apos" -> "'"
                entity == "nbsp" -> " "
                entity.startsWith("#x") -> entity.drop(2).toIntOrNull(16)?.let(Character::toChars)?.concatToString() ?: " "
                entity.startsWith("#") -> entity.drop(1).toIntOrNull()?.let(Character::toChars)?.concatToString() ?: " "
                else -> " "
            }
        }.replace(Regex("[\\t\\r ]+"), " ").replace(Regex(" *\\n *"), "\n").trim()
    }
}