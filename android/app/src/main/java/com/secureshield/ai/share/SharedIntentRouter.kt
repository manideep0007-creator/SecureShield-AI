package com.secureshield.ai.share

import com.secureshield.ai.network.ScanInput

data class SharedIntentPayload(
    val action: String?,
    val mimeType: String?,
    val text: String? = null,
    val streamUri: String? = null,
    val dataUri: String? = null
)

sealed class SharedFileReadResult {
    data class Success(val fileName: String, val content: String) : SharedFileReadResult()
    data class Failure(val message: String) : SharedFileReadResult()
}

enum class SharedScanKind(val label: String) {
    TEXT("Text"),
    URL("URL"),
    FILE("File")
}

sealed class ShareDispatchResult {
    data class Dispatched(val kind: SharedScanKind) : ShareDispatchResult()
    data class Rejected(val message: String) : ShareDispatchResult()
}

object SharedIntentRouter {
    private const val ACTION_SEND = "android.intent.action.SEND"
    private const val SOURCE_CHANNEL = "android_share"
    private val urlPattern = Regex("(?i)https?://[^\\s<>\"']+")

    fun dispatch(
        payload: SharedIntentPayload,
        readFile: (String) -> SharedFileReadResult,
        executeScan: (ScanInput, SharedScanKind) -> Unit
    ): ShareDispatchResult {
        if (payload.action != ACTION_SEND) {
            return ShareDispatchResult.Rejected("Unsupported share action.")
        }

        val mimeType = payload.mimeType?.substringBefore(';')?.trim()?.lowercase()
        val streamUri = payload.streamUri?.takeIf(String::isNotBlank)
        val text = payload.text?.trim()?.takeIf(String::isNotEmpty)
        val dataUrl = payload.dataUri?.takeIf(::isHttpUrl)

        if (streamUri != null) {
            if (!isSupportedFileMime(mimeType)) {
                return ShareDispatchResult.Rejected("Unsupported shared file type.")
            }

            val file = when (val readResult = readFile(streamUri)) {
                is SharedFileReadResult.Success -> readResult
                is SharedFileReadResult.Failure -> return ShareDispatchResult.Rejected(readResult.message)
            }
            if (file.content.isEmpty()) {
                return ShareDispatchResult.Rejected("Shared file is empty.")
            }
            val url = findUrl(text)
            val input = ScanInput(
                text = text?.takeUnless { url != null && it == url },
                url = url,
                file_name = file.fileName,
                file_bytes = file.content,
                source_channel = SOURCE_CHANNEL
            )
            executeScan(input, SharedScanKind.FILE)
            return ShareDispatchResult.Dispatched(SharedScanKind.FILE)
        }

        if (mimeType != null && !isSupportedTextMime(mimeType)) {
            return ShareDispatchResult.Rejected("Unsupported shared content type.")
        }

        val sharedText = text ?: dataUrl
            ?: return ShareDispatchResult.Rejected("No shared text or URL was provided.")
        val url = findUrl(sharedText) ?: dataUrl
        val input = ScanInput(
            text = sharedText.takeUnless { url != null && it == url },
            url = url,
            source_channel = SOURCE_CHANNEL
        )
        val kind = if (url != null) SharedScanKind.URL else SharedScanKind.TEXT
        executeScan(input, kind)
        return ShareDispatchResult.Dispatched(kind)
    }

    private fun isSupportedFileMime(mimeType: String?): Boolean =
        mimeType != null && (mimeType.startsWith("text/") || mimeType in SUPPORTED_APPLICATION_MIME_TYPES)

    private fun isSupportedTextMime(mimeType: String): Boolean =
        mimeType.startsWith("text/") || mimeType in SUPPORTED_APPLICATION_MIME_TYPES

    private fun findUrl(text: String?): String? = text?.let(urlPattern::find)?.value?.trimEnd('.', ',', ';', '!', ')', ']', '}')

    private fun isHttpUrl(value: String): Boolean =
        value.startsWith("http://", ignoreCase = true) || value.startsWith("https://", ignoreCase = true)

    private val SUPPORTED_APPLICATION_MIME_TYPES = setOf(
        "application/json",
        "application/xml",
        "application/x-www-form-urlencoded"
    )
}