package com.secureshield.ai

object GmailEmailScanDispatcher {
    suspend fun dispatch(emails: List<GmailEmail>, scan: suspend (GmailEmail) -> Unit) {
        emails.distinctBy { it.messageId }.forEach { email -> scan(email) }
    }
}