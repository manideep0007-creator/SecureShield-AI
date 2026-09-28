package com.secureshield.ai

import android.content.Context
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.api.client.googleapis.extensions.android.gms.auth.GoogleAccountCredential
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.gson.GsonFactory
import com.google.api.services.gmail.Gmail
import com.google.api.services.gmail.GmailScopes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class GmailScanner(private val context: Context, private val account: GoogleSignInAccount) {

    private val gmailService: Gmail by lazy {
        val credential = GoogleAccountCredential.usingOAuth2(
            context, listOf(GmailScopes.GMAIL_READONLY)
        ).apply {
            selectedAccount = account.account
        }
        
        Gmail.Builder(NetHttpTransport(), GsonFactory.getDefaultInstance(), credential)
            .setApplicationName("SecureShield AI")
            .build()
    }

    suspend fun getLatestMessageData(): MessageData? = withContext(Dispatchers.IO) {
        try {
            // Get latest UNREAD message
            val messagesResponse = gmailService.users().messages().list("me")
                .setQ("is:unread")
                .setMaxResults(1)
                .execute()

            val messages = messagesResponse.messages
            if (messages.isNullOrEmpty()) return@withContext null

            val msgId = messages[0].id
            val fullMsg = gmailService.users().messages().get("me", msgId)
                .setFormat("full")
                .execute()

            var sender = "Unknown"
            fullMsg.payload?.headers?.forEach { header ->
                if (header.name == "From") {
                    sender = header.value
                }
            }

            // Extremely basic body extraction for MVP
            var body = ""
            if (fullMsg.snippet != null) {
                body = fullMsg.snippet
            }

            // Simple regex to find the first URL in the snippet
            val urlRegex = "(?i)\\b((?:https?://|www\\d{0,3}[.]|[a-z0-9.\\-]+[.][a-z]{2,4}/)(?:[^\\s()<>]+|\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\))+(?:\\(([^\\s()<>]+|(\\([^\\s()<>]+\\)))*\\)|[^\\s`!()\\[\\]{};:'\".,<>?«»“”‘’]))".toRegex()
            val extractedUrl = urlRegex.find(body)?.value

            return@withContext MessageData(sender, body, extractedUrl)
        } catch (e: Exception) {
            e.printStackTrace()
            return@withContext null
        }
    }

    data class MessageData(val sender: String, val bodyText: String, val extractedUrl: String?)
}