package com.secureshield.ai

import android.content.Context
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.api.client.googleapis.extensions.android.gms.auth.GoogleAccountCredential
import com.google.api.client.googleapis.extensions.android.gms.auth.UserRecoverableAuthIOException
import com.google.api.client.googleapis.json.GoogleJsonResponseException
import com.google.api.client.http.HttpRequestInitializer
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.gson.GsonFactory
import com.google.api.services.gmail.Gmail
import com.google.api.services.gmail.GmailScopes
import com.google.api.services.gmail.model.Message
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.SocketTimeoutException

interface GmailMessageApi {
    fun listUnreadMessageIds(maxResults: Int): List<String?>?
    fun getMessage(messageId: String): Message?
}

enum class GmailFailureKind {
    AUTHENTICATION_REQUIRED,
    PERMISSION_DENIED,
    TIMEOUT,
    NETWORK,
    API,
    MALFORMED_RESPONSE
}

class GmailApiFailure(val kind: GmailFailureKind, message: String) : IOException(message)

sealed class GmailFetchResult {
    data class Messages(val emails: List<GmailEmail>, val skippedMessages: Int) : GmailFetchResult()
    object NoUnreadMessages : GmailFetchResult()
    data class NoReadableMessages(val skippedMessages: Int) : GmailFetchResult()
    data class Failure(val kind: GmailFailureKind) : GmailFetchResult()
}

class GmailScanner(private val api: GmailMessageApi) {
    constructor(context: Context, account: GoogleSignInAccount) : this(GoogleGmailMessageApi(context, account))

    suspend fun fetchUnreadMessages(maxResults: Int = DEFAULT_MAX_MESSAGES): GmailFetchResult = withContext(Dispatchers.IO) {
        try {
            val messageIds = api.listUnreadMessageIds(maxResults.coerceIn(1, DEFAULT_MAX_MESSAGES)).orEmpty()
            if (messageIds.isEmpty()) return@withContext GmailFetchResult.NoUnreadMessages

            val emails = mutableListOf<GmailEmail>()
            var skippedMessages = 0
            for (messageId in messageIds.distinct()) {
                if (messageId.isNullOrBlank()) {
                    skippedMessages++
                    continue
                }
                when (val extraction = GmailMessageExtractor.extract(api.getMessage(messageId))) {
                    is GmailMessageExtraction.Extracted -> emails += extraction.email
                    GmailMessageExtraction.Malformed,
                    GmailMessageExtraction.MissingBody -> skippedMessages++
                }
            }

            when {
                emails.isNotEmpty() -> GmailFetchResult.Messages(emails, skippedMessages)
                skippedMessages > 0 -> GmailFetchResult.NoReadableMessages(skippedMessages)
                else -> GmailFetchResult.NoUnreadMessages
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: UserRecoverableAuthIOException) {
            GmailFetchResult.Failure(GmailFailureKind.AUTHENTICATION_REQUIRED)
        } catch (error: GmailApiFailure) {
            GmailFetchResult.Failure(error.kind)
        } catch (error: SocketTimeoutException) {
            GmailFetchResult.Failure(GmailFailureKind.TIMEOUT)
        } catch (error: IOException) {
            GmailFetchResult.Failure(GmailFailureKind.NETWORK)
        } catch (error: Exception) {
            GmailFetchResult.Failure(GmailFailureKind.MALFORMED_RESPONSE)
        }
    }

    private class GoogleGmailMessageApi(context: Context, account: GoogleSignInAccount) : GmailMessageApi {
        private val service: Gmail by lazy {
            val credential = GoogleAccountCredential.usingOAuth2(context, listOf(GmailScopes.GMAIL_READONLY)).apply {
                selectedAccount = account.account
            }
            Gmail.Builder(NetHttpTransport(), GsonFactory.getDefaultInstance(), HttpRequestInitializer { request ->
                credential.initialize(request)
                request.connectTimeout = 15_000
                request.readTimeout = 20_000
            }).setApplicationName("SecureShield AI").build()
        }

        override fun listUnreadMessageIds(maxResults: Int): List<String?>? = withGmailErrors {
            service.users().messages().list("me")
                .setQ("is:unread")
                .setMaxResults(maxResults.toLong())
                .execute()
                .messages
                ?.map { it.id }
        }

        override fun getMessage(messageId: String): Message? = withGmailErrors {
            service.users().messages().get("me", messageId).setFormat("full").execute()
        }

        private inline fun <T> withGmailErrors(request: () -> T): T = try {
            request()
        } catch (error: GoogleJsonResponseException) {
            val kind = when (error.statusCode) {
                401 -> GmailFailureKind.AUTHENTICATION_REQUIRED
                403 -> GmailFailureKind.PERMISSION_DENIED
                else -> GmailFailureKind.API
            }
            throw GmailApiFailure(kind, "Gmail API request failed (${error.statusCode}).")
        }
    }

    companion object {
        const val DEFAULT_MAX_MESSAGES = 20
    }
}