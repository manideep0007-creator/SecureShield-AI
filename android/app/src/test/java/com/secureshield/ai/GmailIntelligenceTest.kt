package com.secureshield.ai

import com.google.api.services.gmail.model.Message
import com.google.api.services.gmail.model.MessagePart
import com.google.api.services.gmail.model.MessagePartBody
import com.google.api.services.gmail.model.MessagePartHeader
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.Base64

class GmailIntelligenceTest {

    @Test
    fun `OAuth success cancellation and failure are classified`() {
        assertEquals(GmailOAuthOutcome.AUTHORIZED, GmailOAuthOutcomeMapper.classify(true, null, 12501))
        assertEquals(GmailOAuthOutcome.CANCELLED, GmailOAuthOutcomeMapper.classify(false, 12501, 12501))
        assertEquals(GmailOAuthOutcome.FAILED, GmailOAuthOutcomeMapper.classify(false, 8, 12501))
    }

    @Test
    fun `extracts sender recipient subject body urls and message id`() {
        val result = GmailMessageExtractor.extract(
            message("msg-123", part("text/plain", "Please verify at https://secure.example/login."))
        ) as GmailMessageExtraction.Extracted

        assertEquals("msg-123", result.email.messageId)
        assertEquals("alerts@example.test", result.email.sender)
        assertEquals("user@example.test", result.email.recipient)
        assertEquals("Account notice", result.email.subject)
        assertEquals("Please verify at https://secure.example/login.", result.email.bodyText)
        assertEquals(listOf("https://secure.example/login"), result.email.embeddedUrls)

        val scanInput = result.email.toScanInput()
        assertEquals("alerts@example.test", scanInput.sender_id)
        assertEquals("https://secure.example/login", scanInput.url)
        assertEquals("msg-123", scanInput.metadata["gmail_message_id"])
        assertEquals(listOf("https://secure.example/login"), scanInput.metadata["embedded_urls"])
    }

    @Test
    fun `multipart extraction prefers plain text and ignores attachments`() {
        val multipart = MessagePart()
            .setMimeType("multipart/mixed")
            .setParts(
                listOf(
                    MessagePart()
                        .setMimeType("multipart/alternative")
                        .setParts(
                            listOf(
                                part("text/plain", "Plain body https://example.test"),
                                part("text/html", "<p>HTML body <a href=\"https://html-only.example/path\">sign in</a></p>")
                            )
                        ),
                    MessagePart()
                        .setMimeType("text/plain")
                        .setFilename("invoice.txt")
                        .setBody(MessagePartBody().setAttachmentId("attachment-1"))
                )
            )

        val result = GmailMessageExtractor.extract(message("multipart-1", multipart)) as GmailMessageExtraction.Extracted
        assertEquals("Plain body https://example.test", result.email.bodyText)
        assertFalse(result.email.bodyText.contains("HTML body"))
        assertEquals(listOf("https://example.test", "https://html-only.example/path"), result.email.embeddedUrls)
    }

    @Test
    fun `HTML body fallback strips tags and decodes entities`() {
        val result = GmailMessageExtractor.extract(
            message("html-1", part("text/html", "<style>hidden</style><p>Open &amp; review https://example.test</p>"))
        ) as GmailMessageExtraction.Extracted

        assertEquals("Open & review https://example.test", result.email.bodyText)
        assertEquals(listOf("https://example.test"), result.email.embeddedUrls)
    }

    @Test
    fun `malformed base64 parts and unsupported attachment-only messages have no readable body`() {
        val badPart = MessagePart().setMimeType("text/plain").setBody(MessagePartBody().setData("%%%"))
        val result = GmailMessageExtractor.extract(message("bad-part", badPart))
        assertEquals(GmailMessageExtraction.MissingBody, result)

        val malformed = GmailMessageExtractor.extract(Message().setPayload(MessagePart()))
        assertEquals(GmailMessageExtraction.Malformed, malformed)
    }

    @Test
    fun `fetches each unread message and reports empty inbox`() = runTest {
        val first = message("first", part("text/plain", "One"))
        val second = message("second", part("text/plain", "Two"))
        val api = FakeGmailApi(listOf("first", "second"), mapOf("first" to first, "second" to second))

        val result = GmailScanner(api).fetchUnreadMessages()
        assertTrue(result is GmailFetchResult.Messages)
        assertEquals(listOf("first", "second"), (result as GmailFetchResult.Messages).emails.map { it.messageId })
        assertEquals(listOf("first", "second"), api.requestedMessageIds)

        assertEquals(GmailFetchResult.NoUnreadMessages, GmailScanner(FakeGmailApi(emptyList())).fetchUnreadMessages())
    }

    @Test
    fun `malformed and bodyless unread messages are reported without scanning`() = runTest {
        val api = FakeGmailApi(listOf(null, "no-body"), mapOf("no-body" to message("no-body", MessagePart())))

        val result = GmailScanner(api).fetchUnreadMessages()
        assertEquals(GmailFetchResult.NoReadableMessages(2), result)
    }

    @Test
    fun `API and network failures are classified`() = runTest {
        val network = GmailScanner(FakeGmailApi(failure = IOException("offline"))).fetchUnreadMessages()
        assertEquals(GmailFetchResult.Failure(GmailFailureKind.NETWORK), network)

        val auth = GmailScanner(
            FakeGmailApi(failure = GmailApiFailure(GmailFailureKind.AUTHENTICATION_REQUIRED, "expired"))
        ).fetchUnreadMessages()
        assertEquals(GmailFetchResult.Failure(GmailFailureKind.AUTHENTICATION_REQUIRED), auth)

        val apiError = GmailScanner(
            FakeGmailApi(failure = GmailApiFailure(GmailFailureKind.API, "service error"))
        ).fetchUnreadMessages()
        assertEquals(GmailFetchResult.Failure(GmailFailureKind.API), apiError)

        val timeout = GmailScanner(FakeGmailApi(failure = java.net.SocketTimeoutException("timeout"))).fetchUnreadMessages()
        assertEquals(GmailFetchResult.Failure(GmailFailureKind.TIMEOUT), timeout)
    }

    @Test
    fun `each unread email invokes the scan callback exactly once`() = runTest {
        val emails = listOf(
            GmailEmail("one", "a@example.test", null, "One", "Body one", emptyList()),
            GmailEmail("two", "b@example.test", null, "Two", "Body two", emptyList()),
            GmailEmail("three", "c@example.test", null, "Three", "Body three", emptyList()),
            GmailEmail("two", "b@example.test", null, "Two duplicate", "Body duplicate", emptyList())
        )
        val scannedIds = mutableListOf<String>()

        GmailEmailScanDispatcher.dispatch(emails) { email -> scannedIds += email.messageId }

        assertEquals(listOf("one", "two", "three"), scannedIds)
        assertEquals(3, scannedIds.size)
    }

    private fun message(id: String, payload: MessagePart): Message = Message()
        .setId(id)
        .setPayload(
            MessagePart()
                .setMimeType("multipart/mixed")
                .setHeaders(
                    listOf(
                        MessagePartHeader().setName("From").setValue("alerts@example.test"),
                        MessagePartHeader().setName("To").setValue("user@example.test"),
                        MessagePartHeader().setName("Subject").setValue("Account notice")
                    )
                )
                .setParts(listOf(payload))
        )

    private fun part(mimeType: String, text: String): MessagePart = MessagePart()
        .setMimeType(mimeType)
        .setBody(MessagePartBody().setData(Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray())))

    private class FakeGmailApi(
        private val ids: List<String?>? = emptyList(),
        private val messages: Map<String, Message> = emptyMap(),
        private val failure: IOException? = null
    ) : GmailMessageApi {
        val requestedMessageIds = mutableListOf<String>()

        override fun listUnreadMessageIds(maxResults: Int): List<String?>? {
            failure?.let { throw it }
            assertTrue(maxResults in 1..GmailScanner.DEFAULT_MAX_MESSAGES)
            return ids
        }

        override fun getMessage(messageId: String): Message? {
            requestedMessageIds += messageId
            failure?.let { throw it }
            return messages[messageId]
        }
    }
}