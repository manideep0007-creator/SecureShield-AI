package com.secureshield.ai.background

import com.secureshield.ai.GmailEmail
import com.secureshield.ai.GmailFetchResult
import com.secureshield.ai.network.RiskAssessment
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackgroundScannerTest {

    private class FakeDependencies : BackgroundDependencies {
        var enabled = true
        var active = true
        var fetchResult: GmailFetchResult = GmailFetchResult.NoUnreadMessages
        
        val processed = mutableSetOf<String>()
        val historySaved = mutableListOf<String>()
        val notified = mutableListOf<String>()
        var lastCheckUpdated = false

        override val isEnabled: Boolean get() = enabled
        override val accountActive: Boolean get() = active

        override fun updateLastCheck() {
            lastCheckUpdated = true
        }

        override suspend fun fetchUnreadMessages(): GmailFetchResult {
            return fetchResult
        }

        override fun isProcessed(messageId: String): Boolean = processed.contains(messageId)

        override fun markProcessed(messageId: String) {
            processed.add(messageId)
        }

        override suspend fun scan(input: ScanInput): UnifiedScanResponse? {
            val txt = input.text ?: ""
            val classif = when {
                "Phishing" in txt -> "Phishing"
                "Malware" in txt -> "Malware"
                "Suspicious" in txt -> "Suspicious"
                else -> "Safe"
            }
            return UnifiedScanResponse("id123", "completed", emptyList(), 0, 0, 0,
                RiskAssessment(90f, classif, 0.9f, emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), "act"),
                90f, classif)
        }

        override suspend fun saveHistory(result: UnifiedScanResponse, source: String) {
            historySaved.add(result.classification)
        }

        override fun notifyThreat(classification: String, score: Float, action: String, scanId: String) {
            notified.add(classification)
        }
    }

    @Test
    fun `worker disabled state returns success without scanning`() = runTest {
        val deps = FakeDependencies()
        deps.enabled = false
        assertTrue(BackgroundScanner.execute(deps))
        assertFalse(deps.lastCheckUpdated)
    }

    @Test
    fun `worker enabled state updates check and works`() = runTest {
        val deps = FakeDependencies()
        assertTrue(BackgroundScanner.execute(deps))
        assertTrue(deps.lastCheckUpdated)
    }

    @Test
    fun `scan only Phishing and Malware notifies`() = runTest {
        val deps = FakeDependencies()
        deps.fetchResult = GmailFetchResult.Messages(listOf(
            GmailEmail("msg1", null, null, null, "Phishing", emptyList()),
            GmailEmail("msg2", null, null, null, "Safe", emptyList()),
            GmailEmail("msg3", null, null, null, "Malware", emptyList()),
            GmailEmail("msg4", null, null, null, "Suspicious", emptyList())
        ), 0)
        
        assertTrue(BackgroundScanner.execute(deps))
        assertEquals(4, deps.processed.size)
        assertEquals(4, deps.historySaved.size)
        assertEquals(listOf("Phishing", "Malware"), deps.notified)
    }

    @Test
    fun `duplicate processing prevents scanning`() = runTest {
        val deps = FakeDependencies()
        deps.processed.add("msg1")
        deps.fetchResult = GmailFetchResult.Messages(listOf(
            GmailEmail("msg1", null, null, null, "Phishing", emptyList()),
        ), 0)
        
        assertTrue(BackgroundScanner.execute(deps))
        assertEquals(0, deps.historySaved.size)
        assertEquals(0, deps.notified.size)
    }

    @Test
    fun `authentication failure completes successfully without retrying`() = runTest {
        val deps = FakeDependencies()
        deps.active = false
        assertTrue(BackgroundScanner.execute(deps))
        assertTrue(deps.processed.isEmpty())
    }

    @Test
    fun `network API failure on scan ignores the message and continues`() = runTest {
        var notifiedCount = 0
        val deps = object : BackgroundDependencies {
            override val isEnabled = true
            override val accountActive = true
            override fun updateLastCheck() {}
            override suspend fun fetchUnreadMessages() = GmailFetchResult.Messages(listOf(
                GmailEmail("msg1", null, null, null, "Phishing", emptyList()),
                GmailEmail("msg2", null, null, null, "Malware", emptyList())
            ), 0)
            override fun isProcessed(messageId: String) = false
            override fun markProcessed(messageId: String) {}
            override suspend fun scan(input: ScanInput): UnifiedScanResponse? {
                if (input.text?.contains("Phishing") == true) throw Exception("Network Error")
                return UnifiedScanResponse("id123", "completed", emptyList(), 0, 0, 0,
                    RiskAssessment(90f, "Malware", 0.9f, emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), "act"),
                    90f, "Malware")
            }
            override suspend fun saveHistory(result: UnifiedScanResponse, source: String) {}
            override fun notifyThreat(classification: String, score: Float, action: String, scanId: String) { notifiedCount++ }
        }
        assertTrue(BackgroundScanner.execute(deps))
        assertEquals(1, notifiedCount)
    }

    @Test
    fun `cancellation throws cancellation exception`() = runTest {
        val deps = object : BackgroundDependencies {
            override val isEnabled = true
            override val accountActive = true
            override fun updateLastCheck() {}
            override suspend fun fetchUnreadMessages() = throw kotlinx.coroutines.CancellationException()
            override fun isProcessed(messageId: String) = false
            override fun markProcessed(messageId: String) {}
            override suspend fun scan(input: ScanInput) = null
            override suspend fun saveHistory(result: UnifiedScanResponse, source: String) {}
            override fun notifyThreat(classification: String, score: Float, action: String, scanId: String) {}
        }
        var threw = false
        try {
            BackgroundScanner.execute(deps)
        } catch (_: kotlinx.coroutines.CancellationException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun `fetch failure retries`() = runTest {
        val deps = object : BackgroundDependencies {
            override val isEnabled = true
            override val accountActive = true
            override fun updateLastCheck() {}
            override suspend fun fetchUnreadMessages() = throw Exception()
            override fun isProcessed(messageId: String) = false
            override fun markProcessed(messageId: String) {}
            override suspend fun scan(input: ScanInput) = null
            override suspend fun saveHistory(result: UnifiedScanResponse, source: String) {}
            override fun notifyThreat(classification: String, score: Float, action: String, scanId: String) {}
        }
        assertFalse(BackgroundScanner.execute(deps))
    }

    @Test
    fun `saveHistory failure prevents message from being marked as processed`() = runTest {
        val deps = object : BackgroundDependencies {
            override val isEnabled = true
            override val accountActive = true
            override fun updateLastCheck() {}
            override suspend fun fetchUnreadMessages() = GmailFetchResult.Messages(listOf(
                GmailEmail("msg1", null, null, null, "Safe", emptyList())
            ), 0)
            
            var processed = false
            
            override fun isProcessed(messageId: String) = false
            override fun markProcessed(messageId: String) { processed = true }
            override suspend fun scan(input: ScanInput) = UnifiedScanResponse("id123", "completed", emptyList(), 0, 0, 0,
                RiskAssessment(0f, "Safe", 1f, emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), "act"),
                0f, "Safe")
            override suspend fun saveHistory(result: UnifiedScanResponse, source: String) {
                throw Exception("Database Error")
            }
            override fun notifyThreat(classification: String, score: Float, action: String, scanId: String) {}
        }
        assertTrue(BackgroundScanner.execute(deps))
        assertFalse(deps.processed)
    }

    @Test
    fun `scan cancellation throws cancellation exception`() = runTest {
        val deps = object : BackgroundDependencies {
            override val isEnabled = true
            override val accountActive = true
            override fun updateLastCheck() {}
            override suspend fun fetchUnreadMessages() = GmailFetchResult.Messages(listOf(
                GmailEmail("msg1", null, null, null, "Safe", emptyList())
            ), 0)
            override fun isProcessed(messageId: String) = false
            override fun markProcessed(messageId: String) {}
            override suspend fun scan(input: ScanInput): UnifiedScanResponse? {
                throw kotlinx.coroutines.CancellationException()
            }
            override suspend fun saveHistory(result: UnifiedScanResponse, source: String) {}
            override fun notifyThreat(classification: String, score: Float, action: String, scanId: String) {}
        }
        var threw = false
        try {
            BackgroundScanner.execute(deps)
        } catch (_: kotlinx.coroutines.CancellationException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun `threat notification uses safe identifiers and avoids private data`() = runTest {
        val deps = object : BackgroundDependencies {
            override val isEnabled = true
            override val accountActive = true
            override fun updateLastCheck() {}
            override suspend fun fetchUnreadMessages() = GmailFetchResult.Messages(listOf(
                GmailEmail("msg123", "secret@gmail.com", "body text here", "http://phishing.com", "Phishing", emptyList())
            ), 0)
            override fun isProcessed(messageId: String) = false
            override fun markProcessed(messageId: String) {}
            override suspend fun scan(input: ScanInput) = UnifiedScanResponse("scan456", "completed", emptyList(), 0, 0, 0,
                RiskAssessment(90f, "Phishing", 0.9f, emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), "action"),
                90f, "Phishing")
            override suspend fun saveHistory(result: UnifiedScanResponse, source: String) {}
            
            var notifiedScanId: String? = null
            var notifiedClass: String? = null
            override fun notifyThreat(classification: String, score: Float, action: String, scanId: String) {
                notifiedClass = classification
                notifiedScanId = scanId
            }
        }
        BackgroundScanner.execute(deps)
        
        assertEquals("scan456", deps.notifiedScanId)
        assertEquals("Phishing", deps.notifiedClass)
    }
}