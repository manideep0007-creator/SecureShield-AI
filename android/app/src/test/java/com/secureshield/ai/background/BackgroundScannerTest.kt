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

        override fun notifyThreat(classification: String, score: Float, action: String) {
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
            override suspend fun saveHistory(r: UnifiedScanResponse, s: String) {}
            override fun notifyThreat(c: String, s: Float, a: String) {}
        }
        assertFalse(BackgroundScanner.execute(deps))
    }
}