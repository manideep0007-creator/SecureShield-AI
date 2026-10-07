package com.secureshield.ai.accessibility

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.secureshield.ai.background.ProcessedMessageStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class GuardianServiceTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        UniversalLinkGuardManager.setUserPreferenceEnabled(context, true)
        ProcessedMessageStore.clearUrlCache(context)
    }

    @Test
    fun guardianPreference_toggle_persistsCorrectly() {
        UniversalLinkGuardManager.setUserPreferenceEnabled(context, true)
        assertTrue(UniversalLinkGuardManager.isUserPreferenceEnabled(context))

        UniversalLinkGuardManager.setUserPreferenceEnabled(context, false)
        assertFalse(UniversalLinkGuardManager.isUserPreferenceEnabled(context))
    }

    @Test
    fun guardianExtractor_whatsAppMessage_extractsTargetUrl() {
        val message = "Check out this reward: http://phish-login-bank.xyz/claim immediately!"
        val urls = UniversalLinkExtractor.extractUrlsFromText(message)

        assertEquals(1, urls.size)
        assertEquals("http://phish-login-bank.xyz/claim", urls[0])
    }

    @Test
    fun guardianExtractor_textWithoutUrl_detectsSuspiciousUrgency() {
        val message = "URGENT: Your account is suspended due to unauthorized activity. Confirm your identity."
        assertTrue(UniversalLinkExtractor.hasSuspiciousText(message))

        val snippet = UniversalLinkExtractor.extractSuspiciousTextSnippet(message)
        assertNotNull(snippet)
        assertTrue(snippet!!.contains("account is suspended"))
    }

    @Test
    fun guardianExtractor_benignText_notFlaggedAsSuspicious() {
        val message = "Hey are we still meeting for lunch today at the cafe?"
        assertFalse(UniversalLinkExtractor.hasSuspiciousText(message))
        assertEquals(null, UniversalLinkExtractor.extractSuspiciousTextSnippet(message))
    }

    @Test
    fun guardianDeduplication_preventsDuplicateScansWithinTtl() {
        val testUrl = "http://malicious-threat-url.xyz/payload"
        assertFalse("Should not be processed yet", ProcessedMessageStore.isUrlProcessed(context, testUrl))

        ProcessedMessageStore.markUrlProcessed(context, testUrl)
        assertTrue("Should be marked as processed", ProcessedMessageStore.isUrlProcessed(context, testUrl))
    }

    @Test
    fun guardianRateLimiter_dropsExcessScansImmediately() {
        val limiter = ScanRateLimiter(maxScansPerMinute = 2, windowMillis = 60_000L)
        val now = 1_000_000L

        assertTrue("1st scan allowed", limiter.tryAcquire(now))
        assertTrue("2nd scan allowed", limiter.tryAcquire(now + 100))
        assertFalse("3rd scan dropped immediately", limiter.tryAcquire(now + 200))
    }
}
