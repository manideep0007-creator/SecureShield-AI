package com.secureshield.ai.accessibility

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.secureshield.ai.background.ProcessedMessageStore
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProcessedMessageStoreUrlTest {

    private val context = ApplicationProvider.getApplicationContext<android.app.Application>()

    @Before
    @After
    fun cleanup() {
        ProcessedMessageStore.clearUrlCache(context)
    }

    @Test
    fun isUrlProcessed_unseenUrl_returnsFalse() {
        assertFalse(ProcessedMessageStore.isUrlProcessed(context, "https://novel-phishing-link.com"))
    }

    @Test
    fun isUrlProcessed_recentlyMarkedUrl_returnsTrueWithin10Minutes() {
        val url = "https://suspicious-bank-login.xyz/auth"
        val timestamp = 1_000_000L

        ProcessedMessageStore.markUrlProcessed(context, url, timestamp)

        // 5 minutes later: still within 10 minute TTL
        val fiveMinutesLater = timestamp + 5 * 60 * 1000L
        assertTrue(ProcessedMessageStore.isUrlProcessed(context, url, currentTimeMillis = fiveMinutesLater))

        // 9.9 minutes later: still within TTL
        val nineMinutesLater = timestamp + 9 * 60 * 1000L + 50_000L
        assertTrue(ProcessedMessageStore.isUrlProcessed(context, url, currentTimeMillis = nineMinutesLater))
    }

    @Test
    fun isUrlProcessed_after10Minutes_returnsFalseDueToExpiration() {
        val url = "https://expired-link.xyz/test"
        val timestamp = 1_000_000L

        ProcessedMessageStore.markUrlProcessed(context, url, timestamp)

        // 10 minutes and 1 millisecond later: expired
        val elevenMinutesLater = timestamp + 10 * 60 * 1000L + 1L
        assertFalse(
            "URL should be treated as expired and re-scannable after 10 minutes",
            ProcessedMessageStore.isUrlProcessed(context, url, currentTimeMillis = elevenMinutesLater)
        )
    }

    @Test
    fun clearUrlCache_removesAllEntries() {
        val url = "https://sample.com"
        ProcessedMessageStore.markUrlProcessed(context, url)
        assertTrue(ProcessedMessageStore.isUrlProcessed(context, url))

        ProcessedMessageStore.clearUrlCache(context)
        assertFalse(ProcessedMessageStore.isUrlProcessed(context, url))
    }
}
