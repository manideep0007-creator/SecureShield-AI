package com.secureshield.ai.accessibility

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.secureshield.ai.background.ProcessedMessageStore
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.SecureShieldApi
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.IOException
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class UniversalLinkGuardServiceTest {

    private lateinit var mockWebServer: MockWebServer
    private lateinit var service: UniversalLinkGuardService
    private lateinit var context: Context

    private val validSafeScanJson = """
        {
            "scan_id": "scan-12345",
            "status": "completed",
            "total_engines": 1,
            "completed_engines": 1,
            "skipped_engines": 0,
            "risk_score": 5.0,
            "classification": "Safe",
            "results": [],
            "risk_assessment": {
                "risk_score": 5.0,
                "classification": "Safe",
                "confidence": 0.95,
                "contributing_engines": ["url_engine"],
                "ignored_engines": [],
                "flags": [],
                "evidence": [],
                "reasons": ["Domain is safe"],
                "recommended_action": "Safe to browse"
            }
        }
    """.trimIndent()

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        context = ApplicationProvider.getApplicationContext()
        UniversalLinkGuardManager.setUserPreferenceEnabled(context, true)
        ProcessedMessageStore.clearUrlCache(context)

        val controller = Robolectric.buildService(UniversalLinkGuardService::class.java).create()
        service = controller.get()
        service.retryDelayMillis = 0L // immediate retry for fast tests
        service.apiOverride = createApi()
    }

    private fun createApi(): SecureShieldApi =
        Retrofit.Builder()
            .baseUrl(mockWebServer.url("/"))
            .client(OkHttpClient.Builder().connectTimeout(1, TimeUnit.SECONDS).readTimeout(1, TimeUnit.SECONDS).build())
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SecureShieldApi::class.java)

    @After
    fun tearDown() {
        mockWebServer.shutdown()
        service.onDestroy()
        ProcessedMessageStore.clearUrlCache(context)
    }

    @Test
    fun failedScan_5xxError_retriesAndUnmarksUrl_rescannedOnNextSighting() = runTest {
        val targetUrl = "https://server-error-site.org/login"

        // Enqueue two 500 errors (1st attempt + 1 retry)
        mockWebServer.enqueue(MockResponse().setResponseCode(500).setBody("Internal Server Error"))
        mockWebServer.enqueue(MockResponse().setResponseCode(500).setBody("Internal Server Error"))

        // First sighting of URL on screen
        service.processVisibleText("Click here: $targetUrl", "com.chat.app")

        // Should have attempted twice (initial + 1 retry)
        assertEquals(2, mockWebServer.requestCount)

        // URL must be unmarked after failed scan
        assertFalse(
            "Failed scan must unmark the URL from ProcessedMessageStore",
            ProcessedMessageStore.isUrlProcessed(context, targetUrl)
        )

        // Next sighting: server has recovered and returns 200 OK
        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody(validSafeScanJson))
        service.processVisibleText("Click here: $targetUrl", "com.chat.app")

        // Should have dispatched a 3rd request (rescanned)
        assertEquals(3, mockWebServer.requestCount)

        // URL should now remain marked
        assertTrue(
            "Successful scan must keep URL marked in ProcessedMessageStore",
            ProcessedMessageStore.isUrlProcessed(context, targetUrl)
        )
    }

    @Test
    fun successfulScan_staysMarked_notRescannedOnNextSighting() = runTest {
        val targetUrl = "https://already-scanned-safe.com/docs"

        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody(validSafeScanJson))

        // First sighting
        service.processVisibleText("Visit $targetUrl for info", "com.browser.app")

        assertEquals(1, mockWebServer.requestCount)
        assertTrue(
            "Successful scan should mark URL as processed",
            ProcessedMessageStore.isUrlProcessed(context, targetUrl)
        )

        // Second sighting in window (next sighting within TTL)
        service.processVisibleText("Visit $targetUrl for info", "com.browser.app")

        // Request count should still be 1 (not rescanned)
        assertEquals(1, mockWebServer.requestCount)
    }

    @Test
    fun coldStartWakeup_503Then200_retrySucceeds_staysMarked() = runTest {
        val targetUrl = "https://render-cold-start.com/home"

        // Attempt 1: 503 Service Unavailable (Render waking up)
        mockWebServer.enqueue(MockResponse().setResponseCode(503).setBody("Service Unavailable"))
        // Attempt 2 (Retry): 200 OK
        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody(validSafeScanJson))

        service.processVisibleText("Go to $targetUrl", "com.messaging.app")

        // Both attempts made
        assertEquals(2, mockWebServer.requestCount)

        // Because retry succeeded, URL must stay marked
        assertTrue(
            "URL should stay marked after retry succeeds",
            ProcessedMessageStore.isUrlProcessed(context, targetUrl)
        )
    }

    @Test
    fun failedScan_4xxClientError_doesNotRetry_unmarksUrl() = runTest {
        val targetUrl = "https://client-error-endpoint.com/bad"

        // 400 Bad Request
        mockWebServer.enqueue(MockResponse().setResponseCode(400).setBody("Bad Request"))

        service.processVisibleText("Check $targetUrl", "com.email.app")

        // 4xx must NOT trigger a retry
        assertEquals(1, mockWebServer.requestCount)

        // URL must be unmarked
        assertFalse(
            "4xx failure must unmark URL",
            ProcessedMessageStore.isUrlProcessed(context, targetUrl)
        )
    }

    @Test
    fun rateLimiter_enforcedAcrossRetries_blocksRetryWhenExhausted() = runTest {
        val targetUrl = "https://ratelimited-site.org/link"

        // Rate limiter configured for strictly 1 scan per minute
        service.rateLimiter = ScanRateLimiter(maxScansPerMinute = 1, windowMillis = 60_000L)

        // Attempt 1 fails with 500
        mockWebServer.enqueue(MockResponse().setResponseCode(500).setBody("Server Error"))

        service.processVisibleText("Link: $targetUrl", "com.sms.app")

        // Attempt 1 consumed the single permit; retry was blocked by rate limiter
        assertEquals(1, mockWebServer.requestCount)

        // URL must be unmarked so it can be scanned when rate limit resets
        assertFalse(
            "Rate-limited failed scan must unmark URL",
            ProcessedMessageStore.isUrlProcessed(context, targetUrl)
        )
    }
}
