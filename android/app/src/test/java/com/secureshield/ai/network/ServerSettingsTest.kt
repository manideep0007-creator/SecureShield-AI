package com.secureshield.ai.network

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ServerSettingsTest {

    private lateinit var context: Context
    private var mockWebServer: MockWebServer? = null

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        val prefs = context.getSharedPreferences(ServerSettings.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        ApiClient.resetBaseUrl()
    }

    @After
    fun teardown() {
        mockWebServer?.shutdown()
        val prefs = context.getSharedPreferences(ServerSettings.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        ApiClient.resetBaseUrl()
    }

    @Test
    fun `default emulator development URL is configured`() {
        val defaultUrl = ServerSettings.getDefaultBaseUrl()
        assertEquals("http://10.0.2.2:8000/", defaultUrl)
        assertEquals("http://10.0.2.2:8000/", ApiClient.baseUrl)
    }

    @Test
    fun `configured base URL reflects in ServerSettings and ApiClient`() {
        ServerSettings.init(context)
        assertEquals(ServerSettings.getDefaultBaseUrl(), ServerSettings.getServerUrl(context))
        assertEquals(ServerSettings.getDefaultBaseUrl(), ApiClient.baseUrl)
    }

    @Test
    fun `persisted server URL is restored on init`() {
        val customUrl = "http://192.168.1.50:8000"
        val saved = ServerSettings.saveServerUrl(context, customUrl)
        assertTrue(saved)
        assertEquals("http://192.168.1.50:8000/", ApiClient.baseUrl)

        // Reset in-memory state and re-initialize from storage
        ApiClient.resetBaseUrl()
        ServerSettings.init(context)

        assertEquals("http://192.168.1.50:8000/", ApiClient.baseUrl)
        assertEquals("http://192.168.1.50:8000/", ServerSettings.getServerUrl(context))
    }

    @Test
    fun `invalid server URL is rejected and not persisted`() {
        val invalidInputs = listOf(
            "",
            "   ",
            "not-a-url",
            "ftp://192.168.1.1:8000/",
            "http://",
            "https://",
            "http://   :8000/"
        )

        for (invalid in invalidInputs) {
            assertFalse("Expected '$invalid' to be invalid", ServerSettings.isValidServerUrl(invalid))
            val saved = ServerSettings.saveServerUrl(context, invalid)
            assertFalse("Expected save to fail for '$invalid'", saved)
        }

        // Verify that default URL remains intact
        assertEquals(ServerSettings.getDefaultBaseUrl(), ApiClient.baseUrl)
    }

    @Test
    fun `successful health check returns true`() = runTest {
        val server = MockWebServer()
        mockWebServer = server
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"status":"running","project":"SecureShield-AI"}"""))
        server.start()

        val mockUrl = server.url("/").toString()
        ApiClient.setBaseUrl(mockUrl)

        val healthy = ApiClient.checkHealth()
        assertTrue("Expected health check to succeed", healthy)

        val recorded = server.takeRequest()
        assertEquals("/health", recorded.path)
    }

    @Test
    fun `unreachable backend returns false and probe returns failure`() = runTest {
        val unusedServer = MockWebServer()
        unusedServer.start()
        val unusedUrl = unusedServer.url("/").toString()
        unusedServer.shutdown() // Intentionally stopped

        ApiClient.setBaseUrl(unusedUrl)
        val healthy = ApiClient.checkHealth()
        assertFalse("Expected health check to fail when server is stopped", healthy)

        when (val probeResult = ApiClient.testConnection(unusedUrl)) {
            is ProbeResult.Failure -> assertTrue(probeResult.message.isNotEmpty())
            is ProbeResult.Success -> throw AssertionError("Expected probe to fail for stopped server")
        }
    }

    @Test
    fun `Gmail scan uses configured URL`() = runTest {
        val server = MockWebServer()
        mockWebServer = server
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"status":"running","project":"SecureShield-AI"}"""))
        server.enqueue(MockResponse().setResponseCode(200).setBody("""
            {
                "scan_id": "gmail-scan-001",
                "status": "completed",
                "total_engines": 1,
                "completed_engines": 1,
                "skipped_engines": 0,
                "risk_score": 15.0,
                "classification": "Safe",
                "results": [],
                "risk_assessment": {
                    "risk_score": 15.0,
                    "classification": "Safe",
                    "confidence": 0.95,
                    "contributing_engines": ["nlp_engine"],
                    "ignored_engines": [],
                    "flags": [],
                    "evidence": [],
                    "reasons": ["Clean message"],
                    "recommended_action": "Proceed with normal caution."
                }
            }
        """.trimIndent()))
        server.start()

        val mockUrl = server.url("/").toString()
        ServerSettings.saveServerUrl(context, mockUrl)
        assertEquals(mockUrl, ApiClient.baseUrl)

        // 1. Health check
        assertTrue(ApiClient.checkHealth())
        val healthReq = server.takeRequest()
        assertEquals("/health", healthReq.path)

        // 2. Scan call
        val scanResponse = ApiClient.api.scan(ScanInput(text = "Hello Gmail"))
        assertTrue(scanResponse.isSuccessful)
        val scanReq = server.takeRequest()
        assertEquals("/api/scan", scanReq.path)
    }

    @Test
    fun `background scan uses the same persisted URL`() = runTest {
        val customUrl = "http://192.168.1.88:8000"
        ServerSettings.saveServerUrl(context, customUrl)

        // Simulate background process startup
        ApiClient.resetBaseUrl()
        ServerSettings.init(context)

        assertEquals("http://192.168.1.88:8000/", ApiClient.baseUrl)
    }

    @Test
    fun `changing Server Settings updates subsequent requests immediately without rebuild`() = runTest {
        val server1 = MockWebServer()
        server1.enqueue(MockResponse().setResponseCode(200).setBody("""{"status":"server1"}"""))
        server1.start()

        val server2 = MockWebServer()
        server2.enqueue(MockResponse().setResponseCode(200).setBody("""{"status":"server2"}"""))
        server2.start()

        try {
            // First URL
            ServerSettings.saveServerUrl(context, server1.url("/").toString())
            assertEquals(server1.url("/").toString(), ApiClient.baseUrl)
            ApiClient.api.healthCheck()
            val req1 = server1.takeRequest()
            assertEquals("/health", req1.path)

            // Update to second URL
            ServerSettings.saveServerUrl(context, server2.url("/").toString())
            assertEquals(server2.url("/").toString(), ApiClient.baseUrl)
            ApiClient.api.healthCheck()
            val req2 = server2.takeRequest()
            assertEquals("/health", req2.path)

            assertEquals(0, server1.requestCount - 1)
            assertEquals(1, server2.requestCount)
        } finally {
            server1.shutdown()
            server2.shutdown()
        }
    }
}
