package com.secureshield.ai.network

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.OkHttpClient
import com.google.gson.stream.MalformedJsonException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import com.google.gson.JsonSyntaxException

class ApiClientTest {

    private lateinit var mockWebServer: MockWebServer
    private lateinit var api: SecureShieldApi

    @Before
    fun setup() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        api = createApi()
    }

    private fun createApi(readTimeoutMillis: Long = 10_000L): SecureShieldApi =
        Retrofit.Builder()
            .baseUrl(mockWebServer.url("/"))
            .client(OkHttpClient.Builder().readTimeout(readTimeoutMillis, TimeUnit.MILLISECONDS).build())
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SecureShieldApi::class.java)

    @After
    fun teardown() {
        mockWebServer.shutdown()
    }

    @Test
    fun `test successful API response`() = runTest {
        val jsonResponse = """
            {
                "scan_id": "test-uuid",
                "status": "completed",
                "total_engines": 1,
                "completed_engines": 1,
                "skipped_engines": 0,
                "risk_score": 85.0,
                "classification": "Phishing",
                "results": [],
                "risk_assessment": {
                    "risk_score": 85.0,
                    "classification": "Phishing",
                    "confidence": 0.9,
                    "contributing_engines": ["url_engine"],
                    "ignored_engines": [],
                    "flags": ["ip_based_host"],
                    "evidence": [],
                    "reasons": ["The URL uses an IP address."],
                    "recommended_action": "Do not click any links."
                }
            }
        """.trimIndent()

        mockWebServer.enqueue(MockResponse().setBody(jsonResponse).setResponseCode(200))

        val response = api.scan(ScanInput(url = "http://192.168.1.1"))
        
        assertTrue(response.isSuccessful)
        val body = UnifiedScanResponseParser.parse(response.body()!!)
        assertEquals("test-uuid", body.scan_id)
        assertEquals(85.0f, body.risk_score)
        assertEquals("Phishing", body.classification)
        assertEquals(0.9f, body.risk_assessment.confidence)
        assertEquals("The URL uses an IP address.", body.risk_assessment.reasons[0])
    }

    @Test
    fun `test HTTP error response`() = runTest {
        mockWebServer.enqueue(MockResponse().setResponseCode(500).setBody("Internal Server Error"))

        val response = api.scan(ScanInput(text = "test"))
        
        assertFalse(response.isSuccessful)
        assertEquals(500, response.code())
    }

    @Test
    fun `test malformed response`() = runTest {
        val malformedJson = "{ invalid_json: "
        mockWebServer.enqueue(MockResponse().setBody(malformedJson).setResponseCode(200))

        try {
            api.scan(ScanInput(text = "test"))
            throw AssertionError("Expected malformed JSON to fail conversion")
        } catch (e: MalformedJsonException) {
            assertTrue(e.message != null)
        }
    }

    @Test
    fun `test malformed schema response`() = runTest {
        mockWebServer.enqueue(MockResponse().setBody("{}").setResponseCode(200))

        val response = api.scan(ScanInput(text = "test"))
        try {
            UnifiedScanResponseParser.parse(response.body()!!)
            throw AssertionError("Expected missing response fields to fail validation")
        } catch (e: MalformedScanResponseException) {
            assertTrue(e.message!!.contains("scan_id"))
        }
    }

    @Test
    fun `test timeout`() = runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setBodyDelay(300, TimeUnit.MILLISECONDS)
                .setBody("{}")
                .setResponseCode(200)
        )

        try {
            createApi(readTimeoutMillis = 50).scan(ScanInput(text = "test"))
            throw AssertionError("Expected read timeout")
        } catch (e: IOException) {
            assertTrue(generateSequence<Throwable>(e) { it.cause }.any { it is SocketTimeoutException })
        }
    }

    @Test
    fun `test network failure`() = runTest {
        mockWebServer.shutdown()

        try {
            api.scan(ScanInput(text = "test"))
            throw AssertionError("Expected network failure")
        } catch (e: IOException) {
            assertTrue(e.message != null)
        }
    }

    @Test
    fun `file bytes use backend UTF-8 JSON bytes representation`() {
        val content = "plain text: café"
        val encoded = fileBytesAsBackendJsonValue(content.toByteArray(Charsets.UTF_8))
        assertEquals(content, encoded)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `binary file bytes are rejected instead of corrupted`() {
        fileBytesAsBackendJsonValue(byteArrayOf(0, 0xC3.toByte(), 0x28))
    }
}