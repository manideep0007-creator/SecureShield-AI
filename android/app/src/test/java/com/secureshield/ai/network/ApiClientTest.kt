package com.secureshield.ai.network

import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.OkHttpClient
import com.google.gson.stream.MalformedJsonException
import org.junit.After
import org.junit.Assert.assertArrayEquals
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
    fun `file bytes are base64-encoded for the JSON transport`() {
        val content = "plain text: café"
        val encoded = fileBytesAsBackendJsonValue(content.toByteArray(Charsets.UTF_8))
        assertEquals(
            java.util.Base64.getEncoder().encodeToString(content.toByteArray(Charsets.UTF_8)),
            encoded
        )
    }

    @Test
    fun `binary file bytes are base64-encoded without corruption`() {
        val binary = byteArrayOf(0, 0xC3.toByte(), 0x28, 0x89.toByte(), 0x50, 0x4E, 0x47)
        val encoded = fileBytesAsBackendJsonValue(binary)
        assertEquals(java.util.Base64.getEncoder().encodeToString(binary), encoded)
        assertArrayEquals(binary, java.util.Base64.getDecoder().decode(encoded))
    }

    @Test
    fun `file bytes contain no base64 line wrapping`() {
        val large = ByteArray(300) { (it % 256).toByte() }
        val encoded = fileBytesAsBackendJsonValue(large)
        assertFalse(encoded.contains("\n"))
        assertFalse(encoded.contains("\r"))
        assertArrayEquals(large, java.util.Base64.getDecoder().decode(encoded))
    }

    @Test
    fun `scan response warnings are parsed when present`() = runTest {
        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody("""
            {
                "scan_id": "test-uuid-warn",
                "status": "completed",
                "total_engines": 2,
                "completed_engines": 1,
                "skipped_engines": 0,
                "risk_score": 12.0,
                "classification": "Safe",
                "warnings": ["malware scan unavailable: VT_API_ERROR_429"],
                "results": [],
                "risk_assessment": {
                    "risk_score": 12.0,
                    "classification": "Safe",
                    "confidence": 0.8,
                    "contributing_engines": ["url_engine"],
                    "ignored_engines": ["malware_engine"],
                    "flags": [],
                    "evidence": [],
                    "reasons": ["No threats found."],
                    "recommended_action": "Proceed with normal caution."
                }
            }
        """.trimIndent()))

        val response = api.scan(ScanInput(text = "test"))
        val parsed = UnifiedScanResponseParser.parse(response.body()!!)
        assertEquals(listOf("malware scan unavailable: VT_API_ERROR_429"), parsed.warnings)
    }

    @Test
    fun `scan response without warnings defaults to an empty list`() = runTest {
        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody("""
            {
                "scan_id": "test-uuid-no-warn",
                "status": "completed",
                "total_engines": 1,
                "completed_engines": 1,
                "skipped_engines": 0,
                "risk_score": 10.0,
                "classification": "Safe",
                "results": [],
                "risk_assessment": {
                    "risk_score": 10.0,
                    "classification": "Safe",
                    "confidence": 0.9,
                    "contributing_engines": ["url_engine"],
                    "ignored_engines": [],
                    "flags": [],
                    "evidence": [],
                    "reasons": [],
                    "recommended_action": "Proceed."
                }
            }
        """.trimIndent()))

        val response = api.scan(ScanInput(text = "test"))
        val parsed = UnifiedScanResponseParser.parse(response.body()!!)
        assertEquals(emptyList<String>(), parsed.warnings)
    }

    @Test
    fun `non-string warnings are rejected as malformed`() = runTest {
        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody("""
            {
                "scan_id": "test-uuid-bad-warn",
                "status": "completed",
                "total_engines": 1,
                "completed_engines": 1,
                "skipped_engines": 0,
                "risk_score": 10.0,
                "classification": "Safe",
                "warnings": [42],
                "results": [],
                "risk_assessment": {
                    "risk_score": 10.0,
                    "classification": "Safe",
                    "confidence": 0.9,
                    "contributing_engines": [],
                    "ignored_engines": [],
                    "flags": [],
                    "evidence": [],
                    "reasons": [],
                    "recommended_action": "Proceed."
                }
            }
        """.trimIndent()))

        val response = api.scan(ScanInput(text = "test"))
        try {
            UnifiedScanResponseParser.parse(response.body()!!)
            throw AssertionError("Expected non-string warnings to fail validation")
        } catch (e: MalformedScanResponseException) {
            assertTrue(e.message!!.contains("warnings"))
        }
    }

    @Test
    fun `test probe api does not repoint the shared base url`() {
        val sharedBefore = ApiClient.baseUrl
        ApiClient.createProbeApi("http://9.9.9.9:8000/")
        assertEquals(sharedBefore, ApiClient.baseUrl)

        ApiClient.createProbeApi("https://example.invalid/path")
        assertEquals(sharedBefore, ApiClient.baseUrl)
    }

    @Test
    fun `normalizeBaseUrl appends a single trailing slash`() {
        assertEquals("http://10.0.2.2:8000/", ApiClient.normalizeBaseUrl("http://10.0.2.2:8000"))
        assertEquals("http://10.0.2.2:8000/", ApiClient.normalizeBaseUrl("http://10.0.2.2:8000/"))
        assertEquals("http://192.168.1.5:8000/", ApiClient.normalizeBaseUrl("  http://192.168.1.5:8000  "))
    }

    @Test
    fun `test scan input includes classification profile`() = runTest {
        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody("""
            {
                "scan_id": "test-uuid-profile",
                "status": "completed",
                "total_engines": 1,
                "completed_engines": 1,
                "skipped_engines": 0,
                "risk_score": 45.0,
                "classification": "Deceptive",
                "results": [],
                "risk_assessment": {
                    "risk_score": 45.0,
                    "classification": "Deceptive",
                    "confidence": 0.95,
                    "contributing_engines": ["url_engine"],
                    "ignored_engines": [],
                    "flags": [],
                    "evidence": [],
                    "reasons": ["Risk assessed under strict profile."],
                    "recommended_action": "Do not trust this content."
                }
            }
        """.trimIndent()))

        val input = ScanInput(text = "sample", classification_profile = "strict")
        val response = api.scan(input)
        assertTrue(response.isSuccessful)
        val parsed = UnifiedScanResponseParser.parse(response.body()!!)
        assertEquals("Deceptive", parsed.classification)

        val recordedRequest = mockWebServer.takeRequest()
        assertTrue(recordedRequest.body.readUtf8().contains("\"classification_profile\":\"strict\""))
    }

    @Test
    fun `test malformed schema response missing root classification`() = runTest {
        val jsonWithoutClassification = """
            {
                "scan_id": "test-uuid",
                "status": "completed",
                "total_engines": 1,
                "completed_engines": 1,
                "skipped_engines": 0,
                "risk_score": 85.0,
                "results": [],
                "risk_assessment": {
                    "risk_score": 85.0,
                    "classification": "Phishing",
                    "confidence": 0.9,
                    "contributing_engines": [],
                    "ignored_engines": [],
                    "flags": [],
                    "evidence": [],
                    "reasons": [],
                    "recommended_action": "Do not click"
                }
            }
        """.trimIndent()
        mockWebServer.enqueue(MockResponse().setResponseCode(200).setBody(jsonWithoutClassification))
        val response = api.scan(ScanInput(text = "test"))
        try {
            UnifiedScanResponseParser.parse(response.body()!!)
            throw AssertionError("Expected missing root classification to fail validation")
        } catch (e: MalformedScanResponseException) {
            assertTrue(e.message!!.contains("classification"))
        }
    }
}