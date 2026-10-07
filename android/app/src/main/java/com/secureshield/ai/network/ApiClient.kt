package com.secureshield.ai.network

import com.secureshield.ai.BuildConfig
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParseException
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST
import okhttp3.OkHttpClient
import okio.ByteString.Companion.toByteString
import java.util.concurrent.TimeUnit

data class ScanInput(
    val text: String? = null,
    val url: String? = null,
    val sender_id: String? = null,
    val source_channel: String? = null,
    val file_name: String? = null,
    val file_bytes: String? = null,
    val image_bytes: String? = null,
    val metadata: Map<String, Any> = emptyMap(),
    val classification_profile: String? = null
)

data class EvidenceItem(
    val key: String,
    val value: Any?,
    val description: String?
)

data class RiskAssessment(
    val risk_score: Float,
    val classification: String,
    val confidence: Float,
    val contributing_engines: List<String>,
    val ignored_engines: List<String>,
    val flags: List<String>,
    val evidence: List<EvidenceItem>,
    val reasons: List<String>,
    val recommended_action: String
)

data class EngineResult(
    val engine_name: String,
    val risk_score: Float,
    val confidence: Float,
    val flags: List<String>,
    val evidence: List<EvidenceItem>,
    val status: String,
    val error_message: String?,
    val metadata: Map<String, Any>
)

data class UnifiedScanResponse(
    val scan_id: String,
    val status: String,
    val results: List<EngineResult>,
    val total_engines: Int,
    val completed_engines: Int,
    val skipped_engines: Int,
    val risk_assessment: RiskAssessment,
    val risk_score: Float,
    val classification: String,
    val warnings: List<String> = emptyList()
)

data class FeedbackRequest(
    val scan_id: String,
    val user_feedback: String,
    val classification_at_scan_time: String,
    val risk_score_at_scan_time: Float,
    val confidence_at_scan_time: Float,
    val source_type: String
)

data class FeedbackSubmissionResponse(
    val status: String?,
    val scan_id: String?,
    val timestamp: String?
)

interface SecureShieldApi {
    @POST("/api/scan")
    suspend fun scan(@Body request: ScanInput): Response<JsonObject>
    
    @POST("/api/feedback")
    suspend fun sendFeedback(@Body request: FeedbackRequest): Response<FeedbackSubmissionResponse>

    @retrofit2.http.GET("/health")
    suspend fun healthCheck(): Response<JsonObject>
}

class MalformedScanResponseException(message: String) : RuntimeException(message)

object UnifiedScanResponseParser {
    private val gson = Gson()

    fun parse(json: JsonObject): UnifiedScanResponse {
        requireString(json, "scan_id")
        requireString(json, "status")
        requireNumber(json, "total_engines")
        requireNumber(json, "completed_engines")
        requireNumber(json, "skipped_engines")
        requireNumber(json, "risk_score")
        requireString(json, "classification")

        val assessment = requireObject(json, "risk_assessment")
        requireNumber(assessment, "risk_score")
        requireString(assessment, "classification")
        requireNumber(assessment, "confidence")
        requireStringArray(assessment, "contributing_engines")
        requireStringArray(assessment, "ignored_engines")
        requireStringArray(assessment, "flags")
        requireEvidenceArray(assessment, "evidence")
        requireStringArray(assessment, "reasons")
        requireString(assessment, "recommended_action")

        requireArray(json, "results").forEach { resultElement ->
            val result = requireObject(resultElement, "result")
            requireString(result, "engine_name")
            requireNumber(result, "risk_score")
            requireNumber(result, "confidence")
            requireStringArray(result, "flags")
            requireEvidenceArray(result, "evidence")
            requireString(result, "status")
            if (result.has("error_message") && !result.get("error_message").isJsonNull) {
                requireString(result, "error_message")
            }
            requireObject(result, "metadata")
        }

        if (json.has("warnings") && !json.get("warnings").isJsonNull) {
            requireStringArray(json, "warnings")
        }

        return try {
            gson.fromJson(json, UnifiedScanResponse::class.java).let { parsed ->
                val warnings = if (json.has("warnings") && json.get("warnings").isJsonArray) {
                    json.getAsJsonArray("warnings").map { it.asString }
                } else {
                    emptyList()
                }
                parsed.copy(warnings = warnings)
            }
        } catch (error: JsonParseException) {
            throw MalformedScanResponseException("Response fields do not match the scan contract.")
        }
    }

    private fun requireObject(parent: JsonObject, name: String): JsonObject =
        requireElement(parent, name).takeIf(JsonElement::isJsonObject)?.asJsonObject
            ?: malformed("'$name' must be an object.")

    private fun requireObject(element: JsonElement, name: String): JsonObject =
        element.takeIf(JsonElement::isJsonObject)?.asJsonObject
            ?: malformed("$name must be an object.")

    private fun requireArray(parent: JsonObject, name: String): JsonArray =
        requireElement(parent, name).takeIf(JsonElement::isJsonArray)?.asJsonArray
            ?: malformed("'$name' must be an array.")

    private fun requireString(parent: JsonObject, name: String) {
        val value = requireElement(parent, name)
        if (!value.isJsonPrimitive || !value.asJsonPrimitive.isString) malformed("'$name' must be a string.")
    }

    private fun requireNumber(parent: JsonObject, name: String) {
        val value = requireElement(parent, name)
        if (!value.isJsonPrimitive || !value.asJsonPrimitive.isNumber) malformed("'$name' must be a number.")
    }

    private fun requireStringArray(parent: JsonObject, name: String) {
        requireArray(parent, name).forEach { value ->
            if (!value.isJsonPrimitive || !value.asJsonPrimitive.isString) malformed("'$name' must contain strings.")
        }
    }

    private fun requireEvidenceArray(parent: JsonObject, name: String) {
        requireArray(parent, name).forEach { item ->
            val evidence = requireObject(item, "evidence item")
            requireString(evidence, "key")
            requireString(evidence, "description")
            if (!evidence.has("value")) malformed("Evidence items must include 'value'.")
        }
    }

    private fun requireElement(parent: JsonObject, name: String): JsonElement =
        parent.get(name)?.takeUnless(JsonElement::isJsonNull)
            ?: malformed("Missing or null required field '$name'.")

    private fun malformed(message: String): Nothing = throw MalformedScanResponseException(message)
}

/**
 * Encodes a file payload for the scan API.
 *
 * JSON cannot carry raw bytes and the backend `file_bytes` field decodes strings as
 * base64, so every payload — text or binary — is base64-encoded here. Encoding the
 * bytes verbatim instead would corrupt any non-UTF-8 file (PE, PDF, ZIP, images) and
 * invalidate the SHA-256 the Malware engine sends to VirusTotal.
 *
 * okio's ByteString produces standard padded base64 with no line wrapping, so the
 * value stays a single JSON string token.
 */
fun fileBytesAsBackendJsonValue(bytes: ByteArray): String = bytes.toByteString().base64()

object ApiClient {
    @Volatile
    private var customBaseUrl: String? = null

    val baseUrl: String
        get() = customBaseUrl ?: BuildConfig.BASE_URL

    private val okHttpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(35, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }

    @Volatile
    private var currentApi: SecureShieldApi? = null

    val api: SecureShieldApi
        get() = currentApi ?: synchronized(this) {
            currentApi ?: Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
                .create(SecureShieldApi::class.java).also { currentApi = it }
        }

    fun setBaseUrl(url: String) {
        val trimmed = url.trim()
        val sanitized = if (!trimmed.endsWith("/")) "$trimmed/" else trimmed
        synchronized(this) {
            customBaseUrl = sanitized
            currentApi = null
        }
    }

    fun normalizeBaseUrl(url: String): String {
        val trimmed = url.trim()
        return if (!trimmed.endsWith("/")) "$trimmed/" else trimmed
    }

    /**
     * Builds a throwaway API client for [url] without touching the shared instance.
     * Connectivity tests must not repoint live scans at an unverified server.
     */
    fun createProbeApi(url: String): SecureShieldApi = Retrofit.Builder()
        .baseUrl(normalizeBaseUrl(url))
        .client(probeOkHttpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(SecureShieldApi::class.java)

    private val probeOkHttpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()
    }
}