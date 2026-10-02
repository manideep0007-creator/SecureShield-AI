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
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

data class ScanInput(
    val text: String? = null,
    val url: String? = null,
    val sender_id: String? = null,
    val source_channel: String? = null,
    val file_name: String? = null,
    val file_bytes: String? = null,
    val image_bytes: String? = null,
    val metadata: Map<String, Any> = emptyMap()
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
    val classification: String
)

data class FeedbackRequest(
    val analyzed_target: String,
    val score: Int,
    val category: String,
    val feedback_value: String
)

interface SecureShieldApi {
    @POST("/api/scan")
    suspend fun scan(@Body request: ScanInput): Response<JsonObject>
    
    @POST("/api/feedback")
    suspend fun sendFeedback(@Body request: FeedbackRequest): Response<Unit>
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

        return try {
            gson.fromJson(json, UnifiedScanResponse::class.java)
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

fun fileBytesAsBackendJsonValue(bytes: ByteArray): String = try {
    StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (error: java.nio.charset.CharacterCodingException) {
    throw IllegalArgumentException("The scan API accepts UTF-8 file content only.", error)
}

object ApiClient {
    private val BASE_URL = BuildConfig.BASE_URL 

    val api: SecureShieldApi by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SecureShieldApi::class.java)
    }
}