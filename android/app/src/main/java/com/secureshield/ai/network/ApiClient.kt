package com.secureshield.ai.network

import com.secureshield.ai.BuildConfig
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST

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
    suspend fun scan(@Body request: ScanInput): Response<UnifiedScanResponse>
    
    @POST("/api/feedback")
    suspend fun sendFeedback(@Body request: FeedbackRequest): Response<Unit>
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