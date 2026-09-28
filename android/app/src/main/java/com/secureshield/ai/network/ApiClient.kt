package com.secureshield.ai.network

import com.secureshield.ai.BuildConfig
import okhttp3.MultipartBody
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part

data class MessageScanRequest(
    val message_text: String?,
    val url: String?,
    val sender_id: String?
)

data class FeedbackRequest(
    val analyzed_target: String,
    val score: Int,
    val category: String,
    val feedback_value: String
)

data class ScanResponse(
    val final_score: Int,
    val category: String,
    val reasons: List<String>,
    val recommended_action: String,
    val analyzed_target: String
)

interface SecureShieldApi {
    @POST("/api/analyze/message")
    suspend fun analyzeMessage(@Body request: MessageScanRequest): Response<ScanResponse>

    @Multipart
    @POST("/api/analyze/file")
    suspend fun analyzeFile(@Part file: MultipartBody.Part): Response<ScanResponse>
    
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