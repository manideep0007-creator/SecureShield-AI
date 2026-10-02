package com.secureshield.ai.feedback

import com.google.gson.JsonParseException
import com.google.gson.stream.MalformedJsonException
import com.secureshield.ai.network.FeedbackRequest
import com.secureshield.ai.network.FeedbackSubmissionResponse
import kotlinx.coroutines.CancellationException
import retrofit2.Response
import java.io.EOFException
import java.io.IOException

sealed class FeedbackSubmissionResult {
    object Submitted : FeedbackSubmissionResult()
    object AlreadySubmitted : FeedbackSubmissionResult()
    object InProgress : FeedbackSubmissionResult()
    data class HttpFailure(val statusCode: Int) : FeedbackSubmissionResult()
    object NetworkFailure : FeedbackSubmissionResult()
    object MalformedResponse : FeedbackSubmissionResult()
}

object FeedbackSubmissionUiPolicy {
    fun shouldDismissFeedback(result: FeedbackSubmissionResult): Boolean =
        result == FeedbackSubmissionResult.Submitted || result == FeedbackSubmissionResult.AlreadySubmitted
}

class FeedbackSubmissionManager(
    private val send: suspend (FeedbackRequest) -> Response<FeedbackSubmissionResponse>
) {
    private val lock = Any()
    private val inFlightScanIds = mutableSetOf<String>()
    private val submittedScanIds = mutableSetOf<String>()

    suspend fun submit(request: FeedbackRequest): FeedbackSubmissionResult {
        if (request.scan_id.isBlank()) return FeedbackSubmissionResult.MalformedResponse
        val reservation = synchronized(lock) {
            when {
                request.scan_id in submittedScanIds -> false
                request.scan_id in inFlightScanIds -> null
                else -> {
                    inFlightScanIds.add(request.scan_id)
                    true
                }
            }
        }
        if (reservation == false) return FeedbackSubmissionResult.AlreadySubmitted
        if (reservation == null) return FeedbackSubmissionResult.InProgress

        try {
            val response = send(request)
            if (response.code() == 409) {
                markSubmitted(request.scan_id)
                return FeedbackSubmissionResult.AlreadySubmitted
            }
            if (!response.isSuccessful) return FeedbackSubmissionResult.HttpFailure(response.code())
            val body = response.body()
            if (body?.status != "success" || body.scan_id != request.scan_id || body.timestamp.isNullOrBlank()) {
                return FeedbackSubmissionResult.MalformedResponse
            }
            markSubmitted(request.scan_id)
            return FeedbackSubmissionResult.Submitted
        } catch (error: CancellationException) {
            throw error
        } catch (_: JsonParseException) {
            return FeedbackSubmissionResult.MalformedResponse
        } catch (_: MalformedJsonException) {
            return FeedbackSubmissionResult.MalformedResponse
        } catch (_: EOFException) {
            return FeedbackSubmissionResult.MalformedResponse
        } catch (_: IOException) {
            return FeedbackSubmissionResult.NetworkFailure
        } catch (_: Exception) {
            return FeedbackSubmissionResult.NetworkFailure
        } finally {
            synchronized(lock) { inFlightScanIds.remove(request.scan_id) }
        }
    }

    private fun markSubmitted(scanId: String) {
        synchronized(lock) { submittedScanIds.add(scanId) }
    }
}