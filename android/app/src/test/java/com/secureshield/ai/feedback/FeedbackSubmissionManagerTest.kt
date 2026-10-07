package com.secureshield.ai.feedback

import com.google.gson.JsonParseException
import com.secureshield.ai.network.FeedbackRequest
import com.secureshield.ai.network.FeedbackSubmissionResponse
import kotlinx.coroutines.async
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Response
import java.io.IOException

class FeedbackSubmissionManagerTest {
    private fun request(scanId: String = "scan-uuid") = FeedbackRequest(
        scan_id = scanId,
        user_feedback = "positive",
        classification_at_scan_time = "Safe",
        risk_score_at_scan_time = 10.5f,
        confidence_at_scan_time = 0.9f,
        source_type = "url"
    )

    @Test
    fun `feedback success is associated with scan id`() = runTest {
        val manager = FeedbackSubmissionManager { input ->
            Response.success(FeedbackSubmissionResponse("success", input.scan_id, "2026-10-02T12:00:00Z"))
        }

        assertEquals(FeedbackSubmissionResult.Submitted, manager.submit(request()))
        assertTrue(FeedbackSubmissionUiPolicy.shouldDismissFeedback(FeedbackSubmissionResult.Submitted))
    }

    @Test
    fun `duplicate submission is prevented after accepted feedback`() = runTest {
        var requests = 0
        val manager = FeedbackSubmissionManager { input ->
            requests++
            Response.success(FeedbackSubmissionResponse("success", input.scan_id, "2026-10-02T12:00:00Z"))
        }

        assertEquals(FeedbackSubmissionResult.Submitted, manager.submit(request()))
        assertEquals(FeedbackSubmissionResult.AlreadySubmitted, manager.submit(request()))
        assertEquals(1, requests)
    }

    @Test
    fun `in-flight duplicate does not send twice`() = runTest {
        val gate = CompletableDeferred<Unit>()
        var requests = 0
        val manager = FeedbackSubmissionManager { input ->
            requests++
            gate.await()
            Response.success(FeedbackSubmissionResponse("success", input.scan_id, "2026-10-02T12:00:00Z"))
        }
        val first = async { manager.submit(request()) }
        kotlinx.coroutines.yield()

        assertEquals(FeedbackSubmissionResult.InProgress, manager.submit(request()))
        gate.complete(Unit)
        assertEquals(FeedbackSubmissionResult.Submitted, first.await())
        assertEquals(1, requests)
    }

    @Test
    fun `network failure leaves scan result usable and permits retry`() = runTest {
        var attempts = 0
        val manager = FeedbackSubmissionManager { input ->
            attempts++
            if (attempts == 1) throw IOException("offline")
            Response.success(FeedbackSubmissionResponse("success", input.scan_id, "2026-10-02T12:00:00Z"))
        }
        val visibleScanId = request().scan_id

        val failed = manager.submit(request())
        assertEquals(FeedbackSubmissionResult.NetworkFailure, failed)
        assertFalse(FeedbackSubmissionUiPolicy.shouldDismissFeedback(failed))
        assertEquals("scan-uuid", visibleScanId)
        assertEquals(FeedbackSubmissionResult.Submitted, manager.submit(request()))
        assertEquals("scan-uuid", visibleScanId)
    }

    @Test
    fun `malformed feedback responses do not mark scan submitted`() = runTest {
        val manager = FeedbackSubmissionManager { input ->
            Response.success(FeedbackSubmissionResponse("success", "different-scan", ""))
        }

        val outcome = manager.submit(request())
        assertEquals(FeedbackSubmissionResult.MalformedResponse, outcome)
        assertFalse(FeedbackSubmissionUiPolicy.shouldDismissFeedback(outcome))
    }

    @Test
    fun `malformed JSON is reported separately from network errors`() = runTest {
        val manager = FeedbackSubmissionManager { throw JsonParseException("bad response") }

        assertEquals(FeedbackSubmissionResult.MalformedResponse, manager.submit(request()))
    }

    @Test
    fun `HTTP errors retain feedback controls`() = runTest {
        val manager = FeedbackSubmissionManager {
            Response.error(503, "unavailable".toResponseBody("text/plain".toMediaType()))
        }

        val outcome = manager.submit(request())
        assertEquals(FeedbackSubmissionResult.HttpFailure(503), outcome)
        assertFalse(FeedbackSubmissionUiPolicy.shouldDismissFeedback(outcome))
    }

    @Test
    fun `isSubmitted accurately tracks submission state`() = runTest {
        val manager = FeedbackSubmissionManager { input ->
            Response.success(FeedbackSubmissionResponse("success", input.scan_id, "2026-10-02T12:00:00Z"))
        }

        assertFalse(manager.isSubmitted("scan-uuid"))
        assertEquals(FeedbackSubmissionResult.Submitted, manager.submit(request("scan-uuid")))
        assertTrue(manager.isSubmitted("scan-uuid"))
        assertFalse(manager.isSubmitted("other-scan-uuid"))
    }
}