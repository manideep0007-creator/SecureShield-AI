package com.secureshield.ai.background

import com.secureshield.ai.GmailFetchResult
import com.secureshield.ai.history.ScanHistoryRecord
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse

interface BackgroundDependencies {
    val isEnabled: Boolean
    val accountActive: Boolean
    fun updateLastCheck()
    suspend fun fetchUnreadMessages(): GmailFetchResult
    fun isProcessed(messageId: String): Boolean
    fun markProcessed(messageId: String)
    suspend fun scan(input: ScanInput): UnifiedScanResponse?
    suspend fun saveHistory(result: UnifiedScanResponse, source: String)
    fun notifyThreat(classification: String, score: Float, action: String)
}

object BackgroundScanner {
    suspend fun execute(deps: BackgroundDependencies): Boolean {
        if (!deps.isEnabled) return true
        deps.updateLastCheck()
        
        if (!deps.accountActive) return true
        
        val fetchResult = try {
            deps.fetchUnreadMessages()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            return false // Retry
        }

        if (fetchResult !is GmailFetchResult.Messages) {
            return true
        }

        for (email in fetchResult.emails) {
            if (deps.isProcessed(email.messageId)) continue
            
            try {
                val input = email.toScanInput()
                val result = deps.scan(input)
                if (result != null) {
                    deps.saveHistory(result, "gmail")
                    if (result.classification == "Phishing" || result.classification == "Malware") {
                        deps.notifyThreat(result.classification, result.risk_score, result.risk_assessment.recommended_action)
                    }
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (_: Exception) {
                // Ignore individual message failure
            } finally {
                deps.markProcessed(email.messageId)
            }
        }
        return true
    }
}