package com.secureshield.ai

enum class GmailOAuthOutcome {
    AUTHORIZED,
    CANCELLED,
    FAILED
}

object GmailOAuthOutcomeMapper {
    fun classify(hasAccount: Boolean, statusCode: Int?, cancellationStatusCode: Int): GmailOAuthOutcome = when {
        hasAccount -> GmailOAuthOutcome.AUTHORIZED
        statusCode == cancellationStatusCode -> GmailOAuthOutcome.CANCELLED
        else -> GmailOAuthOutcome.FAILED
    }
}