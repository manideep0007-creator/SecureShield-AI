package com.secureshield.ai.notification

import com.secureshield.ai.network.RiskAssessment
import com.secureshield.ai.network.UnifiedScanResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SmartNotificationManagerTest {

    private fun buildScanResponse(score: Float, classification: String, flags: List<String> = emptyList()): UnifiedScanResponse {
        return UnifiedScanResponse(
            scan_id = "test-id",
            status = "completed",
            results = emptyList(),
            total_engines = 4,
            completed_engines = 4,
            skipped_engines = 0,
            risk_assessment = RiskAssessment(
                risk_score = score,
                classification = classification,
                confidence = 0.90f,
                contributing_engines = listOf("url_engine"),
                ignored_engines = emptyList(),
                flags = flags,
                evidence = emptyList(),
                reasons = listOf("Testing reason"),
                recommended_action = "Action"
            ),
            risk_score = score,
            classification = classification,
            warnings = emptyList()
        )
    }

    @Test
    fun `safe and low-risk scans never trigger notifications`() {
        val safeResponse = buildScanResponse(0f, "Safe")
        val decision = SmartNotificationManager.shouldSendThreatNotification(safeResponse)
        assertEquals(SmartNotificationManager.NotificationTier.NONE, decision.tier)
        assertFalse("Safe scans must never post push notifications", decision.shouldPostNotification)

        val lowResponse = buildScanResponse(18f, "Safe")
        val lowDecision = SmartNotificationManager.shouldSendThreatNotification(lowResponse)
        assertEquals(SmartNotificationManager.NotificationTier.NONE, lowDecision.tier)
        assertFalse(lowDecision.shouldPostNotification)
    }

    @Test
    fun `medium-risk suspicious scans are strictly in-app only with no unsolicited push notifications`() {
        val suspiciousResponse = buildScanResponse(45f, "Suspicious")
        val decision = SmartNotificationManager.shouldSendThreatNotification(suspiciousResponse)
        assertEquals(SmartNotificationManager.NotificationTier.IN_APP_ONLY, decision.tier)
        assertFalse(
            "Medium risk suspicious content must NOT send unsolicited push notifications",
            decision.shouldPostNotification
        )
    }

    @Test
    fun `high-risk deceptive scans trigger security warning notification`() {
        val deceptiveResponse = buildScanResponse(
            score = 75f,
            classification = "Deceptive",
            flags = listOf("brand_impersonation", "suspicious_tld")
        )
        val decision = SmartNotificationManager.shouldSendThreatNotification(deceptiveResponse)
        assertEquals(SmartNotificationManager.NotificationTier.SECURITY_WARNING, decision.tier)
        assertTrue("High risk deceptive scans must post security warning", decision.shouldPostNotification)
    }

    @Test
    fun `critical-risk phishing and malware scans trigger immediate critical alert`() {
        val phishingResponse = buildScanResponse(88f, "Phishing", listOf("brand_impersonation", "credential_harvesting"))
        val phishingDecision = SmartNotificationManager.shouldSendThreatNotification(phishingResponse)
        assertEquals(SmartNotificationManager.NotificationTier.CRITICAL_ALERT, phishingDecision.tier)
        assertTrue("Critical phishing must post high priority alert", phishingDecision.shouldPostNotification)

        val malwareResponse = buildScanResponse(95f, "Malware", listOf("malware_detected"))
        val malwareDecision = SmartNotificationManager.shouldSendThreatNotification(malwareResponse)
        assertEquals(SmartNotificationManager.NotificationTier.CRITICAL_ALERT, malwareDecision.tier)
        assertTrue("Critical malware must post high priority alert", malwareDecision.shouldPostNotification)
    }

    @Test
    fun `threat fingerprinting is deterministic and stable`() {
        val fp1 = SmartNotificationManager.computeThreatFingerprint("https://example.com/test", "Phishing")
        val fp2 = SmartNotificationManager.computeThreatFingerprint("https://example.com/test", "Phishing")
        val fpDifferent = SmartNotificationManager.computeThreatFingerprint("https://other.com/test", "Phishing")

        assertEquals(fp1, fp2)
        assertNotEquals(fp1, fpDifferent)
        assertEquals(16, fp1.length)
    }

    @Test
    fun `deduplication suppresses repeated alerts within cooldown but allows escalation`() {
        val fingerprint = SmartNotificationManager.computeThreatFingerprint("http://threat-source-123.xyz", "Warning")

        // 1. First alert is permitted
        val isFirstDuplicate = SmartNotificationManager.isDuplicateOrInCooldown(
            context = null,
            threatId = fingerprint,
            currentTier = SmartNotificationManager.NotificationTier.SECURITY_WARNING
        )
        assertFalse("First alert must not be marked as duplicate", isFirstDuplicate)

        // 2. Immediate duplicate within cooldown is suppressed
        val isSecondDuplicate = SmartNotificationManager.isDuplicateOrInCooldown(
            context = null,
            threatId = fingerprint,
            currentTier = SmartNotificationManager.NotificationTier.SECURITY_WARNING
        )
        assertTrue("Immediate duplicate within cooldown window must be suppressed", isSecondDuplicate)

        // 3. Escalated severity (Security Warning -> Critical Alert) bypasses cooldown
        val isEscalationDuplicate = SmartNotificationManager.isDuplicateOrInCooldown(
            context = null,
            threatId = fingerprint,
            currentTier = SmartNotificationManager.NotificationTier.CRITICAL_ALERT
        )
        assertFalse("Escalated severity must bypass cooldown", isEscalationDuplicate)
    }
}
