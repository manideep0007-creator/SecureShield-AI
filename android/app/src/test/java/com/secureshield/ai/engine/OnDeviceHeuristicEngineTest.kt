package com.secureshield.ai.engine

import com.google.gson.Gson
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponseParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OnDeviceHeuristicEngineTest {

    private val gson = Gson()

    @Test
    fun `malicious URL with IP, userinfo, and suspicious keywords is classified as Phishing or Deceptive`() {
        val input = ScanInput(url = "http://192.168.1.1@secure-login-verify.xyz/account")
        val response = OnDeviceHeuristicEngine.scan(input)

        assertNotNull(response)
        assertTrue("Risk score should be high: ${response.risk_score}", response.risk_score >= 60f)
        assertTrue(
            "Classification should be Phishing or Deceptive but was ${response.classification}",
            response.classification in setOf("Phishing", "Deceptive")
        )
        assertTrue(response.risk_assessment.flags.contains("ip_based_host"))
        assertTrue(response.risk_assessment.flags.contains("at_symbol_present"))
        assertTrue(response.risk_assessment.flags.contains("suspicious_tld"))
        assertTrue(response.risk_assessment.flags.contains("suspicious_keywords"))
        assertTrue(response.risk_assessment.reasons.isNotEmpty())
        assertTrue(response.warnings.isNotEmpty())
        assertEquals(listOf("Limited offline check - cloud engines were not used"), response.warnings)

        // Verify JSON round-trip strictly matches backend contract
        val jsonElement = gson.toJsonTree(response).asJsonObject
        val parsed = UnifiedScanResponseParser.parse(jsonElement)
        assertEquals(response.scan_id, parsed.scan_id)
        assertEquals(response.classification, parsed.classification)
    }

    @Test
    fun `urgent phishing email body with social engineering triggers is classified high risk`() {
        val input = ScanInput(
            text = "URGENT: Your account has been suspended due to unauthorized activity. Please verify your identity immediately.",
            sender_id = "security-alert@fakebank-update.xyz"
        )
        val response = OnDeviceHeuristicEngine.scan(input)

        assertNotNull(response)
        assertTrue("Risk score should be >= 50: ${response.risk_score}", response.risk_score >= 50f)
        assertTrue(response.risk_assessment.flags.contains("urgency_and_fear_cues"))
        assertTrue(response.risk_assessment.flags.contains("credential_harvesting_intent"))
        assertTrue(response.risk_assessment.flags.contains("suspicious_sender_tld"))
    }

    @Test
    fun `dangerous executable and double extension files are classified as Malware`() {
        val exeInput = ScanInput(file_name = "security_patch.apk")
        val exeResponse = OnDeviceHeuristicEngine.scan(exeInput)
        assertTrue(exeResponse.risk_score >= 70f)
        assertTrue(exeResponse.risk_assessment.flags.contains("dangerous_executable_extension"))

        val doubleExtInput = ScanInput(file_name = "urgent_invoice.pdf.exe")
        val doubleExtResponse = OnDeviceHeuristicEngine.scan(doubleExtInput)
        assertTrue(doubleExtResponse.risk_score >= 80f)
        assertEquals("Malware", doubleExtResponse.classification)
        assertTrue(doubleExtResponse.risk_assessment.flags.contains("double_extension_anomaly"))
    }

    @Test
    fun `benign input returns Safe verdict with low risk score`() {
        val cleanInput = ScanInput(
            url = "https://www.google.com/search?q=weather",
            text = "Hello team, let's meet tomorrow at 10 AM for sprint planning."
        )
        val cleanResponse = OnDeviceHeuristicEngine.scan(cleanInput)

        assertEquals("Safe", cleanResponse.classification)
        assertTrue("Risk score should be low: ${cleanResponse.risk_score}", cleanResponse.risk_score < 25f)
        assertTrue(cleanResponse.risk_assessment.reasons.isNotEmpty())
    }

    @Test
    fun `popular trusted domains with login or account paths return Safe with low risk score`() {
        val googleLogin = ScanInput(url = "https://accounts.google.com/signin/v2/identifier")
        val googleResp = OnDeviceHeuristicEngine.scan(googleLogin)
        assertEquals("Safe", googleResp.classification)
        assertTrue("Expected score < 20 for accounts.google.com, got ${googleResp.risk_score}", googleResp.risk_score < 20f)
        assertTrue(googleResp.risk_assessment.flags.contains("whitelisted_trusted_domain"))
        assertFalse(googleResp.risk_assessment.flags.contains("suspicious_keywords"))

        val msftAccount = ScanInput(url = "https://support.microsoft.com/en-us/account-billing/help")
        val msftResp = OnDeviceHeuristicEngine.scan(msftAccount)
        assertEquals("Safe", msftResp.classification)
        assertTrue("Expected score < 20 for support.microsoft.com, got ${msftResp.risk_score}", msftResp.risk_score < 20f)
        assertTrue(msftResp.risk_assessment.flags.contains("whitelisted_trusted_domain"))

        val wikiPage = ScanInput(url = "https://en.wikipedia.org/wiki/Phishing")
        val wikiResp = OnDeviceHeuristicEngine.scan(wikiPage)
        assertEquals("Safe", wikiResp.classification)
        assertTrue(wikiResp.risk_score < 20f)
    }

    @Test
    fun `brand impersonation spoofing on untrusted root domain is classified as Phishing or Deceptive`() {
        val spoofInput = ScanInput(url = "http://paypal.com.account-update.xyz/login")
        val spoofResp = OnDeviceHeuristicEngine.scan(spoofInput)

        assertTrue("Risk score should be >= 80, got ${spoofResp.risk_score}", spoofResp.risk_score >= 80f)
        assertTrue(spoofResp.classification in setOf("Phishing", "Deceptive"))
        assertTrue(spoofResp.risk_assessment.flags.contains("brand_impersonation_spoofing"))
    }

    @Test
    fun `homograph punycode domain is classified as high risk Phishing`() {
        // Cyrillic 'а' (U+0430) in paypal.com
        val homographInput = ScanInput(url = "https://pаypal.com/signin")
        val homographResp = OnDeviceHeuristicEngine.scan(homographInput)

        assertTrue("Homograph score should be >= 60, got ${homographResp.risk_score}", homographResp.risk_score >= 60f)
        assertTrue(homographResp.risk_assessment.flags.contains("homograph_punycode_attack"))
    }

    @Test
    fun `empty input gracefully handles triage without throwing`() {
        val emptyInput = ScanInput()
        val emptyResponse = OnDeviceHeuristicEngine.scan(emptyInput)

        assertEquals("Safe", emptyResponse.classification)
        assertEquals(0f, emptyResponse.risk_score)
        assertTrue(emptyResponse.results.all { it.status == "skipped" })
    }
}
