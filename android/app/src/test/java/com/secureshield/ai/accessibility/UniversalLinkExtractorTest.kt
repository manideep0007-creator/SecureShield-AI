package com.secureshield.ai.accessibility

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UniversalLinkExtractorTest {

    @Test
    fun extractUrlsFromText_whatsAppMessageWithPunctuation_extractsCleanUrl() {
        val text = "Hey check this link: https://evil-phish.xyz/login. Don't miss it!"
        val urls = UniversalLinkExtractor.extractUrlsFromText(text)
        assertEquals(listOf("https://evil-phish.xyz/login"), urls)
    }

    @Test
    fun extractUrlsFromText_instagramDmWithParentheses_extractsCleanUrl() {
        val text = "Click here (http://192.168.1.1@secure-login-verify.xyz/account) to verify your account"
        val urls = UniversalLinkExtractor.extractUrlsFromText(text)
        assertEquals(listOf("http://192.168.1.1@secure-login-verify.xyz/account"), urls)
    }

    @Test
    fun extractUrlsFromText_chromeAddressBarDomain_extractsAndNormalizesUrl() {
        val text = "suspicious-banking-update.xyz/auth/redirect"
        val urls = UniversalLinkExtractor.extractUrlsFromText(text)
        assertEquals(listOf("https://suspicious-banking-update.xyz/auth/redirect"), urls)
    }

    @Test
    fun extractUrlsFromText_multipleDistinctUrls_extractsAllWithoutDuplicates() {
        val text = """
            First link: https://test1.com/a
            Second link: http://test2.com/b
            Duplicate link: https://test1.com/a
        """.trimIndent()
        val urls = UniversalLinkExtractor.extractUrlsFromText(text)
        assertEquals(2, urls.size)
        assertTrue(urls.contains("https://test1.com/a"))
        assertTrue(urls.contains("http://test2.com/b"))
    }

    @Test
    fun extractUrlsFromText_plainTextWithoutUrls_returnsEmptyList() {
        val text = "Hello, how are you doing today? Just wanted to say hi."
        val urls = UniversalLinkExtractor.extractUrlsFromText(text)
        assertTrue(urls.isEmpty())
    }

    @Test
    fun cleanAndNormalizeUrl_handlesTrailingAndLeadingPunctuation() {
        assertEquals("https://example.com/test", UniversalLinkExtractor.cleanAndNormalizeUrl("<https://example.com/test>"))
        assertEquals("https://example.com/test", UniversalLinkExtractor.cleanAndNormalizeUrl("\"https://example.com/test\""))
        assertEquals("https://example.com/test", UniversalLinkExtractor.cleanAndNormalizeUrl("https://example.com/test,"))
        assertEquals("https://example.com/test", UniversalLinkExtractor.cleanAndNormalizeUrl("https://example.com/test."))
        assertEquals("https://example.com/test", UniversalLinkExtractor.cleanAndNormalizeUrl("[https://example.com/test]"))
    }

    @Test
    fun hasSuspiciousText_matchingPhrases_returnsTrue() {
        assertTrue(UniversalLinkExtractor.hasSuspiciousText("URGENT: Your bank account is locked due to unauthorized activity"))
        assertTrue(UniversalLinkExtractor.hasSuspiciousText("Security Alert: Please verify your account now"))
        assertTrue(UniversalLinkExtractor.hasSuspiciousText("Account suspended! Confirm your identity immediately"))
    }

    @Test
    fun hasSuspiciousText_benignPhrases_returnsFalse() {
        org.junit.Assert.assertFalse(UniversalLinkExtractor.hasSuspiciousText("Hey are we still meeting for lunch at 12?"))
        org.junit.Assert.assertFalse(UniversalLinkExtractor.hasSuspiciousText("The weather today is sunny and pleasant."))
    }

    @Test
    fun extractSuspiciousTextSnippet_truncatesAndNormalizes() {
        val snippet = UniversalLinkExtractor.extractSuspiciousTextSnippet("URGENT: Security Alert - please verify your account")
        org.junit.Assert.assertNotNull(snippet)
        assertTrue(snippet!!.contains("Security Alert"))
    }

    @Test
    fun sanitizeSnippet_redactsOtpsAndPasscodes() {
        val snippet = "Your OTP is 483920, password reset"
        val sanitized = UniversalLinkExtractor.sanitizeSnippet(snippet)
        org.junit.Assert.assertFalse("Should not contain plain OTP digits", sanitized.contains("483920"))
        assertEquals("Your OTP: [redacted], password reset", sanitized)
    }

    @Test
    fun sanitizeSnippet_cleanPhishingMessage_remainsUnchanged() {
        val clean = "Security alert: Unusual activity detected. Verify your account immediately."
        val sanitized = UniversalLinkExtractor.sanitizeSnippet(clean)
        assertEquals(clean, sanitized)
    }

    @Test
    fun sanitizeSnippet_extendedKeywordsAndDigits_removesAllDigits() {
        val testCases = listOf(
            "your verification code is 483920" to "483920",
            "login code 771204" to "771204",
            "ATM PIN is 4821" to "4821",
            "cvv 123" to "123"
        )

        for ((input, rawDigits) in testCases) {
            val sanitized = UniversalLinkExtractor.sanitizeSnippet(input)
            org.junit.Assert.assertFalse(
                "Output for '$input' must not contain raw digits '$rawDigits'. Got: '$sanitized'",
                sanitized.contains(rawDigits)
            )
            org.junit.Assert.assertFalse(
                "Output for '$input' must not contain any digits. Got: '$sanitized'",
                sanitized.any { it.isDigit() }
            )
        }

        // Clean phishing sentence must remain unchanged
        val cleanPhishing = "URGENT: Your account is suspended due to unauthorized activity. Confirm your identity."
        val sanitizedClean = UniversalLinkExtractor.sanitizeSnippet(cleanPhishing)
        assertEquals(cleanPhishing, sanitizedClean)
    }

    @Test
    fun isMostlyRedacted_identifiesHeavyRedaction() {
        val mostlyRedacted = "OTP: 123456. Token: abcdef1234567890abcdef1234567890"
        val sanitized = UniversalLinkExtractor.sanitizeSnippet(mostlyRedacted)
        assertTrue(UniversalLinkExtractor.isMostlyRedacted(mostlyRedacted, sanitized))

        val barelyRedacted = "Your OTP is 483920, password reset"
        val sanitizedBarely = UniversalLinkExtractor.sanitizeSnippet(barelyRedacted)
        org.junit.Assert.assertFalse(UniversalLinkExtractor.isMostlyRedacted(barelyRedacted, sanitizedBarely))
    }
}
