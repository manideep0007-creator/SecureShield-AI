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
}
