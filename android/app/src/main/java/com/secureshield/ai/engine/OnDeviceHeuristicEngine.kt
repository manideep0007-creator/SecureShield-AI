package com.secureshield.ai.engine

import com.secureshield.ai.network.EngineResult
import com.secureshield.ai.network.EvidenceItem
import com.secureshield.ai.network.RiskAssessment
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse
import java.net.URI
import java.util.UUID
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min

/**
 * Autonomous On-Device Heuristic Security Engine.
 *
 * Provides instant, zero-latency, offline threat triage whenever cloud services
 * are unreachable, sleeping (e.g. Render cold start), or when network is disconnected.
 * Ensures that SecureShield AI NEVER fails or blocks the user with "Service Unavailable".
 */
object OnDeviceHeuristicEngine {

    private val SUSPICIOUS_TLDS = setOf(
        "xyz", "top", "work", "ru", "click", "buzz", "club", "info", "live",
        "loan", "vip", "cc", "cfd", "gq", "tk", "ml", "ga", "cf", "country",
        "stream", "download", "racing", "win", "bid", "date", "faith"
    )

    private val TRUSTED_ROOT_DOMAINS = setOf(
        "google.com", "google.co.in", "google.co.uk", "youtube.com", "microsoft.com",
        "live.com", "office.com", "apple.com", "icloud.com", "amazon.com", "amazon.in",
        "github.com", "gitlab.com", "wikipedia.org", "wikimedia.org", "linkedin.com",
        "twitter.com", "x.com", "facebook.com", "instagram.com", "whatsapp.com",
        "netflix.com", "spotify.com", "yahoo.com", "bing.com", "reddit.com",
        "stackoverflow.com", "dropbox.com", "adobe.com", "zoom.us", "slack.com"
    )

    private val AUTHENTIC_BRAND_DOMAINS = mapOf(
        "paypal" to setOf("paypal.com", "paypal.me"),
        "google" to setOf("google.com", "google.co.in", "google.co.uk", "youtube.com", "gmail.com"),
        "microsoft" to setOf("microsoft.com", "live.com", "office.com", "office365.com", "outlook.com"),
        "apple" to setOf("apple.com", "icloud.com"),
        "amazon" to setOf("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"),
        "netflix" to setOf("netflix.com"),
        "facebook" to setOf("facebook.com", "fb.com", "meta.com"),
        "instagram" to setOf("instagram.com"),
        "whatsapp" to setOf("whatsapp.com"),
        "chase" to setOf("chase.com"),
        "wellsfargo" to setOf("wellsfargo.com"),
        "bankofamerica" to setOf("bankofamerica.com", "bofa.com"),
        "binance" to setOf("binance.com"),
        "coinbase" to setOf("coinbase.com"),
        "dropbox" to setOf("dropbox.com"),
        "adobe" to setOf("adobe.com")
    )

    private val TARGET_BRANDS = AUTHENTIC_BRAND_DOMAINS.keys.toList()

    private val SUSPICIOUS_URL_KEYWORDS = listOf(
        "login", "verify", "account", "secure", "banking", "update", "suspend",
        "confirm", "password", "wallet", "billing", "support", "auth", "signin",
        "security-alert", "recover", "webscr", "ebayisapi", "credential", "security",
        "access", "validate", "reactivate", "unauthorized", "locked"
    )

    private val SUSPICIOUS_TEXT_URGENCY_PHRASES = listOf(
        "account has been suspended", "account has been locked", "account suspended",
        "unauthorized activity", "verify your identity immediately", "verify immediately",
        "action required", "urgent notice", "within 24 hours", "security alert",
        "permanently deactivated", "access denied", "suspicious sign-in", "locked due to",
        "confirm your identity", "immediate verification"
    )

    private val SUSPICIOUS_TEXT_HARVESTING_PHRASES = listOf(
        "verify your identity", "verify identity", "confirm your identity", "identity verification",
        "enter your password", "confirm your password", "provide your pin",
        "enter otp", "verification code", "social security", "credit card details",
        "billing information", "update payment method", "seed phrase", "private key"
    )

    private val DANGEROUS_FILE_EXTENSIONS = setOf(
        "exe", "apk", "bat", "vbs", "cmd", "scr", "ps1", "sh", "msi", "hta",
        "iso", "com", "pif", "jar", "reg", "cpl"
    )

    private val MACRO_EXTENSIONS = setOf(
        "docm", "xlsm", "pptm", "dotm", "xltm"
    )

    private val IP_REGEX = Regex("""^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$""")
    private val URL_REGEX = Regex("""https?://[^\s<>"{}|\\^`]+""", RegexOption.IGNORE_CASE)

    fun scan(input: ScanInput): UnifiedScanResponse {
        val scanId = "local-" + UUID.randomUUID().toString()

        val results = mutableListOf<EngineResult>()
        val allFlags = mutableListOf<String>()
        val allEvidence = mutableListOf<EvidenceItem>()
        val allReasons = mutableListOf<String>()
        val contributingEngines = mutableListOf<String>()
        val ignoredEngines = mutableListOf<String>()

        // 1. URL Engine Analysis
        val candidateUrl = input.url ?: extractFirstUrl(input.text)
        val urlResult = analyzeUrl(candidateUrl)
        if (urlResult != null) {
            results.add(urlResult)
            if (urlResult.status == "success") {
                contributingEngines.add(urlResult.engine_name)
                allFlags.addAll(urlResult.flags)
                allEvidence.addAll(urlResult.evidence)
                urlResult.flags.forEach { flag ->
                    urlFlagToReason(flag)?.let { allReasons.add(it) }
                }
            } else {
                ignoredEngines.add(urlResult.engine_name)
            }
        } else {
            ignoredEngines.add("url_engine")
        }

        // 2. NLP Social Engineering Engine Analysis
        val nlpResult = analyzeText(input.text)
        if (nlpResult != null) {
            results.add(nlpResult)
            if (nlpResult.status == "success") {
                contributingEngines.add(nlpResult.engine_name)
                allFlags.addAll(nlpResult.flags)
                allEvidence.addAll(nlpResult.evidence)
                nlpResult.flags.forEach { flag ->
                    nlpFlagToReason(flag)?.let { allReasons.add(it) }
                }
            } else {
                ignoredEngines.add(nlpResult.engine_name)
            }
        } else {
            ignoredEngines.add("nlp_engine")
        }

        // 3. Malware / Attachment Engine Analysis
        val malwareResult = analyzeFile(input.file_name, input.file_bytes)
        if (malwareResult != null) {
            results.add(malwareResult)
            if (malwareResult.status == "success") {
                contributingEngines.add(malwareResult.engine_name)
                allFlags.addAll(malwareResult.flags)
                allEvidence.addAll(malwareResult.evidence)
                malwareResult.flags.forEach { flag ->
                    malwareFlagToReason(flag)?.let { allReasons.add(it) }
                }
            } else {
                ignoredEngines.add(malwareResult.engine_name)
            }
        } else {
            ignoredEngines.add("malware_engine")
        }

        // 4. Sender Engine Analysis
        val senderResult = analyzeSender(input.sender_id)
        if (senderResult != null) {
            results.add(senderResult)
            if (senderResult.status == "success") {
                contributingEngines.add(senderResult.engine_name)
                allFlags.addAll(senderResult.flags)
                allEvidence.addAll(senderResult.evidence)
                senderResult.flags.forEach { flag ->
                    senderFlagToReason(flag)?.let { allReasons.add(it) }
                }
            } else {
                ignoredEngines.add(senderResult.engine_name)
            }
        } else {
            ignoredEngines.add("sender_engine")
        }

        // Calculate unified risk score
        val completedEngines = results.count { it.status == "success" }
        val skippedEngines = results.count { it.status == "skipped" }
        val totalEngines = results.size

        val maxEngineScore = results.filter { it.status == "success" }
            .maxOfOrNull { it.risk_score } ?: 0f

        // Multi-signal synthesis: compound danger if multiple engines flag threats
        val flaggedEnginesCount = results.count { it.status == "success" && it.risk_score >= 40f }
        val correlationBonus = if (flaggedEnginesCount >= 2) 15f else 0f

        val finalScore = min(100f, maxEngineScore + correlationBonus)

        val classification = when {
            finalScore >= 80f -> {
                if (malwareResult?.status == "success" && malwareResult.risk_score >= 80f) "Malware" else "Phishing"
            }
            finalScore >= 60f -> "Deceptive"
            finalScore >= 30f -> "Suspicious"
            else -> "Safe"
        }

        val recommendedAction = when (classification) {
            "Phishing", "Malware" -> "CRITICAL THREAT: Do not click any links, open attachments, or input passwords. Quarantine immediately."
            "Deceptive" -> "WARNING: High likelihood of phishing or deceptive spoofing. Avoid interacting with this message or link."
            "Suspicious" -> "CAUTION: Suspicious indicators detected. Exercise heightened vigilance before proceeding."
            else -> "Clean content: No high-risk threats detected by SecureShield On-Device Shield."
        }

        if (allReasons.isEmpty()) {
            if (classification == "Safe") {
                allReasons.add("No malicious indicators, known threat patterns, or suspicious redirects detected.")
            } else {
                allReasons.add("Suspicious structural characteristics detected.")
            }
        }

        val riskAssessment = RiskAssessment(
            risk_score = finalScore,
            classification = classification,
            confidence = 0.90f,
            contributing_engines = contributingEngines,
            ignored_engines = ignoredEngines,
            flags = allFlags.distinct(),
            evidence = allEvidence,
            reasons = allReasons.distinct(),
            recommended_action = recommendedAction
        )

        return UnifiedScanResponse(
            scan_id = scanId,
            status = "completed",
            results = results,
            total_engines = max(totalEngines, 4),
            completed_engines = completedEngines,
            skipped_engines = skippedEngines,
            risk_assessment = riskAssessment,
            risk_score = finalScore,
            classification = classification,
            warnings = listOf("Limited offline check - cloud engines were not used")
        )
    }

    private fun analyzeUrl(url: String?): EngineResult? {
        if (url.isNullOrBlank()) {
            return EngineResult(
                engine_name = "url_engine",
                risk_score = 0f,
                confidence = 0f,
                flags = emptyList(),
                evidence = emptyList(),
                status = "skipped",
                error_message = "No URL provided",
                metadata = emptyMap()
            )
        }

        val cleanUrl = url.trim()
        val flags = mutableListOf<String>()
        val evidence = mutableListOf<EvidenceItem>()
        var score = 0f

        val uri = try {
            URI(cleanUrl)
        } catch (_: Exception) {
            null
        }

        val host = uri?.host ?: extractHostFallback(cleanUrl)
        val scheme = uri?.scheme ?: if (cleanUrl.startsWith("https://", true)) "https" else "http"
        val rootDomain = if (host != null) extractRootDomain(host) else ""
        val isTrusted = isTrustedDomain(host)

        if (isTrusted) {
            flags.add("whitelisted_trusted_domain")
            evidence.add(EvidenceItem("WHITELISTED_DOMAIN", rootDomain, "Root domain is verified on global trusted authority list."))
        }

        // 1. IP-based host check (high evasion risk regardless of whitelist)
        val hasIp = Regex("""://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}""").containsMatchIn(cleanUrl) ||
                (host != null && IP_REGEX.matches(host))
        if (hasIp) {
            flags.add("ip_based_host")
            evidence.add(EvidenceItem("HOST_TYPE", "IPv4", "Host utilizes an IP address instead of a standard domain name."))
            score += 35f
        }

        // 2. User-info '@' obfuscation
        if (cleanUrl.contains("@")) {
            flags.add("at_symbol_present")
            evidence.add(EvidenceItem("URL_OBFUSCATION", "@ Symbol", "URL contains '@' userinfo symbol used to mask true destination."))
            score += 30f
        }

        // 3. Unencrypted HTTP
        if (scheme.equals("http", ignoreCase = true)) {
            flags.add("http_without_https")
            evidence.add(EvidenceItem("PROTOCOL", "Insecure HTTP", "Protocol defaults to unencrypted HTTP."))
            score += 10f
        }

        val isHostAnIp = host != null && IP_REGEX.matches(host)

        // Check for Homograph / IDN / Punycode attacks (applies to all non-IP hosts)
        if (host != null && !isHostAnIp) {
            val hasPunycode = host.startsWith("xn--", ignoreCase = true) || host.contains(".xn--", ignoreCase = true)
            val hasNonAscii = host.any { it.code > 127 }
            if (hasPunycode || hasNonAscii) {
                flags.add("homograph_punycode_attack")
                evidence.add(EvidenceItem("HOMOGRAPH_ATTACK", host, "Domain uses Punycode or non-ASCII characters to spoof visual appearance."))
                score += 65f
            }
        }

        // If domain is NOT trusted, perform deeper phishing / impersonation heuristics
        if (!isTrusted && host != null) {
            val lowerHost = host.lowercase()
            val lowerPath = (uri?.path ?: "").lowercase()

            // 4. Brand Impersonation / Subdomain Nesting Spoofing
            if (!isHostAnIp) {
                val matchedBrand = AUTHENTIC_BRAND_DOMAINS.keys.firstOrNull { brand ->
                    val authDomains = AUTHENTIC_BRAND_DOMAINS[brand] ?: emptySet()
                    (lowerHost.contains(brand) || lowerPath.contains(brand)) && !authDomains.contains(rootDomain)
                }
                if (matchedBrand != null) {
                    flags.add("brand_impersonation_spoofing")
                    evidence.add(EvidenceItem("BRAND_SPOOFING", matchedBrand, "Brand '$matchedBrand' detected in untrusted destination '$rootDomain'."))
                    score += 55f
                }

                // 5. Suspicious TLD check
                val tld = host.substringAfterLast('.', "").lowercase()
                val hasSuspiciousTld = tld.isNotBlank() && SUSPICIOUS_TLDS.contains(tld)
                if (hasSuspiciousTld) {
                    flags.add("suspicious_tld")
                    evidence.add(EvidenceItem("TOP_LEVEL_DOMAIN", ".$tld", "Uses TLD associated with spam and malware campaigns: .$tld"))
                    score += 25f
                }
            }

            // 6. Security Keywords check in host and path
            val lowerUrl = cleanUrl.lowercase()
            val matchedKeywords = SUSPICIOUS_URL_KEYWORDS.filter { keyword ->
                lowerUrl.contains(keyword)
            }
            if (matchedKeywords.isNotEmpty()) {
                flags.add("suspicious_keywords")
                evidence.add(EvidenceItem("SUSPICIOUS_KEYWORDS", matchedKeywords, "Detected credential and security keywords in untrusted URL: ${matchedKeywords.joinToString(", ")}"))
                score += min(35f, matchedKeywords.size * 10f)
            }

            // 7. Subdomain depth anomaly & Entropy (domain names only)
            if (!isHostAnIp) {
                val dotCount = host.count { it == '.' }
                if (dotCount >= 3) {
                    flags.add("subdomain_depth_anomaly")
                    evidence.add(EvidenceItem("SUBDOMAIN_DEPTH", dotCount, "Hostname exhibits excessive subdomain nesting: $dotCount levels."))
                    score += 20f
                }

                // 8. Shannon character entropy & digit ratio
                val entropy = calculateShannonEntropy(host)
                if (entropy > 4.0) {
                    flags.add("high_shannon_entropy")
                    evidence.add(EvidenceItem("SHANNON_ENTROPY", "%.2f".format(entropy), "Hostname exhibits high randomness entropy: %.2f".format(entropy)))
                    score += 15f
                }

                val digits = host.count { it.isDigit() }
                val digitRatio = digits.toFloat() / max(1, host.length)
                if (digitRatio > 0.25f) {
                    flags.add("high_digit_ratio")
                    evidence.add(EvidenceItem("DIGIT_RATIO", "%.0f%%".format(digitRatio * 100), "Unusually high digit density in domain: %.0f%%".format(digitRatio * 100)))
                    score += 15f
                }
            }
        }

        // On trusted domains without evasion, score is strictly capped at clean/safe level
        val finalUrlScore = if (isTrusted && !hasIp && !cleanUrl.contains("@")) {
            min(10f, score)
        } else {
            min(100f, score)
        }

        return EngineResult(
            engine_name = "url_engine",
            risk_score = finalUrlScore,
            confidence = 0.90f,
            flags = flags,
            evidence = evidence,
            status = "success",
            error_message = null,
            metadata = mapOf("heuristic_source" to "on_device_url_analyzer")
        )
    }

    private fun analyzeText(text: String?): EngineResult? {
        if (text.isNullOrBlank()) {
            return EngineResult(
                engine_name = "nlp_engine",
                risk_score = 0f,
                confidence = 0f,
                flags = emptyList(),
                evidence = emptyList(),
                status = "skipped",
                error_message = "No text provided",
                metadata = emptyMap()
            )
        }

        val flags = mutableListOf<String>()
        val evidence = mutableListOf<EvidenceItem>()
        var score = 0f
        val lowerText = text.lowercase()

        // 1. Urgency & Fear Cues
        val matchedUrgency = SUSPICIOUS_TEXT_URGENCY_PHRASES.filter { lowerText.contains(it) }
        if (matchedUrgency.isNotEmpty()) {
            flags.add("urgency_and_fear_cues")
            evidence.add(EvidenceItem("URGENCY_TRIGGERS", matchedUrgency, "Urgent psychological intimidation phrases: ${matchedUrgency.joinToString(", ")}"))
            score += min(40f, 25f + matchedUrgency.size * 10f)
        }

        // 2. Credential Harvesting Intent
        val matchedHarvesting = SUSPICIOUS_TEXT_HARVESTING_PHRASES.filter { lowerText.contains(it) }
        if (matchedHarvesting.isNotEmpty()) {
            flags.add("credential_harvesting_intent")
            evidence.add(EvidenceItem("HARVESTING_TRIGGERS", matchedHarvesting, "Demands sensitive credentials or verification: ${matchedHarvesting.joinToString(", ")}"))
            score += min(40f, 30f + matchedHarvesting.size * 10f)
        }

        // 3. Embedded Suspicious Link inside text
        val embeddedUrl = extractFirstUrl(text)
        if (embeddedUrl != null) {
            val urlLower = embeddedUrl.lowercase()
            if (urlLower.contains("@") || SUSPICIOUS_TLDS.any { urlLower.contains(".$it") } || IP_REGEX.containsMatchIn(urlLower)) {
                flags.add("embedded_suspicious_url")
                evidence.add(EvidenceItem("EMBEDDED_LINK", embeddedUrl, "Message contains deceptive or high-risk embedded link."))
                score += 25f
            }
        }

        val finalNlpScore = min(100f, score)

        return EngineResult(
            engine_name = "nlp_engine",
            risk_score = finalNlpScore,
            confidence = 0.88f,
            flags = flags,
            evidence = evidence,
            status = "success",
            error_message = null,
            metadata = mapOf("heuristic_source" to "on_device_nlp_analyzer")
        )
    }

    private fun analyzeFile(fileName: String?, fileBytes: String?): EngineResult? {
        if (fileName.isNullOrBlank() && fileBytes.isNullOrBlank()) {
            return EngineResult(
                engine_name = "malware_engine",
                risk_score = 0f,
                confidence = 0f,
                flags = emptyList(),
                evidence = emptyList(),
                status = "skipped",
                error_message = "No file data provided",
                metadata = emptyMap()
            )
        }

        val flags = mutableListOf<String>()
        val evidence = mutableListOf<EvidenceItem>()
        var score = 0f

        val name = fileName.orEmpty().lowercase()
        val ext = name.substringAfterLast('.', "")

        // 1. Dangerous executable / script extension
        if (DANGEROUS_FILE_EXTENSIONS.contains(ext)) {
            flags.add("dangerous_executable_extension")
            evidence.add(EvidenceItem("FILE_EXTENSION", ext.uppercase(), "High-risk executable or script format: .$ext"))
            score += 75f
        }

        // 2. Double extension masquerade (e.g. document.pdf.exe)
        val parts = name.split('.')
        if (parts.size >= 3) {
            val secondaryExt = parts[parts.size - 2]
            if (setOf("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt").contains(secondaryExt) &&
                DANGEROUS_FILE_EXTENSIONS.contains(ext)) {
                flags.add("double_extension_anomaly")
                evidence.add(EvidenceItem("DECEPTIVE_EXTENSION", "$secondaryExt.$ext", "Double extension masquerade attempting to mimic a document: $secondaryExt.$ext"))
                score += 85f
            }
        }

        // 3. Macro-enabled document
        if (MACRO_EXTENSIONS.contains(ext)) {
            flags.add("macro_enabled_document")
            evidence.add(EvidenceItem("FILE_EXTENSION", ext.uppercase(), "Macro-enabled document format frequently leveraged for droppers: .$ext"))
            score += 45f
        }

        val finalScore = min(100f, score)

        return EngineResult(
            engine_name = "malware_engine",
            risk_score = finalScore,
            confidence = 0.95f,
            flags = flags,
            evidence = evidence,
            status = "success",
            error_message = null,
            metadata = mapOf("heuristic_source" to "on_device_malware_analyzer")
        )
    }

    private fun analyzeSender(senderId: String?): EngineResult? {
        if (senderId.isNullOrBlank()) {
            return EngineResult(
                engine_name = "sender_engine",
                risk_score = 0f,
                confidence = 0f,
                flags = emptyList(),
                evidence = emptyList(),
                status = "skipped",
                error_message = "No sender provided",
                metadata = emptyMap()
            )
        }

        val flags = mutableListOf<String>()
        val evidence = mutableListOf<EvidenceItem>()
        var score = 0f
        val cleanSender = senderId.trim().lowercase()

        val senderDomain = cleanSender.substringAfterLast('@', "")
        if (senderDomain.isNotEmpty()) {
            val tld = senderDomain.substringAfterLast('.', "")
            if (SUSPICIOUS_TLDS.contains(tld)) {
                flags.add("suspicious_sender_tld")
                evidence.add(EvidenceItem("SENDER_DOMAIN", senderDomain, "Sender uses high-abuse top-level domain: .$tld"))
                score += 30f
            }

            if (SUSPICIOUS_URL_KEYWORDS.any { senderDomain.contains(it) } &&
                (senderDomain.contains("update") || senderDomain.contains("alert") || senderDomain.contains("verify"))) {
                flags.add("sender_impersonation_mismatch")
                evidence.add(EvidenceItem("SENDER_REPUTATION", senderDomain, "Sender domain mimics official alert/security infrastructure."))
                score += 35f
            }
        }

        return EngineResult(
            engine_name = "sender_engine",
            risk_score = min(100f, score),
            confidence = 0.85f,
            flags = flags,
            evidence = evidence,
            status = "success",
            error_message = null,
            metadata = mapOf("heuristic_source" to "on_device_sender_analyzer")
        )
    }

    fun extractRootDomain(host: String): String {
        val cleanHost = host.lowercase().trim().removePrefix("www.")
        val parts = cleanHost.split(".")
        if (parts.size <= 2) return cleanHost
        val secondLast = parts[parts.size - 2]
        val last = parts[parts.size - 1]
        val commonTwoPartSuffixes = setOf("co.uk", "co.in", "com.au", "co.jp", "com.br", "gov.in", "edu.in", "org.uk")
        val possibleSuffix = "$secondLast.$last"
        return if (commonTwoPartSuffixes.contains(possibleSuffix) && parts.size >= 3) {
            "${parts[parts.size - 3]}.$possibleSuffix"
        } else {
            "${parts[parts.size - 2]}.$last"
        }
    }

    fun isTrustedDomain(host: String?): Boolean {
        if (host.isNullOrBlank()) return false
        val root = extractRootDomain(host)
        return TRUSTED_ROOT_DOMAINS.contains(root) ||
                root.endsWith(".gov") || root.endsWith(".edu") || root.endsWith(".mil") ||
                TRUSTED_ROOT_DOMAINS.any { root.endsWith(".$it") }
    }

    private fun extractFirstUrl(text: String?): String? {
        if (text == null) return null
        return URL_REGEX.find(text)?.value
    }

    private fun extractHostFallback(url: String): String? {
        val withoutProto = url.substringAfter("://")
        val auth = withoutProto.substringBefore('/').substringBefore('?')
        return auth.substringAfterLast('@').substringBefore(':').takeIf { it.isNotBlank() }
    }

    private fun calculateShannonEntropy(str: String): Double {
        if (str.isEmpty()) return 0.0
        val freq = mutableMapOf<Char, Int>()
        for (c in str) {
            freq[c] = (freq[c] ?: 0) + 1
        }
        var entropy = 0.0
        val len = str.length.toDouble()
        for (count in freq.values) {
            val p = count / len
            entropy -= p * (ln(p) / ln(2.0))
        }
        return entropy
    }

    private fun urlFlagToReason(flag: String): String? = when (flag) {
        "ip_based_host" -> "The URL uses a raw IP address instead of a recognized domain name, a common evasion tactic."
        "at_symbol_present" -> "The URL contains an '@' symbol used to obscure the true browser destination."
        "suspicious_tld" -> "The URL uses a Top-Level Domain (TLD) heavily associated with deceptive spam or malware."
        "suspicious_keywords" -> "High-risk credential harvesting keywords (e.g., login, verify, account) were detected in the URL path."
        "subdomain_depth_anomaly" -> "Excessive subdomain nesting detected, often used to bypass reputation filters."
        "http_without_https" -> "The URL transmits unencrypted data via HTTP instead of secure HTTPS."
        "high_shannon_entropy" -> "The hostname appears algorithmically generated with high randomness entropy."
        "high_digit_ratio" -> "The domain name comprises an abnormally high density of numerical digits."
        "brand_impersonation_spoofing" -> "Deceptive brand impersonation detected targeting established services on an untrusted root domain."
        "homograph_punycode_attack" -> "Visual homoglyph / Punycode spoofing detected to impersonate a legitimate domain name."
        "whitelisted_trusted_domain" -> "Verified authentic root domain on trusted global authority list."
        else -> null
    }

    private fun nlpFlagToReason(flag: String): String? = when (flag) {
        "urgency_and_fear_cues" -> "Aggressive urgency or psychological fear tactics detected ('account suspended', 'unauthorized activity')."
        "credential_harvesting_intent" -> "Explicit demands to input passwords, PINs, or verify identity detected."
        "embedded_suspicious_url" -> "Message contains an unverified, deceptive link directing outside legitimate infrastructure."
        else -> null
    }

    private fun malwareFlagToReason(flag: String): String? = when (flag) {
        "dangerous_executable_extension" -> "File payload uses an executable or script format known to deliver malicious code."
        "double_extension_anomaly" -> "Deceptive double extension detected attempting to disguise an executable as a document."
        "macro_enabled_document" -> "Document contains macro execution capabilities frequently leveraged in targeted attacks."
        else -> null
    }

    private fun senderFlagToReason(flag: String): String? = when (flag) {
        "suspicious_sender_tld" -> "Sender email domain originates from a high-risk or disposable top-level domain."
        "sender_impersonation_mismatch" -> "Sender infrastructure mimics bank, security, or corporate verification alerts."
        else -> null
    }
}
