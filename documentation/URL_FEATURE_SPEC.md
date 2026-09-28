# Secure Shield AI - 18-Feature URL Detection Specification

**Date**: 2026-09-28
**Scope**: Lexical and Host Feature Architecture Specification  
**Status**: Specification Phase (Implementation pending)

---

## Overview
This specification outlines the complete 18-feature detection architecture for the SecureShield AI URL Engine. It integrates the 5 existing preliminary features with 13 advanced lexical and host-based metrics, providing a comprehensive data matrix for sophisticated threat profiling prior to external reputation checks (like Google Safe Browsing).

---

## 1. Existing Legacy Features (5)

### 01. IP-Based Host
1. **Name**: `IP_BASED_HOST`
2. **Measures**: Whether the URL utilizes a raw IPv4 or IPv6 address instead of a resolved domain name to bypass domain analysis.
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Lexical
5. **Evidence Produced**: "Hostname resolves directly to an IP string: [IP_ADDRESS]."

### 02. Credential Injection (At-Symbol)
1. **Name**: `AT_SYMBOL_PRESENT`
2. **Measures**: The presence of an `@` symbol in the URL preceding the hostname, frequently used to obfuscate the true destination site.
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Lexical
5. **Evidence Produced**: "Credential injection character '@' detected before the hostname."

### 03. High Hyphen Count
1. **Name**: `HIGH_HYPHEN_COUNT`
2. **Measures**: The total number of hyphens (`-`) concentrated within the hostname, commonly scaling in typosquatted domains.
3. **Output Type/Range**: Integer (Count, e.g., `0 to ∞`)
4. **Type**: Lexical
5. **Evidence Produced**: "Detected [N] hyphens in the hostname (Threshold: >= 3)."

### 04. Suspicious Top-Level Domain (TLD)
1. **Name**: `SUSPICIOUS_TLD`
2. **Measures**: Matching of the hostname's trailing suffix against a hardcoded list of low-trust or notoriously abused Top-Level Domains (e.g., `.xyz`, `.top`).
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Lexical
5. **Evidence Produced**: "Hostname utilizes known high-risk TLD: [TLD]."

### 05. URL Shortener Used
1. **Name**: `URL_SHORTENER`
2. **Measures**: Identifies if the domain belongs to a list of known URL shortening services (e.g., `bit.ly`, `tinyurl.com`), which hides the final payload destination.
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Host-Based / Lexical (Database match)
5. **Evidence Produced**: "Domain matches verified URL shortener service: [SERVICE_NAME]."

---

## 2. Advanced Architectural Additions (13)

### 06. URL Length Deviation
1. **Name**: `URL_LENGTH`
2. **Measures**: The absolute character length of the complete URL. Phishing URLs frequently exceed 75-100 characters to push deceptive parameters off-screen.
3. **Output Type/Range**: Integer (`0 to ∞`)
4. **Type**: Lexical
5. **Evidence Produced**: "Total URL length is [N] characters, exceeding normal limits."

### 07. Path Length Deviation
1. **Name**: `PATH_LENGTH`
2. **Measures**: The absolute character length of the URL path (excluding domain and query strings). Deep directory structures often mask payload drops.
3. **Output Type/Range**: Integer (`0 to ∞`)
4. **Type**: Lexical
5. **Evidence Produced**: "URL path depth is [N] characters."

### 08. Subdomain Depth Count
1. **Name**: `SUBDOMAIN_DEPTH`
2. **Measures**: The count of hierarchical subdomains preceding the root domain (e.g., `secure.login.bank.com.xyz` = 3 subdomains).
3. **Output Type/Range**: Integer (`0 to ∞`)
4. **Type**: Lexical
5. **Evidence Produced**: "Hostname exhibits excessive subdomain nesting: [N] layers."

### 09. Suspicious Keyword Matches
1. **Name**: `SUSPICIOUS_KEYWORDS`
2. **Measures**: Scans the path and subdomains for sensitive trigger words often weaponized in Social Engineering (e.g., `login`, `verify`, `secure`, `account`, `banking`).
3. **Output Type/Range**: List of Strings (Matched words)
4. **Type**: Lexical
5. **Evidence Produced**: "Security-critical keywords detected in URL path/subdomain: [LIST_OF_WORDS]."

### 10. Open Redirect Signature (Double Slash)
1. **Name**: `DOUBLE_SLASH_REDIRECT`
2. **Measures**: The presence of `//` located after the initial protocol `http(s)://`. This strongly indicates an open-redirect exploitation path bridging from a safe domain.
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Lexical
5. **Evidence Produced**: "Double-slash redirect artifact detected at index [N]."

### 11. Unencrypted Protocol Check
1. **Name**: `HTTP_WITHOUT_HTTPS`
2. **Measures**: Evaluates if the URL strictly employs the unencrypted `http://` transport layer rather than `https://`.
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Lexical
5. **Evidence Produced**: "Protocol defaults to unencrypted HTTP."

### 12. Non-Standard Port Mapping
1. **Name**: `NON_STANDARD_PORT`
2. **Measures**: Detects if a specific networking port is hardcoded into the URL (e.g., `:8080`, `:8443`) deviating from the implicit 80/443 mapping.
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Lexical
5. **Evidence Produced**: "URL points to non-standard HTTP port: [PORT]."

### 13. HTTPS Spoofing (Domain Context)
1. **Name**: `HTTPS_IN_HOSTNAME`
2. **Measures**: Identifies the text sequence "http" or "https" explicitly embedded within the domain name itself (e.g., `https-secure-auth.xyz`) to deceive users.
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Lexical
5. **Evidence Produced**: "Deceptive 'http/https' string found within the hostname payload."

### 14. Shannon Entropy (Randomness)
1. **Name**: `SHANNON_ENTROPY`
2. **Measures**: Algorithmically calculates the information entropy of the hostname. Unusually high variance strongly correlates with DGA (Domain Generation Algorithms) used by botnets.
3. **Output Type/Range**: Float (`0.0 to 8.0+`)
4. **Type**: Lexical (Mathematical)
5. **Evidence Produced**: "Hostname strings exhibits high character entropy: [ENTROPY_SCORE]."

### 15. Digit-to-Letter Ratio
1. **Name**: `DIGIT_TO_LETTER_RATIO`
2. **Measures**: The percentage ratio of numerical digits compared to alphabetic letters within the domain block. Standard URLs have drastically low digit ratios.
3. **Output Type/Range**: Float (`0.0 to 1.0+`)
4. **Type**: Lexical
5. **Evidence Produced**: "Hostname comprises an unusual high density of numerical digits: [RATIO]%."

### 16. Special Character Overload
1. **Name**: `SPECIAL_CHAR_COUNT`
2. **Measures**: The aggregated total count of URL functional characters (`?`, `=`, `&`, `%`, `_`). Massive counts generally point to highly obfuscated parameters or tracking shells.
3. **Output Type/Range**: Integer (Count, e.g., `0 to ∞`)
4. **Type**: Lexical
5. **Evidence Produced**: "Detected a massive load of query-modifier characters: [N] occurrences."

### 17. Base64 Obfuscation
1. **Name**: `BASE64_OBFUSCATION`
2. **Measures**: Heuristic evaluation running against all Query Parameters to detect continuous padding and character sets matching Base64-encoded strings harboring secondary payloads.
3. **Output Type/Range**: Boolean (`True`/`False`)
4. **Type**: Lexical
5. **Evidence Produced**: "Detected Base64-encoded execution string inside the URL query payload."

### 18. Domain Age (WHOIS Validation)
1. **Name**: `DOMAIN_AGE_DAYS`
2. **Measures**: The absolute age measuring from when the root domain was registered. Threat actors routinely burn domains within 14 days of registration.
3. **Output Type/Range**: Integer (Days, e.g., `0 to ∞`)
4. **Type**: Host-Based (DNS/WHOIS lookup)
5. **Evidence Produced**: "Root domain is exceedingly new. Registered [N] days ago."