# URL ENGINE AUDIT

**Date**: 2026-09-28
**Scope**: Read-only audit of `backend/app/engines/url_engine.py`

---

## 1. URL / Host Features Currently Implemented

The engine (`lexical_heuristics`) currently extracts **five (5)** lexical features from the URL string:

1. **IP-Based Host**: Detects if the hostname is an IPv4 address (e.g., `http://192.168.1.1`).
2. **Credential Injection (`@` symbol)**: Detects the presence of an `@` symbol in the URL which is commonly used to spoof trust (e.g., `http://google.com@phishing.xyz`).
3. **High Hyphen Count**: Counts the number of hyphens in the hostname. Triggers if the count is `≥ 3`.
4. **Suspicious TLDs**: Checks if the hostname ends with one of the hardcoded suspicious Top-Level Domains (`.xyz`, `.top`, `.cc`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`).
5. **URL Shorteners**: Matches the hostname against known shortening services (`bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `is.gd`, `cli.gs`).

---

## 2. Reputation Checks Currently Used

The engine integrates with **one (1)** external reputation provider:

*   **Google Safe Browsing API v4** (`check_google_safe_browsing`)
    *   **Method**: `POST` to `/v4/threatMatches:find`
    *   **Threat Types Checked**: `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, `POTENTIALLY_HARMFUL_APPLICATION`
    *   **Timeout**: 5.0 seconds
    *   **Failure Handling**: Gracefully returns score `0.0` with an error flag if the API key is missing or a network timeout occurs.

---

## 3. Risk-Score Calculation

The final risk score is composed by balancing the local lexical heuristics against the Google Safe Browsing (GSB) response.

**Lexical Scoring (Additive, capped at 1.0):**
*   IP-based host: `+0.3`
*   `@` symbol: `+0.2`
*   High hyphen count: `+0.2`
*   Suspicious TLD: `+0.4`
*   URL Shortener: `+0.0` (Informational flag only)

**Fusion Math (Converted to a 0–100 scale):**
*   **If GSB reports a threat (`gsb_score > 0`)**:
    *   `Risk Score = (Lexical_Score * 0.4 + 1.0 * 0.6) * 100`
*   **If GSB is clean or unreachable (`gsb_score == 0`)**:
    *   `Risk Score = (Lexical_Score * 0.7 + 0.0 * 0.3) * 100`

---

## 4. Current Flags and Evidence

**Output Flags Generated**:
*   `ip_based_host`
*   `at_symbol_present`
*   `high_hyphen_count(N)` (Dynamic based on count)
*   `suspicious_tld`
*   `url_shortener`
*   GSB dynamic flags: `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, `POTENTIALLY_HARMFUL_APPLICATION`

**Evidence Object**:
*   Currently, the `EngineResult.evidence` list is **Empty (`[]`)** in the V2 codebase. Raw calculation metrics (`lexical_score`, `gsb_score`, JSON matches) are stored passively in the `metadata` dictionary rather than structurally modeled as `EvidenceItem` types.
*   **EngineStatus**: Supports `SUCCESS`, `PARTIAL` (if GSB HTTP fails), or `SKIPPED` (if no URL is provided).

---

## 5. Missing Features (Compared to 18-Feature Architecture)

To expand to a full 18-feature Lexical/Host ML detection structure, the following standard features are presently **missing**:

**Lexical / Length Features:**
1. Overall URL Length
2. Hostname Length
3. Path Length
4. Subdomain presence / depth count

**Character / Syntax Features:**
5. Count of Dots (`.`)
6. Presence of double slashes (`//`) past the protocol
7. Shannon Entropy / Randomness index of character distributions
8. Count of special characters (`?`, `=`, `_`, `~`, `%`)

**Domain / Protocol Features:**
9. HTTPS / SSL protocol validation check
10. Typosquatting / Levenshtein distance against top-1000 Alexa bank/brand domains
11. Port numbers in URL (e.g., `:8080`)

**Reputation / DNS Features:**
12. Domain Age (WHOIS lookup)
13. Certificate Age / Validity period
14. ASN / IP Block Reputation
15. Page Rank / Alexa Top 1 Million correlation
16. Existence of DNS MX/TXT records

---

## Conclusion
The current engine applies a functional baseline of 5 lexical rules and 1 reliable external API lookup. Extending it to the 18-feature architecture will drastically improve zero-day phishing detection capability without over-relying entirely on the GSB blocklist.