# DOMAIN_AGE_DAYS - Feature Design Specification

**Date**: 2026-09-28  
**Feature**: Feature #18 from URL_FEATURE_SPEC.md  
**Status**: Design Phase (Implementation pending)  

---

## 1. Root Domain Extraction
To accurately determine domain age, the exact root domain must be parsed ignoring complex subdomains and multi-part Top-Level Domains (like `.co.uk` or `.com.au`). 
*   **Design**: The future implementation will utilize a robust parsing library (such as `tldextract`) which maintains a verified public suffix list. 
*   **Process**: The raw URL evaluates through the parser to isolate specifically the target `domain` + `suffix`, discarding the `subdomain` parameter completely (e.g., `https://secure.a.login.bank.co.uk` strictly resolves to `bank.co.uk`).

## 2. Obtaining Domain Registration Age
The domain's creation date (often referred to as `creation_date` or `registered_on` in WHOIS databases) is required.
*   **Design**: The system will extract the `creation_date` timestamp from the WHOIS payload. If multiple dates are returned (historically common with certain registrars reporting multiple updates), the earliest non-null datetime object is selected.
*   **Calculation**: A simple delta is calculated: `Elapsed Days = (Current UTC Date - WHOIS Creation Date).days`. 

## 3. External Lookup / Tooling
*   **Library Choice**: The feature will leverage a Python-native WHOIS wrapper such as `python-whois` or `asyncwhois` to execute the query. 
*   *Note*: As these modules generally wrap native OS WHOIS protocols, this avoids adding paid API dependencies to the immediate stack while retaining strong domain coverage.

## 4. Timeout and Error Handling
WHOIS lookups involve external TCP queries over Port 43, which can be unacceptably slow or blocked during an active engine pipeline analysis.
*   **Design**: The lookup block will be strictly wrapped inside an asynchronous timeout (e.g., `asyncio.wait_for(...)` with a maximum limit of `2.0` seconds).
*   **Failure Catching**: All related network exceptions, socket timeouts, and parsing exceptions will be caught silently using a `try/except Exception` block, isolating the failure entirely to this single heuristic without failing the overarching URL engine.

## 5. Unavailable Registration Date Handling
Various TLD registrars refuse to provide creation dates (either due to unique schemas, localized privacy laws, or GDPR protections).
*   **Design**: If the successful WHOIS text blob resolves but yields `creation_date = None`, the feature will immediately abort any further anomaly extraction. No heuristic guesses will be made regarding the domain's age.

## 6. Returned Value and Structured Evidence
*   **Condition**: The feature will trigger if the domain age falls below a critical threshold designed to catch "burn-and-churn" phishing domains (e.g., `< 14 days`).
*   **Flag**: `newly_registered_domain`
*   **EvidenceItem**:
    *   **Key**: `DOMAIN_AGE_DAYS`
    *   **Value**: `<Integer>` (The calculated delta in days)
    *   **Description**: `"Root domain is exceedingly new. Registered [N] days ago."`

## 7. Avoiding Risk Inflation on Unavailable Data
Phishing pipelines must abide by the rule of "fail-safe" intelligence: an inability to verify a threat does not equate to the presence of a threat.
*   **Design**: If the WHOIS lookup times out, errors out, or returns a missing `creation_date`, the `DOMAIN_AGE_DAYS` block gracefully exits.
*   **Risk Protection**: Because the URL engine utilizes an additive flagging behavior, bypassing the threshold check means no `newly_registered_domain` flag is appended. Consequently, the absence of data inherently forces a `0` modification to the final risk score mapping.