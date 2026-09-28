# V1 BASELINE — Engine Configuration

**Snapshot Date**: 2026-09-28

---

## Fusion Engine — Confidence Weights

Each detection engine has a fixed confidence weight used in the weighted-average calculation:

| Engine | Type Key | Confidence Weight | Rationale |
|---|---|---|---|
| URL Engine | `url` | **0.8** | High — combines structural heuristics with GSB API |
| Malware Engine | `file` | **0.9** | Highest — VirusTotal is an authoritative database |
| NLP Engine | `nlp` | **0.65** | Medium — regex patterns have limited precision |
| Sender Engine | `sender` | **0.5** | Lowest — behavioral heuristics are supplementary |

**Formula**: `final_score = round((Σ engine_score × confidence) / (Σ confidence) × 100)`

---

## Category Thresholds (0–100 Scale)

| Category | Score Range | Description |
|---|---|---|
| **Safe** | 0 – 19 | No threats detected |
| **Suspicious** | 20 – 44 | Minor heuristic triggers |
| **Deceptive** | 45 – 69 | Multiple red flags present |
| **Phishing** | 70 – 89 | Strong phishing/scam indicators |
| **Malware** | 90 – 100 | Only when score ≥90 AND malware-specific flags present |

**Malware override**: Score ≥90 is classified as `Malware` only if flags include `vt_malicious`, `vt_suspicious`, `extension_mismatch`, or `MALWARE`. Otherwise it falls to `Phishing`.

---

## URL Engine — Score Contribution

### Lexical Heuristic Scores (additive, capped at 1.0)

| Check | Score Contribution | Flag |
|---|---|---|
| IP-based host | +0.3 | `ip_based_host` |
| `@` symbol present | +0.2 | `at_symbol_present` |
| Hostname hyphens ≥ 3 | +0.2 | `high_hyphen_count(n)` |
| Suspicious TLD | +0.4 | `suspicious_tld` |
| URL shortener | +0.0 (flag only) | `url_shortener` |

### Suspicious TLDs
`.xyz`, `.top`, `.cc`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`

### URL Shorteners Tracked
`bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `is.gd`, `cli.gs`

### Lexical + GSB Combination

| Condition | Formula |
|---|---|
| GSB confirms threat (gsb > 0) | `lexical × 0.4 + gsb × 0.6` |
| GSB clean/unknown (gsb = 0) | `lexical × 0.7 + gsb × 0.3` |

---

## NLP Engine — Category Patterns

| Category | Flag | Score per Hit | Regex Patterns |
|---|---|---|---|
| Urgency | `nlp_urgency` | +0.35 | `act now`, `urgent`, `immediately`, `asap`, `time is running out`, `24 hours` |
| Credential Request | `nlp_credential_request` | +0.35 | `password`, `login`, `verify your account`, `ssn`, `social security`, `one time code`, `otp` |
| Account Suspension | `nlp_account_suspension` | +0.35 | `suspend`, `locked`, `blocked`, `unauthorized access`, `closing your account` |
| Prize/Lottery | `nlp_prize_lottery` | +0.35 | `giveaway`, `lottery`, `winner`, `claim your prize`, `free gift`, `selected to win` |
| Unusual Payment | `nlp_unusual_payment` | +0.35 | `gift card`, `wire transfer`, `western union`, `bitcoin`, `crypto`, `usdt`, `apple pay`, `cashapp` |

**Overall NLP score**: Additive per category hit (0.35 each), capped at 1.0. Returns empty dict if no flags triggered.

---

## Sender Engine — Behavioral Scores

| Condition | Score | Flag |
|---|---|---|
| First-time sender (never seen before) | 0.4 | `first_time_sender` |
| Known sender sends link for the first time | +0.6 | `out_of_character_link` |
| Known sender sends file for the first time | +0.6 | `out_of_character_file` |

**Overall sender score**: Capped at 1.0.

---

## Malware Engine — VirusTotal Scoring

| Condition | Score | Flags |
|---|---|---|
| VT reports malicious detections | `(malicious + suspicious) / total` | `vt_malicious`, `vt_suspicious` |
| File not found in VT (HTTP 404) | 0.0 | `vt_not_found` |
| API key missing / error | 0.0 | — (error in response) |

**Extension mismatch boost**: When preprocessing detects magic-byte mismatch, adds `extension_mismatch` flag and +0.3 to file score (capped at 1.0).

---

## Flag → Reason Mapping (18 flags)

| Flag | Plain-Language Reason |
|---|---|
| `ip_based_host` | The link hides its true destination using an IP address instead of a standard domain name. |
| `at_symbol_present` | The link uses an '@' character, a common trick to inject fake login credentials. |
| `high_hyphen_count` | The web address uses an unusually high number of hyphens. |
| `suspicious_tld` | The web address uses a suspicious top-level domain often associated with scams. |
| `url_shortener` | The link uses a URL shortener to mask its true destination. |
| `MALWARE` | Google Safe Browsing identified this URL as distributing malware. |
| `SOCIAL_ENGINEERING` | Google Safe Browsing identified this URL as a phishing or deceptive site. |
| `UNWANTED_SOFTWARE` | Google Safe Browsing identified this URL as distributing unwanted software. |
| `extension_mismatch` | The actual file type does not match its file extension. |
| `vt_malicious` | VirusTotal databases detected this file as malicious. |
| `vt_suspicious` | VirusTotal databases flagged this file as suspicious. |
| `vt_not_found` | The file is completely unknown to threat intelligence databases. |
| `nlp_urgency` | The message contains urgent language trying to force immediate action. |
| `nlp_credential_request` | The message asks for passwords, OTPs, or login verification. |
| `nlp_account_suspension` | The message threatens an account suspension or block. |
| `nlp_prize_lottery` | The message claims you won a prize or giveaway. |
| `nlp_unusual_payment` | The message asks for gift cards, cryptocurrency, or wire transfers. |
| `first_time_sender` | This sender has never messaged you before. |
| `out_of_character_link` | This contact sent a link, which is out of character for them. |
| `out_of_character_file` | This contact sent a file, which is out of character for them. |

---

## Category → Action Mapping

| Category | Recommended Action |
|---|---|
| Safe | No immediate action needed. Proceed normally. |
| Suspicious | Proceed with caution. Double check the sender's identity. |
| Deceptive | Do not click any links or download files. Reach out to the sender via a different trusted channel. |
| Phishing | Avoid the link. Block this sender and delete the message immediately. |
| Malware | Dangerous! Quarantine or delete the file immediately. Do not open or execute it. |
