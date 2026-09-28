# V1 BASELINE — Features

**Snapshot Date**: 2026-09-28

---

## Fully Implemented Features

### Backend — Detection Pipeline

| # | Feature | Engine | Description |
|---|---|---|---|
| 1 | **URL Lexical Heuristics** | `url_engine.py` | Detects IP-based hosts, `@` credential injection, excessive hyphens (≥3), suspicious TLDs (.xyz, .top, .cc, .tk, .ml, .ga, .cf, .gq), URL shortener usage |
| 2 | **Google Safe Browsing Lookup** | `url_engine.py` | Queries GSB API v4 for MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION threats |
| 3 | **File Hash Scanning** | `malware_engine.py` | Computes SHA-256 of uploaded files and queries VirusTotal API v3 for reputation |
| 4 | **VirusTotal Result Caching** | `malware_engine.py` | 10-minute TTLCache (1000 items) to avoid redundant API calls |
| 5 | **Magic Byte Validation** | `data_prep.py` | Compares actual file type (via `filetype` library magic bytes) against declared extension; flags mismatches with alias awareness (jpg↔jpeg, htm↔html) |
| 6 | **NLP Social Engineering Detection** | `nlp_engine.py` | Regex pattern matching across 5 categories: urgency, credential requests, account suspension, prize/lottery, unusual payment methods |
| 7 | **Sender Behavior Tracking** | `sender_engine.py` | SQLite-backed stateful tracker; flags first-time senders and out-of-character link/file behavior |
| 8 | **Fusion Score Aggregation** | `fusion.py` | Confidence-weighted average across all active engines, scaled to 0-100 |
| 9 | **5-Tier Risk Classification** | `fusion.py` | Score mapped to Safe (0-19) / Suspicious (20-44) / Deceptive (45-69) / Phishing (70-89) / Malware (90-100) |
| 10 | **Explainable AI Reasoning** | `fusion.py` | 18 engine flags mapped to plain-language explanations + per-category recommended actions |
| 11 | **User Feedback Persistence** | `feedback.py` | Thumbs up/down feedback stored in SQLite with target, score, category, value, timestamp |
| 12 | **SSRF Protection** | `safe_url_fetcher.py` | Monkeypatched `socket.getaddrinfo` blocking loopback/private/link-local/multicast IPs; scheme validation; no embedded credentials; per-hop redirect validation (max 5) |
| 13 | **URL Redirect Unrolling** | `data_prep.py` | Iterative redirect following with SSRF-safe validation at each hop |
| 14 | **File Size Enforcement** | `routes.py` | Server-side 10 MB upload limit with proper HTTP 413 response |
| 15 | **Error Bubbling** | `routes.py` | Engine errors (API key missing, network failure, rate limits) surfaced in response payload, never silently swallowed |

### Android Client

| # | Feature | Component | Description |
|---|---|---|---|
| 16 | **Share Intent Receiver** | `MainActivity.kt` + Manifest | Global implicit intent receiver for `text/plain` (URLs/messages) and `*/*` (files) from any app |
| 17 | **URL/Message Scanning** | `MainActivity.kt` | Sends shared text to `/api/analyze/message` via Retrofit, renders verdict |
| 18 | **File Scanning** | `MainActivity.kt` | Reads file bytes from content URI, enforces local 10 MB limit, uploads via multipart to `/api/analyze/file` |
| 19 | **Gmail OAuth Integration** | `GmailScanner.kt` | Google Sign-In with `gmail.readonly` scope, fetches latest unread email, extracts sender/body/URL |
| 20 | **Demo/Fallback Mode** | `MainActivity.kt` | Auto-simulates a phishing email scan when OAuth is unregistered (SHA-1 mismatch) |
| 21 | **Background Monitor Simulation** | `MainActivity.kt` | Sends user to home screen, waits 5s, fires simulated Gmail scan + push notification |
| 22 | **Push Notifications** | `MainActivity.kt` | NotificationChannel "SS_ALERTS" with IMPORTANCE_HIGH; fires on Gmail scan results |
| 23 | **Verdict Rendering** | `activity_main.xml` | Category badge, risk score, bullet-pointed reasons, recommended action |
| 24 | **User Feedback UI** | `MainActivity.kt` | Thumbs up/down buttons, sends `FeedbackRequest` to `/api/feedback` |
| 25 | **OOM Protection** | `MainActivity.kt` | Catches `OutOfMemoryError` on large file reads with graceful UI fallback |

---

## Stubbed / Planned Features (Not Implemented in V1)

| Feature | Status | Notes |
|---|---|---|
| VirusTotal file upload | Stubbed | Only hash lookup; no actual file upload to VT (privacy/rate-limit concern) |
| Gmail background worker | Stubbed | No `WorkManager` or background OAuth refresh; runs only on button press |
| Android 13+ notification re-prompting | Stubbed | `SecurityException` is caught and logged, no re-prompt UX |
| Feedback-based model retuning | Planned | `feedback.db` collects data but no retraining pipeline exists |
| Generative NLP replacement | Planned | Current engine is regex-only; LLM replacement documented as future work |
| Encrypted quarantine vault | Planned | No scoped storage quarantine feature exists |
