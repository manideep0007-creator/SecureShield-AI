# PROJECT AUDIT — SecureShield AI

**Date**: 2026-09-28  
**Scope**: Full project analysis (read-only)

---

## 1. Frontend Structure

**No standalone web frontend exists.** The user-facing client is the Android application (see §3). There is no React, Angular, Vue, or HTML/CSS/JS web UI in this project.

---

## 2. Backend Structure

| Item | Detail |
|---|---|
| **Framework** | FastAPI (Python) |
| **Entry point** | `backend/main.py` — Uvicorn on `0.0.0.0:8000` |
| **Router** | `backend/api/routes.py` — mounted at `/api` |
| **Configuration** | `backend/core/config.py` — `pydantic-settings`, reads `.env` |
| **Preprocessing** | `backend/preprocessing/data_prep.py` — URL redirect resolution, magic-byte file-type validation |
| **Security** | `backend/security/safe_url_fetcher.py` — SSRF-resistant URL fetcher with DNS-rebinding prevention |

### Backend File Tree
```
backend/
├── main.py                       # FastAPI app factory
├── requirements.txt              # 9 dependencies
├── api/
│   └── routes.py                 # 3 endpoints (message, file, feedback)
├── core/
│   └── config.py                 # Settings (API keys, environment)
├── data/
│   ├── sender_behavior.db        # SQLite — sender history
│   └── feedback.db               # SQLite — user feedback
├── engines/
│   ├── url_engine.py             # Lexical heuristics + Google Safe Browsing
│   ├── malware_engine.py         # SHA-256 hash → VirusTotal v3
│   ├── nlp_engine.py             # Regex-based social-engineering classifier
│   ├── sender_engine.py          # Behavioral anomaly tracker (SQLite)
│   ├── fusion.py                 # Weighted score aggregation + explainability
│   └── feedback.py               # Feedback persistence (SQLite)
├── preprocessing/
│   └── data_prep.py              # URL unrolling, file magic-byte check
├── security/
│   └── safe_url_fetcher.py       # SSRF protection layer
└── tests/
    └── test_pipeline.py          # 5 test cases (mocked external APIs)
```

---

## 3. Android Structure

| Item | Detail |
|---|---|
| **Language** | Kotlin |
| **Min SDK** | 24 (Android 7.0) |
| **Target/Compile SDK** | 34 (Android 14) |
| **Package** | `com.secureshield.ai` |
| **Build system** | Gradle (Kotlin DSL), AGP 9.4.1, Kotlin 2.2.10 |
| **Architecture** | Single-Activity, coroutine-based, direct API calls via Retrofit |

### Key Source Files
| File | Purpose |
|---|---|
| `MainActivity.kt` | UI controller — share-intent receiver, Gmail OAuth flow, scan orchestration, push notifications, feedback submission |
| `GmailScanner.kt` | Gmail API client — fetches latest unread email, extracts sender/body/URL |
| `network/ApiClient.kt` | Retrofit singleton — defines `SecureShieldApi` interface with 3 endpoints |
| `activity_main.xml` | Single-screen layout: category badge, score, reasons list, action, feedback thumbs |

### Key Dependencies
- **Retrofit 2.9** + Gson converter (networking)
- **OkHttp 4.12** (HTTP client)
- **Kotlinx Coroutines** (async)
- **Google Play Services Auth** (Google Sign-In)
- **Google API Client for Android** + Gmail API (email access)

---

## 4. Database

| Database | Engine | Location | Purpose |
|---|---|---|---|
| `sender_behavior.db` | SQLite | `backend/data/` | Tracks per-sender message/link/file counts for behavioral anomaly detection |
| `feedback.db` | SQLite | `backend/data/` | Stores user feedback (target, score, category, value, timestamp) |

**Schema — `senders` table**: `sender_id TEXT PK, message_count INT, link_count INT, file_count INT`  
**Schema — `feedback` table**: `id INT PK AUTO, target TEXT, score INT, category TEXT, feedback_value TEXT, timestamp DATETIME`

No external database (PostgreSQL, MySQL, MongoDB, etc.) is used. Both databases are file-local SQLite.

---

## 5. Existing Detection Engines

| # | Engine | File | Technique | Confidence Weight |
|---|---|---|---|---|
| 1 | **URL Engine** | `url_engine.py` | Lexical heuristics (IP host, `@` injection, excessive hyphens, suspicious TLDs, URL shorteners) + Google Safe Browsing API v4 | 0.8 |
| 2 | **Malware Engine** | `malware_engine.py` | SHA-256 hash lookup via VirusTotal API v3 with 10-min TTLCache (1000 items) | 0.9 |
| 3 | **NLP Engine** | `nlp_engine.py` | Regex pattern matching across 5 social-engineering categories: urgency, credential requests, account suspension, prize/lottery, unusual payment | 0.65 |
| 4 | **Sender Behavior Engine** | `sender_engine.py` | SQLite-backed anomaly tracker — flags first-time senders and out-of-character link/file sending | 0.5 |
| 5 | **Fusion Engine** | `fusion.py` | Confidence-weighted average → 0–100 score → 5-tier category (Safe/Suspicious/Deceptive/Phishing/Malware) + plain-language explainability layer mapping 15+ flags to human-readable reasons | — |
| 6 | **Feedback Engine** | `feedback.py` | User thumbs-up/down persistence to SQLite for future model retuning | — |

### Preprocessing
- **URL Redirect Resolution** (`data_prep.py` → `safe_url_fetcher.py`): Iteratively follows redirects (max 5 hops) with per-hop SSRF validation.
- **Magic Byte Validation** (`data_prep.py`): Compares actual file type (via `filetype` library) against declared extension; flags mismatches.

---

## 6. APIs

### Backend Endpoints (FastAPI)

| Method | Path | Purpose | Input |
|---|---|---|---|
| `GET` | `/` | Health check | — |
| `POST` | `/api/analyze/message` | Analyze text/URL/sender | JSON: `message_text`, `url`, `sender_id` (all optional) |
| `POST` | `/api/analyze/file` | Analyze uploaded file | Multipart: `file` (max 10 MB), optional `sender_id` |
| `POST` | `/api/feedback` | Submit user feedback | JSON: `analyzed_target`, `score`, `category`, `feedback_value` |

### External API Integrations

| Service | Used In | Purpose |
|---|---|---|
| **Google Safe Browsing API v4** | `url_engine.py` | URL threat lookup (malware, social engineering, unwanted software) |
| **VirusTotal API v3** | `malware_engine.py` | File hash reputation check |
| **Gmail API** (Android-side) | `GmailScanner.kt` | Read latest unread email via OAuth `gmail.readonly` scope |

### Android → Backend Communication
- **Retrofit 2** with Gson over HTTP to `BASE_URL` (default: `http://10.0.2.2:8000/` for emulator localhost)
- 3 endpoints consumed: `analyzeMessage`, `analyzeFile`, `sendFeedback`

---

## 7. Tests

| File | Framework | Test Count | Description |
|---|---|---|---|
| `backend/tests/test_pipeline.py` | FastAPI `TestClient` + `unittest.mock` | 5 | End-to-end pipeline tests with mocked external APIs |

### Test Cases
1. **Known Safe Message** — casual text → expects `Safe`
2. **Known Safe URL** — `google.com` → expects `Safe`
3. **Obvious Phishing Scam** — urgency + credential + payment keywords → expects `Phishing`
4. **Suspicious IP-Based URL** — IP host + `@` + `.xyz` TLD → expects `Suspicious`/`Deceptive`/`Phishing`/`Malware`
5. **Malware / Misleading Extension** — `.exe` with PDF magic bytes → expects elevated risk

External APIs (Google Safe Browsing, VirusTotal) are **fully mocked** using `AsyncMock`. No Android tests exist.

---

## 8. Configuration Files

| File | Purpose |
|---|---|
| `backend/core/config.py` | Pydantic `BaseSettings` — reads `GOOGLE_SAFE_BROWSING_API_KEY` and `VIRUSTOTAL_API_KEY` from `.env` |
| `backend/requirements.txt` | Python dependencies (9 packages: fastapi, uvicorn, python-dotenv, pydantic, pydantic-settings, httpx, filetype, cachetools, python-multipart) |
| `android/build.gradle.kts` | Root Gradle — AGP 9.4.1, Kotlin 2.2.10 |
| `android/app/build.gradle.kts` | App-level Gradle — SDK versions, dependencies, `BASE_URL` build config |
| `android/settings.gradle.kts` | Project name, repository definitions |
| `android/gradle.properties` | AndroidX, config-cache, Kotlin code style flags |
| `android/local.properties` | Local SDK path + optional `BASE_URL` override |
| `android/gradle/gradle-daemon-jvm.properties` | JVM settings for Gradle daemon |
| `android/app/src/main/AndroidManifest.xml` | Permissions (Internet, storage, notifications), share-intent filters |

---

## Summary

SecureShield AI is a **two-tier mobile security platform**: an Android Kotlin client and a Python FastAPI backend. It uses a modular pipeline of 4 detection engines (URL, Malware, NLP, Sender Behavior) aggregated by a fusion engine into an explainable risk verdict. Data is stored locally in SQLite. External integrations include Google Safe Browsing, VirusTotal, and Gmail. There is no web frontend, no containerization config, no CI/CD pipeline, and no formal test framework (pytest/JUnit) — tests are script-based with mocked APIs.
