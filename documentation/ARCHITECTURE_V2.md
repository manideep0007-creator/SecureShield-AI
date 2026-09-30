# ARCHITECTURE V2 — SecureShield AI

**Version**: 2.0 (Design Specification)  
**Date**: 2026-09-28  
**Status**: Structural scaffolding complete; engine interface defined; feature implementation pending

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         INPUT CHANNELS                                  │
│  Android Share Intent │ Gmail OAuth Polling │ (Future: API Direct)      │
└──────────┬──────────────────┬──────────────────────┬────────────────────┘
           │                  │                      │
           ▼                  ▼                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         PREPROCESSING                                   │
│  URL Resolution │ File Magic-Byte Check │ Input Sanitization            │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       DETECTION ENGINES                                 │
│                   (Concurrent Execution via Registry)                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │   URL    │ │ Malware  │ │   NLP    │ │  Sender  │ │   Visual     │ │
│  │  Engine  │ │  Engine  │ │  Engine  │ │  Engine  │ │   Engine     │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬───────┘ │
│       │             │            │             │              │       │
│       └─────────────┴────────────┴─────────────┴──────────────┘       │
│                          EngineResult                                   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         RISK FUSION                                     │
│         Confidence-Weighted Aggregation → Score 0–100                   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       EXPLAINABILITY                                    │
│     Flag → Reason Mapping │ Recommended Actions │ Verdict Narrative     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     RISK CLASSIFICATION                                 │
│       Safe │ Suspicious │ Deceptive │ Phishing │ Malware               │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
┌────────────────────────┐  ┌────────────────────────────────────────────┐
│        ALERTS          │  │           USER FEEDBACK                     │
│  Push Notifications    │  │  👍/👎 → feedback.db → Future Retuning     │
│  In-App Verdict Cards  │  │                                            │
└────────────────────────┘  └────────────────────────────────────────────┘
```

---

## 1. Input Channels

Entry points that feed data into the detection pipeline.

### 1.1 Android Share Intent — `IMPLEMENTED`

> **Location**: `android/app/src/main/java/com/secureshield/ai/MainActivity.kt`  
> **Manifest**: `AndroidManifest.xml` — intent filters for `text/plain` and `*/*`

Users share URLs, text messages, or files from any Android app into SecureShield via the native Share menu. The `MainActivity` receives `ACTION_SEND` intents, extracts the payload (`EXTRA_TEXT` or `EXTRA_STREAM`), and routes it to the backend.

- **Text/URL sharing**: Extracts shared text, calls `/api/analyze/message`
- **File sharing**: Reads bytes from content URI, enforces 10 MB limit client-side, uploads via multipart to `/api/analyze/file`

### 1.2 Gmail OAuth Polling — `IMPLEMENTED`

> **Location**: `android/.../GmailScanner.kt`, `MainActivity.kt`

Users authenticate via Google Sign-In with `gmail.readonly` scope. The app fetches the latest unread email, extracts the `From` header, body snippet, and first embedded URL, then sends them to `/api/analyze/message`.

- **Live scan**: Triggered by "Connect Gmail & Scan Inbox" button
- **Demo fallback**: Auto-activates when OAuth SHA-1 is unregistered
- **Background simulation**: "Simulate Background Email Monitor" sends user to home, waits 5s, scans, fires push notification

### 1.3 Background Gmail Worker — `NOT IMPLEMENTED`

> **Target**: `app/preprocessing/` (V2) + Android `WorkManager`

Continuous background email scanning via `WorkManager` with background OAuth token refresh. Currently stubbed — scans only run on button press.

### 1.4 Direct API Access — `NOT IMPLEMENTED`

> **Target**: `app/api/` (V2)

Public-facing REST API for third-party integrations, browser extensions, or automated security pipelines. V1 API exists but is designed only for the Android client.

---

## 2. Preprocessing

Input validation, sanitization, and normalization before engine analysis.

### 2.1 URL Redirect Resolution — `IMPLEMENTED`

> **Location**: V1 `preprocessing/data_prep.py` → `security/safe_url_fetcher.py`

Iteratively follows HTTP redirects (max 5 hops) with per-hop SSRF validation. Blocks loopback, private, link-local, multicast, and reserved IPs. Validates URL scheme (http/https only) and rejects embedded credentials.

### 2.2 File Magic-Byte Validation — `IMPLEMENTED`

> **Location**: V1 `preprocessing/data_prep.py`

Compares actual file type (detected via `filetype` library magic bytes) against the declared file extension. Flags mismatches with alias awareness (jpg↔jpeg, htm↔html). Extension mismatch adds +0.3 to malware engine score.

### 2.3 File Size Enforcement — `IMPLEMENTED`

> **Location**: V1 `api/routes.py` (server-side, 10 MB), `MainActivity.kt` (client-side, 10 MB)

Dual enforcement — Android client checks before upload, backend rejects with HTTP 413 if exceeded.

### 2.4 V2 Preprocessing Module — `NOT IMPLEMENTED`

> **Target**: `app/preprocessing/`  
> **Current state**: Empty `__init__.py` placeholder only

V2 preprocessing will centralize input normalization, add text sanitization, and provide a unified preprocessing pipeline that feeds standardized data into the engine registry.

---

## 3. Detection Engines

Independent analysis modules that each produce a threat assessment.

### 3.1 V2 Engine Interface — `IMPLEMENTED`

> **Location**: `app/engines/base_engine.py`, `app/models/engine_result.py`

Abstract `BaseEngine` class defining the contract all V2 engines must follow. Every engine must return a standardized `EngineResult` containing:

| Field | Type | Description |
|---|---|---|
| `engine_name` | `str` | Unique engine identifier |
| `risk_score` | `float` 0.0–100.0 | Threat level |
| `confidence` | `float` 0.0–1.0 | Self-reported confidence |
| `flags` | `list[str]` | Machine-readable threat indicators |
| `evidence` | `list[EvidenceItem]` | Supporting data (key, value, description) |
| `status` | `EngineStatus` | `SUCCESS` · `PARTIAL` · `ERROR` · `SKIPPED` |

Includes `safe_analyze()` fault-tolerance wrapper — one broken engine can never crash the pipeline.

### 3.2 Engine Registry (Phase 6 Parallelism) — `IMPLEMENTED`

> **Location**: `app/engines/registry.py`

Dynamic engine catalog. Engines self-register at startup.
- The pipeline calls `engine_registry.run_all(input_data)` to execute active engines concurrently.
- Utilizes `asyncio.gather` wrapped with `asyncio.wait_for` (30-second bounded safety limit) per engine to guarantee parallel execution isolated from cascading timeout failures.
- Always aggregates and returns sorted, deterministic arrays of `EngineResult` objects seamlessly resolving backwards compatibility.

### 3.3 URL Engine — `PARTIAL`

> **V1 (working)**: `engines/url_engine.py` — returns ad-hoc dict  
> **V2 (pending)**: No V2 subclass of `BaseEngine` yet

V1 implementation is fully functional:
- Lexical heuristics: IP-based host (+0.3), `@` injection (+0.2), hyphen count (+0.2), suspicious TLDs (+0.4), URL shortener detection
- Google Safe Browsing API v4 integration with 5s timeout
- Combined scoring with GSB-confirmation boosting

**V2 gap**: Not yet wrapped as a `BaseEngine` subclass returning `EngineResult`.

### 3.4 Malware Engine — `PARTIAL`

> **V1 (working)**: `engines/malware_engine.py` — returns ad-hoc dict  
> **V2 (pending)**: No V2 subclass of `BaseEngine` yet

V1 implementation is fully functional:
- SHA-256 hash computation + VirusTotal API v3 lookup
- TTLCache (1000 items, 10-minute TTL) to avoid rate-limit bursts
- Handles VT 404 (file unknown) as `vt_not_found` flag

**V2 gap**: Not yet wrapped as a `BaseEngine` subclass returning `EngineResult`.

### 3.5 NLP Engine — `PARTIAL`

> **V1 (working)**: `engines/nlp_engine.py` — returns ad-hoc dict  
> **V2 (pending)**: No V2 subclass of `BaseEngine` yet

V1 implementation is fully functional:
- Regex pattern matching across 5 social-engineering categories
- Categories: urgency, credential harvesting, account suspension, prize/lottery, unusual payment
- Score: +0.35 per category hit, capped at 1.0

**V2 gap**: Not yet wrapped as a `BaseEngine` subclass returning `EngineResult`.

### 3.6 Sender Behavior Engine — `PARTIAL`

> **V1 (working)**: `engines/sender_engine.py` — returns ad-hoc dict  
> **V2 (pending)**: No V2 subclass of `BaseEngine` yet

V1 implementation is fully functional:
- SQLite-backed per-sender history (message count, link count, file count)
- Flags: `first_time_sender` (0.4), `out_of_character_link` (+0.6), `out_of_character_file` (+0.6)

**V2 gap**: Not yet wrapped as a `BaseEngine` subclass returning `EngineResult`.

### 3.7 Header Analysis Engine — `NOT IMPLEMENTED`

> **Target**: `app/engines/`

Future engine to analyze email headers (SPF, DKIM, DMARC, reply-to mismatch, routing anomalies).

### 3.8 Attachment Behavior Engine — `NOT IMPLEMENTED`

> **Target**: `app/engines/`

Future engine for deep file behavioral analysis beyond hash lookup (macro detection, embedded scripts, archive inspection).

### 3.9 Visual Engine (Phases 4 & 5) — `IMPLEMENTED`

> **Location**: `app/engines/visual_engine.py`

Advanced Visual Intelligence engine capable of interpreting image payloads and classifying spatial arrangements:
- **QR + OCR (Phase 4):** Decodes QR payloads extracting URLs or freeform text, and extracts OCR textual artifacts via `easyocr`.
- **Visual Phishing Detection (Phase 5):** Conducts bounding-box and geometric layout checks via `OpenCV` contour detection (aspect-ratio parsing) combined with OCR language hits (e.g., "password", "sign in"). 
- Predictively flags `visual_credential_prompt` and high-confidence fake login overlays (`visual_phishing_detected`) designed to emulate captive portals or email-hosted web credential frames.
- Feeds extracted textual and URL elements downstream into the unified `ScanInput` for subsequent URL/NLP analysis natively without duplication.

---

## 4. Risk Fusion

Aggregation of individual engine results into a single unified threat score.

### 4.1 V1 Fusion (Confidence-Weighted Average) — `IMPLEMENTED`

> **Location**: V1 `engines/fusion.py` → `generate_fusion_score()`

Calculates a confidence-weighted average from all active engine results:
- Engine confidence weights: URL (0.8), File (0.9), NLP (0.65), Sender (0.5)
- Formula: `score = round((Σ engine_score × confidence) / (Σ confidence) × 100)`
- Outputs 0–100 integer score

### 4.2 Risk Fusion & Classification (Phase 7) — `IMPLEMENTED`

> **Location**: `app/fusion/risk_fusion.py`, `app/models/risk_assessment.py`

The V2 response preserves every engine-level `EngineResult` and adds one unified
`RiskAssessment`. Fusion is deterministic and runs after the Phase 6 registry
has completed:

- Only `SUCCESS` and `PARTIAL` results with positive confidence contribute to
    the aggregate. `SKIPPED`, `ERROR`, and zero-confidence results are recorded
    as ignored and do not lower the score.
- Each result is weighted by `confidence * engine reliability`. Reliability
    defaults are URL `0.90`, malware `1.00`, NLP `0.80`, visual `0.90`, sender
    `0.60`, and `0.75` for future engines. Partial results receive half weight.
- The final score is the weighted mean, rounded to two decimals and constrained
    to `0.0–100.0`. Engine flags and evidence are retained in deterministic order
    in the assessment as well as in the original results.
- Classification boundaries are: `Safe` (`<20`), `Suspicious` (`20–44.99`),
    `Deceptive` (`45–69.99`), `Phishing` (`70–89.99`), and `Phishing` at `90+`
    unless a malware signal is present. A malware engine score of `90+` or a
    malware flag (`MALWARE`, `vt_malicious`, `vt_suspicious`, or
    `malware_detected`) produces `Malware`.

The `/api/scan` response exposes `risk_score` and `classification` at the top
level, with the complete `risk_assessment` details and unchanged per-engine
`results` alongside them.

---

## 5. Explainability

Translating technical engine output into human-readable verdicts.

### 5.1 V1 Flag → Reason Mapping — `IMPLEMENTED`

> **Location**: V1 `engines/fusion.py` → `FLAG_REASONS` dict + `CATEGORY_ACTIONS` dict

Maps 18+ machine-readable flags to plain-language explanations:
- URL flags: `ip_based_host`, `at_symbol_present`, `suspicious_tld`, etc.
- File flags: `extension_mismatch`, `vt_malicious`, `vt_suspicious`, `vt_not_found`
- NLP flags: `nlp_urgency`, `nlp_credential_request`, `nlp_account_suspension`, etc.
- Sender flags: `first_time_sender`, `out_of_character_link`, `out_of_character_file`

Includes per-category recommended actions (Safe → "Proceed normally" through Malware → "Quarantine immediately").

### 5.2 V2 Explainability Module — `NOT IMPLEMENTED`

> **Target**: `app/explainability/`  
> **Current state**: Empty `__init__.py` placeholder only

V2 will separate explainability into its own module (extracted from fusion.py). Will consume `EngineResult.evidence` items to generate structured reasoning chains, support localization, and produce both short summaries and detailed breakdowns.

---

## 6. Risk Classification

Mapping the final fused score to a discrete threat category.

### 6.1 5-Tier Category System — `IMPLEMENTED`

> **Location**: V1 `engines/fusion.py`

| Category | Score Range | Threshold |
|---|---|---|
| **Safe** | 0 – 19 | < 20 |
| **Suspicious** | 20 – 44 | < 45 |
| **Deceptive** | 45 – 69 | < 70 |
| **Phishing** | 70 – 89 | < 90 |
| **Malware** | 90 – 100 | ≥ 90 + malware-specific flags |

Malware classification requires score ≥ 90 **and** at least one of: `vt_malicious`, `vt_suspicious`, `extension_mismatch`, `MALWARE`. Otherwise falls to Phishing.

### 6.2 V2 Dynamic Classification — `NOT IMPLEMENTED`

> **Target**: `app/fusion/` or `app/explainability/`

V2 will support configurable thresholds, category weight tuning from feedback data, and per-context classification profiles (e.g. stricter thresholds for enterprise deployments).

---

## 7. Alerts

Notifying users of detected threats.

### 7.1 In-App Verdict Cards — `IMPLEMENTED`

> **Location**: `android/.../activity_main.xml`, `MainActivity.kt`

Single-screen verdict display with:
- Category badge (colored by severity)
- Risk score (N / 100)
- Bulleted evidence/reason list
- Recommended action text

### 7.2 Push Notifications — `IMPLEMENTED`

> **Location**: `android/.../MainActivity.kt`

Android `NotificationChannel` ("SS_ALERTS", IMPORTANCE_HIGH) fires push notifications after Gmail scan results. Includes title and risk summary. Taps open the app.

### 7.3 Android 13+ Notification Permission — `PARTIAL`

> **Location**: `AndroidManifest.xml` (`POST_NOTIFICATIONS`), `MainActivity.kt`

Permission is declared in the manifest. `SecurityException` on missing permission is caught and logged, but **no re-prompt UX** exists to guide the user to grant the permission.

### 7.4 Real-Time Alert Dashboard — `NOT IMPLEMENTED`

> **Target**: `app/api/` (V2 backend) + future Android/web UI

Centralized alert history, threat timeline, and scan activity log. No implementation exists.

---

## 8. User Feedback

Closed-loop system for collecting user accuracy reports.

### 8.1 Feedback Collection — `IMPLEMENTED`

> **Location**: V1 `engines/feedback.py` (backend), `MainActivity.kt` (Android)

**Android**: Thumbs up (👍 Accurate) / Thumbs down (👎 Inaccurate) buttons appear after every scan verdict. Sends `FeedbackRequest` to backend.

**Backend**: `POST /api/feedback` persists to SQLite `feedback.db`:
```
feedback(id, target, score, category, feedback_value, timestamp)
```

### 8.2 Feedback-Driven Model Retuning — `NOT IMPLEMENTED`

> **Target**: `app/database/` + `app/fusion/`

Pipeline to iterate over accumulated `feedback.db` data and adjust engine confidence weights or detection thresholds. Designed for logistic regression over feedback labels. No implementation exists.

### 8.3 V2 Database Layer — `NOT IMPLEMENTED`

> **Target**: `app/database/`  
> **Current state**: Empty `__init__.py` placeholder only

V2 will centralize database connections, replace per-module SQLite init with unified session management, and support schema migrations.

---

## Implementation Status Summary

| Component | Sub-Component | Status |
|---|---|---|
| **Input Channels** | Android Share Intent | `IMPLEMENTED` |
| | Gmail OAuth Polling | `IMPLEMENTED` |
| | Background Gmail Worker | `NOT IMPLEMENTED` |
| | Direct API Access | `NOT IMPLEMENTED` |
| **Preprocessing** | URL Redirect Resolution | `IMPLEMENTED` |
| | File Magic-Byte Validation | `IMPLEMENTED` |
| | File Size Enforcement | `IMPLEMENTED` |
| | V2 Preprocessing Module | `NOT IMPLEMENTED` |
| **Detection Engines** | V2 Engine Interface (`BaseEngine`) | `IMPLEMENTED` |
| | V2 Engine Registry | `IMPLEMENTED` |
| | URL Engine | `PARTIAL` |
| | Malware Engine | `PARTIAL` |
| | NLP Engine | `PARTIAL` |
| | Sender Behavior Engine | `PARTIAL` |
| | Visual Engine (QR/OCR/Phishing) | `IMPLEMENTED` |
| | Header Analysis Engine | `NOT IMPLEMENTED` |
| | Attachment Behavior Engine | `NOT IMPLEMENTED` |
| **Risk Fusion** | V1 Weighted Average | `IMPLEMENTED` |
| | V2 Fusion Module | `NOT IMPLEMENTED` |
| **Explainability** | V1 Flag → Reason Mapping | `IMPLEMENTED` |
| | V2 Explainability Module | `NOT IMPLEMENTED` |
| **Risk Classification** | 5-Tier Category System | `IMPLEMENTED` |
| | V2 Dynamic Classification | `NOT IMPLEMENTED` |
| **Alerts** | In-App Verdict Cards | `IMPLEMENTED` |
| | Push Notifications | `IMPLEMENTED` |
| | Android 13+ Permission Handling | `PARTIAL` |
| | Real-Time Alert Dashboard | `NOT IMPLEMENTED` |
| **User Feedback** | Feedback Collection (UI + DB) | `IMPLEMENTED` |
| | Feedback-Driven Retuning | `NOT IMPLEMENTED` |
| | V2 Database Layer | `NOT IMPLEMENTED` |

### Counts

- **IMPLEMENTED**: 13
- **PARTIAL**: 5
- **NOT IMPLEMENTED**: 10
