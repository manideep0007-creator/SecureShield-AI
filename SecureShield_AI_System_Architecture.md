# SecureShield-AI: System Architecture Document
**Intelligent Phishing & Threat Detection System**

* **Document Version**: 2.0 (Post-Phase 21 Comprehensive Architecture)
* **Status**: Complete & Verified Against Implementation
* **Audience**: College Project Evaluation, Technical Jury Review, Developer Onboarding, Future Maintenance
* **Target Repository**: `SecureShield-AI` (Android Client + FastAPI Backend)
* **Author**: Senior System Architect & Technical Documentation Engineer

---

## Table of Contents

1. [Executive Summary & System Overview](#1-executive-summary--system-overview)
2. [Architectural Principles & Quality Attributes](#2-architectural-principles--quality-attributes)
3. [Level 1 — System Context Architecture](#3-level-1--system-context-architecture)
4. [Level 2 — Container Architecture](#4-level-2--container-architecture)
5. [Level 3 — Component Architecture](#5-level-3--component-architecture)
   - [5.1 Android Client Architecture](#51-android-client-architecture)
   - [5.2 FastAPI Backend Architecture](#52-fastapi-backend-architecture)
   - [5.3 Preprocessing & Input Normalization Layer](#53-preprocessing--input-normalization-layer)
   - [5.4 Detection & Intelligence Layer (The 7 Engines)](#54-detection--intelligence-layer-the-7-engines)
   - [5.5 Risk Fusion Engine](#55-risk-fusion-engine)
   - [5.6 Dynamic Classification Policy & Context Profiles](#56-dynamic-classification-policy--context-profiles)
   - [5.7 Explainability & Action Recommendation Engine](#57-explainability--action-recommendation-engine)
   - [5.8 Storage & Evaluation Architecture](#58-storage--evaluation-architecture)
6. [Level 4 — End-to-End Data Flow Architecture](#6-level-4--end-to-end-data-flow-architecture)
7. [Subsystem Deep Dives](#7-subsystem-deep-dives)
   - [7.1 Android Share Intent Router](#71-android-share-intent-router)
   - [7.2 Gmail Integration & OAuth Lifecycle](#72-gmail-integration--oauth-lifecycle)
   - [7.3 Background Protection & Threat Alerting](#73-background-protection--threat-alerting)
   - [7.4 Client-Side Sanitized Scan History](#74-client-side-sanitized-scan-history)
   - [7.5 User Feedback Loop & Evaluation Metrics](#75-user-feedback-loop--evaluation-metrics)
8. [Security, Privacy & Operational Boundaries](#8-security-privacy--operational-boundaries)
9. [External API Integrations](#9-external-api-integrations)
10. [Error Handling, Fault Tolerance & Resource Limits](#10-error-handling-fault-tolerance--resource-limits)
11. [Deployment & Runtime Architecture](#11-deployment--runtime-architecture)
12. [Technology Stack Inventory](#12-technology-stack-inventory)
13. [Key Design Decisions (Architecture Decision Records)](#13-key-design-decisions-architecture-decision-records)
14. [Known Limitations & Future Roadmap](#14-known-limitations--future-roadmap)
15. [Implementation vs. Legacy Documentation Discrepancies](#15-implementation-vs-legacy-documentation-discrepancies)
16. [Appendix: Core Repository File Map](#16-appendix-core-repository-file-map)

---

## 1. Executive Summary & System Overview

**SecureShield-AI** is a multi-layered cybersecurity defense system designed to safeguard mobile and desktop users against phishing, malicious file attachments, deceptive web URLs, visual credential harvesting, and email impersonation threats.

Rather than relying on a single detection heuristic or proprietary antivirus signatures, SecureShield-AI orchestrates an ensemble of **seven specialized detection and behavioral intelligence engines**. These engines analyze incoming threat vectors concurrently across lexical, textual, visual, behavioral, and structural dimensions. Their findings are synthesized by a **confidence-weighted Bayesian risk fusion model**, evaluated against **deterministic risk classification policies**, and explained to the end user in **actionable, plain-English guidance**.

### Operational Flow at a Glance
```
[User / OS Share / Gmail / File]
               ↓
    [Android Client: Kotlin]
  (MIME Extraction, Redaction, WorkManager)
               ↓ TLS 1.3 / HTTP POST (/api/scan)
  [FastAPI Backend: Python 3.14]
               ↓
 [V2 Preprocessor & SSRF Safe Fetcher]
 (NFKC Normalization, Magic Bytes, IP Pinning)
               ↓
     [Sequential Visual Stage]
  (OpenCV & EasyOCR: QR & Fake Login Detection)
               ↓
   [Concurrent Detection Engines]
  (URL, NLP, Sender, Header, Attachment, Malware)
               ↓
     [Confidence-Weighted Fusion]
 (Usable Engines, Reliability Factors, Score 0–100)
               ↓
    [Dynamic Classification Policy]
(Default / Strict / Enterprise + Malware Safeguard)
               ↓
     [Explainability Engine]
  (Reason Mapping & Actionable Prescriptions)
               ↓
  [Standardized Response: UnifiedScanResponse]
               ↓
   [Android UI / Push Notification / Room DB]
```

---

## 2. Architectural Principles & Quality Attributes

The design of SecureShield-AI is governed by five foundational architectural principles:

1. **Zero-Trust Input Normalization & Bounded Execution**:
   All incoming inputs (text, URLs, files, images, headers) are treated as untrusted. They are sanitized, normalized, and length-bounded before reaching any detection logic. No engine is permitted to execute untrusted code or run unbounded queries.

2. **Fault-Tolerant Engine Isolation**:
   Every detection engine runs inside a safe isolation wrapper (`safe_analyze`). The crash, timeout, or external API failure of one engine cannot crash the pipeline or degrade unrelated engine scores.

3. **Absence of Proof is Not Proof of Absence**:
   An engine that fails due to missing credentials, timeouts, or network loss (e.g., VirusTotal API failure) reports `ERROR` or `PARTIAL` with zero confidence. The fusion layer explicitly ignores errored engines rather than treating an unscanned entity as safe.

4. **Privacy-Preserving Edge & Zero Content Retention**:
   The backend operates statelessly with respect to user payloads. Raw email bodies, file contents, passwords, and tokens are never written to disk or database tables on the backend. Client-side scan history applies strict regex redaction before storing records in SQLite.

5. **Immutable Security Thresholds (Adversarial Feedback Shield)**:
   User feedback (thumbs up / thumbs down) is persisted for evaluation and drift monitoring, but is strictly isolated by software architecture from dynamically retuning classification thresholds, preventing malicious feedback poisoning attacks.

---

## 3. Level 1 — System Context Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │                 USER / CLIENT                │
                  │  • Shares links, text, files via OS menu     │
                  │  • Connects Gmail account for inbox checks   │
                  │  • Views threat verdicts & recommendations   │
                  └───────────────────────┬──────────────────────┘
                                          │
                                          │ Interacts with UI / Share Menu
                                          ▼
                  ┌──────────────────────────────────────────────┐
                  │          SECURESHIELD-AI MOBILE APP          │
                  │  Native Android App (Kotlin / Retrofit)      │
                  │  • SharedIntentRouter                        │
                  │  • Background WorkManager ThreatAlertWorker   │
                  │  • Local SQLite Sanitized History Store      │
                  └───────────────────────┬──────────────────────┘
                                          │
                                          │ HTTPS REST (JSON Payload)
                                          ▼
                  ┌──────────────────────────────────────────────┐
                  │          SECURESHIELD-AI BACKEND             │
                  │  FastAPI Application (Python 3.14)           │
                  │  • Preprocessing & SSRF-Safe Fetcher         │
                  │  • 7 Parallel Detection Engines              │
                  │  • Confidence-Weighted Bayesian Fusion       │
                  │  • Explainability & Classification Policy    │
                  └──────┬────────────┬─────────────┬────────────┘
                         │            │             │
        Google Safe      │            │ VirusTotal  │ Google OAuth
        Browsing v4      │            │ v3 API      │ / Gmail API
        Threat Matches   │            │ Hash Check  │ (Direct Client)
                         ▼            ▼             ▼
                  ┌────────────┐┌────────────┐┌────────────┐
                  │ Google GSB ││ VirusTotal ││ Gmail API  │
                  └────────────┘└────────────┘└────────────┘
```

### External Collaborators
* **Google Safe Browsing API v4** (*External Dependency*): Queried via SHA-256 / threat-matches endpoint to cross-reference URLs against Google's global blacklist.
* **VirusTotal API v3** (*External Dependency*): Queried via SHA-256 file hashes to inspect multi-antivirus scanning telemetry without uploading proprietary user documents.
* **Google Sign-In & Gmail API** (*External Dependency*): Leveraged directly by the Android client using OAuth 2.0 (`gmail.readonly`) to inspect unread message headers and bodies.
* **WHOIS / RDAP Servers** (*External Dependency*): Queried asynchronously with strict 2.0-second timeouts to measure domain registration age.

---

## 4. Level 2 — Container Architecture

The system is cleanly divided into two primary runtime containers, supported by three local SQLite datastores and external security services:

| Container / Component | Tech Stack | Execution Environment | Repository Location | Primary Responsibility |
|---|---|---|---|---|
| **Android Client** | Kotlin, Retrofit2, Gson, WorkManager, SQLiteOpenHelper | Android OS 8.0+ (API 26+) | `android/app/src/main/` | UI, Intent interception, Gmail polling, sanitized local history, threat notifications. |
| **Backend Core** | Python 3.14, FastAPI, Pydantic v2, Uvicorn, AsyncIO | Linux / Windows / Docker | `backend/app/`, `backend/main.py` | Universal scan pipeline, input normalization, engine execution, fusion, classification. |
| **Sender Intelligence DB** | SQLite3 (WAL mode) | Backend local filesystem | `backend/data/sender_behavior.db` | Tracks sender frequency, first/last seen timestamps, hourly distributions, domain drift. |
| **Evaluation Metrics DB** | SQLite3 | Backend local filesystem | `backend/data/feedback.db` | Persists user thumbs up/down feedback indexed by UUID scan_id for precision/recall evaluation. |
| **Client Scan History DB** | SQLite3 (`SQLiteOpenHelper`) | Android private app storage | `secure_scan_history.db` | Secure on-device store of past scan results with redacted sensitive tokens. |

---

## 5. Level 3 — Component Architecture

### 5.1 Android Client Architecture
Located at `android/app/src/main/java/com/secureshield/ai/`:

1. **`MainActivity.kt`**: Main interaction hub. Hosts scanning status, live category badges, risk scores, reasons list, recommended action text, and thumbs up/down feedback triggers.
2. **`ScanHistoryActivity.kt`**: Paginated history viewer allowing users to inspect past scans, view detailed indicators, delete individual records, or clear all history.
3. **`share/SharedIntentRouter.kt`**: Parses incoming `android.intent.action.SEND` intents. Validates MIME types, resolves stream URIs, checks 10 MB file bounds, and routes to URL, Text, or File scan pipelines.
4. **`network/ApiClient.kt`**: Configures Retrofit HTTP client pointing to `BuildConfig.BASE_URL`. Houses `UnifiedScanResponseParser`, which executes strict JSON structural validation on API responses.
5. **`background/BackgroundProtectionManager.kt`**: Coordinates WorkManager periodic task registration (`ThreatAlertWorker`, 15-minute interval, battery & network constraints).
6. **`background/BackgroundScanner.kt`**: Core background execution loop: fetches unread Gmail, deduplicates against `ProcessedMessageStore`, executes scan, saves history, and triggers high-priority threat notifications on Phishing/Malware.
7. **`history/ScanHistoryRepository.kt` & `ScanHistoryDatabase.kt`**: Manages on-device SQLite database `secure_scan_history.db` (Schema v3). Enforces `ScanHistorySanitizer` to scrub secrets before storage.
8. **`feedback/FeedbackSubmissionManager.kt`**: Thread-safe feedback dispatcher with mutex locks, duplicate suppression (409 conflict handling), and optimistic UI dismiss policies.

### 5.2 FastAPI Backend Architecture
Located at `backend/app/`:

1. **`main.py`**: Application bootstrap configuring FastAPI application title, routing prefixes (`/api`), validation exception handlers, and root health check (`GET /`).
2. **`api/routes.py`**: Houses the three production API endpoints:
   - `POST /api/scan`: Ingests `ScanInput`, executes `UnifiedScanPipeline.run()`, returns `UnifiedScanResponse`.
   - `POST /api/feedback`: Ingests `FeedbackRequest`, validates UUID, stores in `feedback.db`.
   - `GET /api/evaluation/metrics`: Computes precision telemetry, positive/negative rates by source and classification.
3. **`config/config.py`**: Pydantic BaseSettings loading environment configurations from `.env` (`GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `PROJECT_NAME`).

### 5.3 Preprocessing & Input Normalization Layer
Located at `backend/app/preprocessing/`:

1. **`v2_preprocessor.py` (`V2Preprocessor`)**:
   - **Text Normalization**: Enforces 50,000 char cap, Unicode NFKC normalization, ASCII control-character stripping, line ending standardization (`\n`), whitespace collapsing.
   - **URL Normalization**: Enforces 4,096 char cap, strips brackets/quotes, rejects dangerous pseudo-schemes (`javascript:`, `data:`, `file:`), defaults to `http://` if missing, lowercases hostnames, strips default ports (`:80`, `:443`).
   - **File Normalization**: Enforces strict 10 MB limit (`MAX_FILE_BYTES = 10 * 1024 * 1024`), sanitizes basename to prevent path traversal (`../`), strips control characters.
   - **Email Metadata Normalization**: Extracts email from display names (`Name <email@domain.com>`), bounds metadata dictionary to 100 items, bounds email `Received` hops to 30.
2. **`safe_url_fetcher.py` (`SafeURLFetcher`)**:
   - **SSRF Prevention**: Resolves domain DNS synchronously before connecting. Rejects private (RFC 1918), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), multicast, reserved, and IPv4-mapped IPv6 internal IPs.
   - **Anti-DNS Rebinding (TOCTOU)**: Directly connects to the pre-validated IP address using custom socket connections with explicit `Host` and TLS `SNI` headers. Follows up to 5 redirects iteratively.
3. **`data_prep.py`**:
   - Magic byte file sniffing (`filetype` library) comparing declared file extension against actual binary signatures to detect extension spoofing (`extension_mismatch`).

---

### 5.4 Detection & Intelligence Layer (The 7 Engines)
Located at `backend/app/engines/`:

All engines inherit from `BaseEngine` (`base_engine.py`) and return a standardized `EngineResult`:

```python
class EngineResult(BaseModel):
    engine_name: str
    risk_score: float         # 0.0 to 100.0
    confidence: float         # 0.0 to 1.0
    flags: list[str]          # Machine-readable flags
    evidence: list[EvidenceItem] # Structured key-value explanations
    status: EngineStatus      # SUCCESS, PARTIAL, ERROR, SKIPPED
    error_message: str | None
    metadata: dict[str, Any]
```

#### Engine 1: URLEngine (`url_engine.py`)
* **Input**: `input_data.url`
* **Analysis**:
  - 17 Lexical Heuristics: IP host, `@` credential injection, hyphen density (>=3), suspicious TLDs (`.xyz`, `.top`, `.tk`), shortener domains, URL length deviation (>=75 chars), path length (>=20 chars), subdomain depth (>=2 layers), keywords (`login`, `verify`, `banking`), double-slash open redirect, unencrypted HTTP, non-standard ports, HTTPS in hostname spoofing, Shannon entropy (>=4.0), digit-to-letter ratio (>=0.20), special char overload, base64 payload obfuscation.
  - Domain Age: Asynchronous WHOIS query via `asyncwhois` with strict 2.0s timeout. Domains <14 days old flagged as `newly_registered_domain`.
  - Google Safe Browsing: POST threatMatches query against `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`.
* **Scoring Floor Rule**: GSB-confirmed threat (`gsb_score >= 1.0`) enforces a strict risk floor of 90.0: `combined_score = min(1.0, 0.90 + (lexical * 0.10))`.
* **Confidence**: 0.80 (downgrades to PARTIAL if GSB unconfigured or fails).

#### Engine 2: NLPEngine (`nlp_engine.py`)
* **Input**: `input_data.text`
* **Analysis**: Regex-based natural language social engineering detection across 5 categories:
  - `urgency`: `act now`, `action required`, `urgent`, `urgently`, `immediately`, `within 24 hours`.
  - `credential_request`: Direct credentials (`password`, `passcode`, `login`, `verify your account`) + Action-oriented OTP requests (`share/enter/send/provide/give/submit your otp/one-time code`).
  - `account_suspension`: `suspend`, `suspended`, `suspension`, `locked`, `blocked`, `unauthorized access`, `closing your account`, `deactivated`, `restricted`.
  - `prize_lottery`: `giveaway`, `lottery`, `winner`, `claim your prize`, `free gift`.
  - `unusual_payment`: `gift card`, `wire transfer`, `western union`, `bitcoin`, `crypto`, `apple pay`, `cashapp`.
* **Dual-Layer OTP False-Positive Protection**:
  1. Bare `"otp"` alone does not match. Requires request verbs (`share your otp`).
  2. Negative disclaimer suppression pattern (`OTP_DISCLAIMER_PATTERN`): Matches like `"do not share"`, `"never share"`, `"should not disclose"` suppress any co-occurring OTP flags, ensuring bank 2FA notices score 0.0.
* **Confidence**: 0.70.

#### Engine 3: SenderEngine (`sender_engine.py`)
* **Input**: `input_data.sender_id` + `metadata`
* **Storage**: Local SQLite `backend/data/sender_behavior.db` (`senders` and `sender_name_history` tables).
* **Behavioral Intelligence**:
  - `new_sender`: First time sender address observed (+0.2 score).
  - `rapid_sender_activity`: Message received <60 seconds after previous (+0.3 score).
  - `unusual_frequency`: >10 messages within 1-hour rolling window (+0.2 score).
  - `unusual_time`: Message arrives at an hour never previously used by sender (+0.2 score).
  - `sender_change`: Sender display name observed sending from a different domain (+0.4 score).
  - `out_of_character_link` / `out_of_character_file`: Sender includes links or attachments for the first time after a history of text-only messages (+0.3 score).
* **LRU Table Pruning**: Automatically prunes oldest records when table exceeds 5,000 entries.
* **Confidence**: 0.80 if historical profile exists, 0.50 if new sender.

#### Engine 4: HeaderAnalysisEngine (`header_analysis_engine.py`)
* **Input**: Email headers in `input_data.metadata["headers"]`
* **Anomalies Detected**:
  - `REPLY_TO_MISMATCH`: Reply-To address differs from From address (+0.1 if same domain, +0.3 if cross-domain).
  - `RETURN_PATH_MISMATCH`: Return-Path domain differs from From domain (+0.3).
  - `AUTHENTICATION_FAILURE`: SPF, DKIM, or DMARC authentication fails or soft-fails (+0.4).
  - `MESSAGE_ID_ANOMALY`: Message-ID header missing or domain does not match sender domain (+0.1).
  - `TIMESTAMP_ANOMALY`: Date header differs by >7 days from scan reference time (+0.2).
  - `RECEIVED_CHAIN_ANOMALY`: Received chain headers contain signs of forgery or suspicious hops (+0.3).
* **Safety Floor**: Score capped at 90.0 so header anomalies alone cannot trigger Malware classification.
* **Confidence**: 0.80 if anomalies present, 1.0 if clean.

#### Engine 5: AttachmentBehaviorEngine (`attachment_behavior_engine.py`)
* **Input**: `input_data.file_bytes` + `input_data.file_name`
* **Execution Boundary**: **100% Static Analysis — NEVER executes, loads, or interprets binaries/scripts**.
* **Behavioral Checks**:
  - `EXECUTABLE_ATTACHMENT` (+50.0): PE (`MZ`), ELF, Mach-O, Java class magic bytes, or executable extensions (`.exe`, `.dll`, `.scr`, `.bat`, `.apk`, `.iso`).
  - `SCRIPT_ATTACHMENT` (+45.0): Script extensions (`.vbs`, `.ps1`, `.js`) or shebang magic bytes (`#!`).
  - `DOUBLE_EXTENSION` (+40.0): Deceptive double extensions (`invoice.pdf.exe`) and Right-to-Left Override (RTLO `\u202e`) manipulation.
  - `MACRO_PRESENT` (+40.0): Inspects OOXML ZIP structure for `vbaProject.bin` or OLE2 markers (`AutoOpen`, `_VBA_PROJECT`) without executing.
  - `EMBEDDED_SCRIPT` (+35.0): PDF `/JavaScript`, `/Launch`, OOXML OLE embeddings, RTF object data, HTML script tags.
  - `ATTACHMENT_TYPE_MISMATCH` (+35.0): Discrepancy between declared extension and actual magic bytes.
  - Archive Inspection (ZIP / TAR): Path traversal (`../`), encrypted entries, nesting depth >5 layers (`ARCHIVE_DEPTH_ANOMALY`), decompression ratio >50:1 or >50MB (`ARCHIVE_EXPANSION_ANOMALY` / zip bombs), single executable dropper files.
* **Safety Cap**: Score hard-capped at 85.0 to prevent attachment heuristics alone from claiming definitive Malware without signature confirmation.
* **Confidence**: 0.95 for high-confidence indicators, 0.85 standard.

#### Engine 6: VisualEngine (`visual_engine.py`)
* **Input**: `input_data.image_bytes`
* **Technologies**: OpenCV (`cv2`) and EasyOCR (`gpu=False`).
* **Capabilities**:
  - QR Code Detection: Decodes QR payloads via `cv2.QRCodeDetector()`. Extracts embedded URLs.
  - Optical Character Recognition: Extracts visible text lines with confidence >0.3.
  - Visual Phishing & Fake Login Detection: Analyzes rectangular input fields via Canny edge detection and contour approximation (`2.0 <= aspect_ratio <= 20.0`, `w > 40`, `h > 10`). If input boxes coincide with credential language (`login`, `password`, `verify account`), flags `visual_phishing_detected` (+60.0 score).
* **Sequential Propagation**: Runs first in `UnifiedScanPipeline`. If QR or OCR extracts URLs or text that was not provided in `ScanInput`, dynamically populates `input_data.url` or `input_data.text` for downstream engines!
* **Confidence**: 0.85.

#### Engine 7: MalwareEngine (`malware_engine.py`)
* **Input**: `input_data.file_bytes`
* **Analysis**: SHA-256 hash lookup against VirusTotal v3 REST API (`/api/v3/files/{hash}`).
* **Local Caching**: In-memory `TTLCache(maxsize=1000, ttl=600)` (10-minute TTL) to prevent redundant external API quota usage.
* **Safe Failure Isolation**: If API key is missing, network times out, or HTTP error occurs, returns `status=EngineStatus.ERROR` with `confidence=0.0`. Fusion layer ignores it, ensuring unscanned files are never falsely reported as safe.
* **Confidence**: 0.90 on successful scan, 0.0 on error.

---

### 5.5 Risk Fusion Engine
Located at `backend/app/fusion/risk_fusion.py`:

The fusion engine implements confidence-weighted Bayesian aggregation. It ensures:
1. Skipped (`SKIPPED`) and errored (`ERROR` or `confidence <= 0.0`) engines are completely ignored and listed in `ignored_engines`.
2. Usable engines (`SUCCESS` or `PARTIAL`) contribute based on self-reported confidence and empirical engine reliability:
   $$\text{Weight}_i = \text{Confidence}_i \times \text{Reliability}_i \times \text{StatusFactor}_i$$
   where $\text{StatusFactor} = 1.0$ for `SUCCESS` and $0.5$ for `PARTIAL`.
3. Reliability Factors:
   - `malware_engine`: 1.00
   - `url_engine`: 0.90
   - `visual_engine`: 0.90
   - `nlp_engine`: 0.80
   - `sender_engine`: 0.60
   - Other engines (Header, Attachment): 0.75 default
4. Final Score Formula:
   $$\text{RiskScore} = \frac{\sum (\text{RiskScore}_i \times \text{Weight}_i)}{\sum \text{Weight}_i}$$
5. Aggregate Confidence:
   $$\text{AggregateConfidence} = \min\left(1.0, \frac{\sum \text{Weight}_i}{\sum (\text{Reliability}_i \times \text{StatusFactor}_i)}\right)$$

---

### 5.6 Dynamic Classification Policy & Context Profiles
Located at `backend/app/classification/policy.py`:

Risk scores are deterministically mapped into one of five user-facing categories based on active `ClassificationPolicy`:

```
Score:    0 ----------- 20 ----------- 45 ----------- 70 ----------- 90 ----------- 100
Default:     [ SAFE ]      [SUSPICIOUS]   [ DECEPTIVE ]   [ PHISHING ]    [ MALWARE* ]
```
*\*Requires verified malware signal (`malware_requires_signal=True`), otherwise classifies as Phishing.*

#### Predefined Profiles
1. **`default`**: Standard enterprise profile matching Phase 7 (Safe <20, Suspicious <45, Deceptive <70, Phishing <90, Malware >=90 with malware signal).
2. **`strict`**: Heightened sensitivity for sensitive operations (Safe <15, Suspicious <35, Deceptive <55, Phishing <80, Malware >=80 with malware signal).
3. **`enterprise`**: Zero-trust profile for critical infrastructure (Safe <10, Suspicious <30, Deceptive <50, Phishing <75, Malware >=75 with malware signal).

---

### 5.7 Explainability & Action Recommendation Engine
Located at `backend/app/explainability/explainability_engine.py`:

Translates obscure machine flags into actionable user intelligence:
* **Reason Synthesis**: Translates flags (`vt_malicious`, `high_shannon_entropy`, `ATTACHMENT_TYPE_MISMATCH`) into plain language.
* **Degraded Telemetry Warnings**: If the malware engine fails or was skipped, injects explicit warnings: `"Malware scan unavailable: Anti-malware engine could not complete analysis."`
* **Prescriptive Action Guidance**:
  - **Safe**: *"Proceed with normal caution."* (or *"Proceed with caution. Malware scanning was unavailable for this file."*)
  - **Suspicious**: *"Exercise caution. Do not share sensitive information unless you are certain of the source."*
  - **Deceptive**: *"Do not trust this content. Avoid clicking links or downloading attachments."*
  - **Phishing**: *"Do not click any links or provide credentials. Report and delete this message."*
  - **Malware**: *"Do not open or execute file/link. Isolate and permanently delete the content immediately."*

---

### 5.8 Storage & Evaluation Architecture
Located at `backend/app/database/` and `backend/app/evaluation/`:

1. **`feedback.db` (SQLite)**:
   - Stores user evaluation records: `scan_id` (UUID), `user_feedback` (`positive`/`negative`), `classification_at_scan_time`, `risk_score_at_scan_time`, `confidence_at_scan_time`, `source_type`.
   - Unique index on `scan_id` prevents duplicate feedback vote manipulation.
   - **Zero User Content**: Never stores message text, URLs, file names, or user identities.
2. **`feedback_metrics.py`**:
   - Calculates aggregate metrics: `positive_rate`, `negative_rate`, count by classification, count by source channel, and average risk score.

---

## 6. Level 4 — End-to-End Data Flow Architecture

```
User Action (Share / Gmail / UI)
  │
  ▼
[Android Client: SharedIntentRouter / GmailScanner]
  │ Extracts MIME, validates UTF-8, bounds file to 10 MB
  │ Constructs ScanInput payload
  │
  ▼  HTTP POST /api/scan (Retrofit)
[FastAPI: routes.py -> UnifiedScanPipeline.run]
  │
  ├── 1. Preprocessing (V2Preprocessor)
  │      • Text NFKC & control-char strip
  │      • URL validation & bracket trimming
  │      • File basename traversal sanitization & magic bytes check
  │      • Header metadata bounding (100 items, 30 hops)
  │
  ├── 2. Sequential Visual Extraction (VisualEngine)
  │      • OpenCV QR detection & EasyOCR text reading
  │      • Canny contour fake login detection
  │      • Upstream propagation: populates input.url / input.text if empty
  │
  ├── 3. Safe URL Fetcher (SafeURLFetcher)
  │      • DNS pre-resolution & SSRF IP validation
  │      • Follows redirects with direct IP pinning (max 5 hops)
  │
  ├── 4. Concurrent Engine Execution (EngineRegistry.run_all)
  │      • asyncio.gather() over URL, Malware, NLP, Sender, Header, Attachment engines
  │      • Strict 30.0-second timeout per engine
  │      • Fault isolation via safe_analyze()
  │
  ├── 5. Post-Processing
  │      • If extension_mismatch detected, boosts MalwareEngine score (+30.0)
  │
  ├── 6. Risk Fusion (fuse_engine_results)
  │      • Filters usable engines (SUCCESS / PARTIAL)
  │      • Ignores errored or skipped engines
  │      • Applies reliability weights & status factors
  │      • Calculates composite Risk Score (0–100) & Confidence
  │
  ├── 7. Dynamic Classification Policy (ClassificationPolicy.classify)
  │      • Maps score to Safe / Suspicious / Deceptive / Phishing / Malware
  │      • Enforces malware signal requirement for Malware tier
  │
  ├── 8. Explainability Engine (ExplainabilityEngine.explain)
  │      • Synthesizes human-readable reasons from flags & evidence
  │      • Generates prescriptive recommended action
  │      • Injects top-level warnings for unavailable services
  │
  ▼  Returns UnifiedScanResponse (JSON)
[Android Client: UnifiedScanResponseParser]
  │ Strict schema & type validation
  │
  ├── Saves sanitized record to SQLite (secure_scan_history.db)
  │   • Redacts passwords, OTPs, tokens, emails, phone numbers
  │
  ├── Updates UI (MainActivity)
  │   • Category Badge, Score, Confidence, Reasons, Action, Feedback Thumbs
  │
  └── Background Alerting (if Phishing or Malware)
      • Posts high-priority system notification (SS_ALERTS)
```

---

## 7. Subsystem Deep Dives

### 7.1 Android Share Intent Router
* Intercepts `android.intent.action.SEND` for `text/plain` and `*/*`.
* Supports plain text, direct URLs, and streamed file content URIs.
* Implements streaming buffer reading capped strictly at 10 MB to prevent Android `OutOfMemoryError` (OOM).

### 7.2 Gmail Integration & OAuth Lifecycle
* **Scopes**: Requests exclusively `https://www.googleapis.com/auth/gmail.readonly`.
* **Zero Inbox Mutation**: Does not mark messages as read, archive, delete, or label emails.
* **Extraction**: Decodes multipart MIME trees (text/plain and text/html), strips non-content tags (`<style>`, `<script>`), translates HTML entities, extracts embedded hyperlinks, and formats clean `ScanInput`.
* **Graceful OAuth Failure**: If SHA-1 fingerprint is not configured in Google Cloud Console (Status Code 10), presents an informative developer dialog and offers an instant simulated demo scan.

### 7.3 Background Protection & Threat Alerting
* Registered with Android `WorkManager` as unique periodic work (`ThreatAlertWorker`).
* **Cadence**: 15-minute intervals (Android OS battery-conscious minimum).
* **Constraints**: Requires `NetworkType.CONNECTED` and `BatteryNotLow`.
* **Deduplication**: Maintains a local ring buffer of 500 processed Gmail `messageId`s in `ProcessedMessageStore`.
* **Notification Channel**: `SS_ALERTS` (NotificationManager.IMPORTANCE_HIGH). Tapping the notification deep-links directly to `ScanHistoryActivity` focused on that scan.

### 7.4 Client-Side Sanitized Scan History
* Implemented using `SQLiteOpenHelper` in `ScanHistoryDatabase.kt`.
* Table schema enforces CHECK constraints on classifications, scores (0–100), and sources.
* **`ScanHistorySanitizer`**:
  - Replaces passwords, tokens, API keys, OTPs with `[redacted]`.
  - Replaces URLs with `[link]`, emails with `[address]`, phone numbers with `[number]`.
  - Binds text length to 320 characters and max reasons to 12 items.

### 7.5 User Feedback Loop & Evaluation Metrics
* Allows users to provide binary feedback (thumbs up / thumbs down) on scan accuracy.
* **Concurrency Guard**: `FeedbackSubmissionManager` prevents double-voting via local in-flight sets. Backend enforces `scan_id UNIQUE` constraint and returns HTTP 409 Conflict on duplicate attempts.
* **Telemetry**: `/api/evaluation/metrics` aggregates model precision across URL, File, Share, and Gmail sources.

---

## 8. Security, Privacy & Operational Boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SECURITY BOUNDARY MATRIX                        │
├──────────────────────────┬──────────────────────┬──────────────────────┤
│ Boundary Dimension       │ What Stays on Device │ What Goes to Backend │
├──────────────────────────┼──────────────────────┼──────────────────────┤
│ Credentials & Auth       │ Gmail OAuth tokens   │ None (never sent)    │
│ Raw Email Body           │ Transient in memory  │ Bounded text in POST │
│ Historical Records       │ Sanitized SQLite DB  │ None (stateless)     │
│ User Passwords / OTPs    │ Scrubbed by Regex    │ None (never sent)    │
│ Sensitive Tokens in URL  │ Displayed to user    │ Normalized URL path  │
├──────────────────────────┼──────────────────────┼──────────────────────┤
│ Backend Storage Boundary │ Stored on Backend    │ NOT Stored on Backend│
├──────────────────────────┼──────────────────────┼──────────────────────┤
│ Sender Behavioral Stats  │ Sender metadata only │ Raw email content    │
│ Evaluation Feedback      │ Scan UUID + vote     │ User identity / IP   │
│ Classification Thresholds│ Immutable policy     │ Feedback retuning    │
└──────────────────────────┴──────────────────────┴──────────────────────┘
```

### Critical Operational Guarantees
1. **No Code Execution**: Neither backend nor client executes attachments, macros, or scripts. Analysis is 100% static inspection of structure and headers.
2. **SSRF Resistance**: `SafeURLFetcher` verifies DNS resolutions and rejects internal, loopback, and private addresses prior to opening sockets.
3. **No Dynamic Model Retuning from Feedback**: `apply_feedback_tuning()` throws `PermissionError`. Feedback is stored for offline human analysis only, eliminating adversarial vote poisoning.

---

## 9. External API Integrations

| Service Name | API Version | Endpoint Used | Payload Sent | Failure Fallback Mode |
|---|---|---|---|---|
| **Google Safe Browsing** | v4 REST | `v4/threatMatches:find` | Target URL | Marks `URLEngine` as `PARTIAL`, relies on lexical heuristics. |
| **VirusTotal** | v3 REST | `api/v3/files/{sha256}` | SHA-256 hash | Returns `ERROR` + 0.0 confidence; surfaces top-level warning; ignored in fusion. |
| **Google Sign-In** | Play Services | Native SDK | OAuth Intent | Presents setup dialog with demo scan fallback. |
| **Gmail API** | v1 REST | `users/me/messages` | OAuth Access Token | Fails gracefully; logs error; worker retries on next WorkManager cycle. |
| **WHOIS** | Socket RDAP | Direct socket port 43 | Root domain string | 2.0s timeout; falls back to `None` without degrading engine. |

---

## 10. Error Handling, Fault Tolerance & Resource Limits

| Resource / Layer | Hard Boundary Limit | Enforcement Mechanism | Failure Behavior |
|---|---|---|---|
| **File Upload Size** | 10 MB (10,485,760 bytes) | Client stream buffer + `V2Preprocessor` | HTTP 400 Bad Request / Client rejection |
| **Message Text Length** | 50,000 characters | `normalize_text` | Truncated to 50k chars with warning flag |
| **URL Length** | 4,096 characters | `normalize_url` | Rejected with `url_exceeds_max_length` |
| **Metadata Items** | 100 items | `normalize_email_metadata` | Truncated with warning flag |
| **Received Hops** | 30 hops | `normalize_email_metadata` | Truncated with warning flag |
| **Engine Execution Time** | 30.0 seconds | `asyncio.wait_for` in `EngineRegistry` | Returns `EngineResult.error("Engine timed out")` |
| **WHOIS Query Time** | 2.0 seconds | `asyncio.wait_for` in `URLEngine` | Ignored; domain age treated as unknown |
| **HTTP Request Timeout** | 35.0 seconds | `withTimeout(35000L)` in Android client | Catches `TimeoutCancellationException`, displays UI error |
| **Archive Decompression** | 50 MB / 50:1 ratio | `inspect_archive` | Flags `ARCHIVE_EXPANSION_ANOMALY` |
| **Sender DB Records** | 5,000 rows | `_prune_tables` in `SenderEngine` | LRU deletion of oldest 500 records |

---

## 11. Deployment & Runtime Architecture

* **Backend Runtime**: Python 3.14.x running under Uvicorn ASGI server.
  - Production start command: `uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4`
  - Dependencies: Managed via `backend/requirements.txt` (FastAPI, httpx, easyocr, opencv-python-headless, asyncwhois, tldextract, cachetools, pydantic-settings).
* **Android Runtime**: Android 7.0 (API level 24) through Android 14 (API level 34).
  - Network Configuration: `network_security_config.xml` permits cleartext traffic for local development testing (`10.0.2.2`, `localhost`). Production requires TLS.
  - Background Service: Powered by Android Jetpack WorkManager (`androidx.work:work-runtime-ktx`).

---

## 12. Technology Stack Inventory

### Backend Stack
* **Language & Core**: Python 3.14, FastAPI 0.115+, Uvicorn 0.32+
* **Validation & Settings**: Pydantic v2, Pydantic-Settings
* **Image Processing & Vision**: OpenCV (`opencv-python-headless`), EasyOCR, NumPy, PyTorch
* **Networking & HTTP**: HTTPX (async client with SNI extension support)
* **Domain & Network Telemetry**: AsyncWHOIS, TLDExtract
* **File & Type Sniffing**: Filetype, Python standard `zipfile` & `tarfile`
* **Databases & Caching**: SQLite3, Cachetools (`TTLCache`)
* **Testing Suite**: Pytest, Pytest-AsyncIO (185 automated tests, 259 total with Android)

### Android Stack
* **Language & Architecture**: Kotlin 2.2+, Single-Activity Architecture + Modular Utility Dispatchers
* **Networking & Parsing**: Retrofit 2, OkHttp 3, Gson
* **Background Processing**: AndroidX WorkManager, Coroutines (`Dispatchers.IO`)
* **Persistence**: SQLite (`SQLiteOpenHelper`)
* **Identity & Authentication**: Google Play Services Auth (`GoogleSignInClient`), Google API Client Library for Java (`google-api-services-gmail`)

---

## 13. Key Design Decisions (ADRs)

1. **ADR-01: Dual-Layer OTP Defense Mechanism**
   - *Problem*: Legitimate bank 2FA SMS/emails ("Your OTP is 483920. Do not share it") score as suspicious because they contain the word "OTP".
   - *Decision*: Require request verbs (`share your otp`) AND suppress matches when warning disclaimers (`do not share`) are present.
   - *Result*: Bank warnings score 0.0 while active credential phishing is flagged accurately.

2. **ADR-02: Synchronous SSRF Pinning with SNI**
   - *Problem*: Pre-validating DNS before HTTP client execution introduces Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding vulnerabilities.
   - *Decision*: Resolve DNS to safe IP, connect directly to that IP string, and inject `Host` and TLS `sni_hostname` headers manually.

3. **ADR-03: Two-Phase Visual Pipeline Execution**
   - *Problem*: Running visual analysis purely in parallel with URL/NLP engines prevents extracted QR links and OCR text from benefiting from full engine analysis.
   - *Decision*: VisualEngine runs sequentially first. Extracted text/URLs are fed into `ScanInput` before parallel engine dispatch.

4. **ADR-04: Static-Only Attachment Inspection**
   - *Problem*: Dynamic sandbox execution of attachments is resource-heavy, slow, and poses escape risks on mobile backends.
   - *Decision*: Enforce 100% static structural analysis (ZIP headers, OLE streams, PDF dictionaries) with strict execution boundaries.

5. **ADR-05: Malware Signal Prerequisite for Malware Classification**
   - *Problem*: High cumulative suspicion scores across heuristic engines could misclassify benign files as confirmed malware.
   - *Decision*: ClassificationPolicy enforces that `Malware` classification strictly requires a verified malware signal (`malware_engine` VT hit or malware flag).

---

## 14. Known Limitations & Future Roadmap

* **OCR Latency on CPU**: `EasyOCR` runs on CPU (`gpu=False`). Processing large complex images can take 2–4 seconds on standard hardware.
* **VirusTotal Free API Rate Limits**: VT free API allows 4 requests/minute. The backend mitigates this via a 10-minute TTL cache, but high concurrent file loads will receive `PARTIAL` results.
* **Encrypted Archives**: Password-protected ZIP/TAR archives cannot have their internal contents inspected statically and are flagged as `SUSPICIOUS_ARCHIVE`.
* **Zero-Day Obfuscated JavaScript**: Complex multi-layer polymorphic JavaScript in HTML attachments cannot be executed or sandboxed by design.
* **Future Work**: Integration of local lightweight on-device TFLite models for offline Android scanning, and expanded browser extension plugins.

---

## 15. Implementation vs. Legacy Documentation Discrepancies

During our architectural audit of the active codebase against initial design documents (`ARCHITECTURE_V2.md`, `README.md`), the following discrepancies were identified and resolved:

1. **Legacy Endpoints Removed**: Old docs reference `/api/analyze/message` and `/api/analyze/file`. In the actual codebase, these endpoints and `app/fusion/fusion.py` were deleted in Phase 21 cleanup. The unified pipeline operates exclusively on `POST /api/scan`.
2. **Engine Count**: Early architecture diagrams depicted 5 engines. The implementation contains **7 production engines**, including `HeaderAnalysisEngine` (Phase 16) and `AttachmentBehaviorEngine` (Phase 17).
3. **Feedback Immutability**: Early notes suggested user feedback would automatically retune detection thresholds. The actual implementation forbids runtime retuning via `PermissionError` in `policy.py` to prevent adversarial data poisoning.
4. **Direct REST API Availability**: Early docs listed direct API access as "Not Implemented". The FastAPI backend is fully REST-compliant with formal OpenAPI / Pydantic schemas.

---

## 16. Appendix: Core Repository File Map

```
SecureShield-AI/
├── backend/
│   ├── main.py                                  # FastAPI entry point & exception handlers
│   ├── app/
│   │   ├── api/routes.py                        # /api/scan, /api/feedback, /api/evaluation/metrics
│   │   ├── config/config.py                     # Pydantic settings & env loader
│   │   ├── models/
│   │   │   ├── scan_input.py                    # Universal ScanInput data model
│   │   │   ├── engine_result.py                 # EngineResult, EngineStatus, EvidenceItem
│   │   │   ├── scan_response.py                 # UnifiedScanResponse model & factory
│   │   │   ├── risk_assessment.py               # RiskAssessment & RiskClassification enum
│   │   │   └── feedback.py                      # FeedbackRequest & EvaluationMetrics models
│   │   ├── preprocessing/
│   │   │   ├── v2_preprocessor.py               # Sanitization & normalization pipeline
│   │   │   ├── safe_url_fetcher.py              # Anti-SSRF fetcher & redirect resolver
│   │   │   └── data_prep.py                     # Magic byte sniffing & file type checks
│   │   ├── engines/
│   │   │   ├── base_engine.py                   # BaseEngine abstract interface
│   │   │   ├── registry.py                      # EngineRegistry concurrent runner
│   │   │   ├── pipeline.py                      # UnifiedScanPipeline coordinator
│   │   │   ├── url_engine.py                    # 17 lexical rules + WHOIS + GSB v4
│   │   │   ├── nlp_engine.py                    # Social engineering regex + OTP suppressor
│   │   │   ├── sender_engine.py                 # SQLite historical behavior profiling
│   │   │   ├── header_analysis_engine.py        # SPF/DKIM/DMARC & header anomalies
│   │   │   ├── attachment_behavior_engine.py    # Static macro, script & archive inspection
│   │   │   ├── visual_engine.py                 # OpenCV + EasyOCR QR & fake login detection
│   │   │   └── malware_engine.py                # VirusTotal v3 SHA-256 API & TTL cache
│   │   ├── fusion/
│   │   │   └── risk_fusion.py                   # Confidence-weighted Bayesian aggregation
│   │   ├── classification/
│   │   │   └── policy.py                        # Default/Strict/Enterprise policy engine
│   │   ├── explainability/
│   │   │   └── explainability_engine.py         # Reason mapping & actionable prescriptions
│   │   ├── database/
│   │   │   └── feedback.py                      # SQLite feedback persistence (feedback.db)
│   │   └── evaluation/
│   │       └── feedback_metrics.py              # Precision, recall, and source metrics
├── android/
│   └── app/src/main/
│       ├── AndroidManifest.xml                  # Permissions, Activities, Intent filters
│       └── java/com/secureshield/ai/
│           ├── MainActivity.kt                  # UI, scanning coordinator, feedback buttons
│           ├── ScanHistoryActivity.kt           # Paginated history UI & record inspector
│           ├── GmailScanner.kt                  # Google Sign-In & unread email fetcher
│           ├── GmailMessageExtractor.kt         # MIME parser & clean text extractor
│           ├── GmailEmailScanDispatcher.kt      # Sequential email scan queue
│           ├── GmailOAuthOutcome.kt             # OAuth state machine & failure mapper
│           ├── network/
│           │   └── ApiClient.kt                 # Retrofit client & response parser
│           ├── background/
│           │   ├── BackgroundProtectionManager.kt# WorkManager periodic job scheduler
│           │   ├── ThreatAlertWorker.kt         # CoroutineWorker for background checks
│           │   ├── BackgroundScanner.kt         # Deduplicating background scanner
│           │   └── ProcessedMessageStore.kt     # Ring-buffer store of scanned message IDs
│           ├── history/
│           │   ├── ScanHistoryDatabase.kt       # SQLite database (secure_scan_history.db)
│           │   ├── ScanHistoryRecord.kt         # Entity model & ScanHistorySanitizer
│           │   └── ScanHistoryRepository.kt     # Repository abstraction for history queries
│           ├── feedback/
│           │   └── FeedbackSubmissionManager.kt # Concurrency-safe feedback dispatcher
│           └── share/
│               └── SharedIntentRouter.kt        # Android Share sheet intent dispatcher
└── documentation/
    └── ARCHITECTURE_V2.md                       # Initial design specification (historical)
