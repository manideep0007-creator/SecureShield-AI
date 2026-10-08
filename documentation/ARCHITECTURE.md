# SecureShield AI — System Architecture

## 1. High-Level Architecture

SecureShield AI is an end-to-end mobile threat detection platform consisting of a Kotlin Android application and a modular Python (FastAPI) intelligence backend.

```mermaid
graph TD
    subgraph Client ["Android Client (Kotlin)"]
        UI["UI Layer / Dashboard"]
        Guard["Guardian Mode (Accessibility)"]
        Share["Share Sheet Router"]
        Gmail["Gmail Inbox Sync"]
        Store["Local SQLite Scan History"]
        ApiClient["Retrofit / OkHttp ApiClient"]
    end

    subgraph Backend ["Intelligence Backend (FastAPI)"]
        Router["/api/scan Router"]
        Pre["V2 Preprocessor & Sanitizer"]
        Pipe["Detection Pipeline Dispatcher"]
        
        subgraph Engines ["Multi-Engine Detection Suite"]
            E1["URL & Heuristic Engine"]
            E2["Malware & Magic Bytes Engine"]
            E3["Social Engineering NLP Engine"]
            E4["Sender Behavior Engine"]
            E5["Email Header Analysis Engine"]
            E6["Attachment Static Analyzer"]
            E7["QR & OCR Visual Scanner"]
        end

        Fusion["Risk Fusion Aggregator"]
        Explain["Explainability & Recommendation Layer"]
        Policy["Dynamic Classification Policy"]
    end

    Guard -->|Real-Time Text/URLs| ApiClient
    Share -->|Shared Files/Links| ApiClient
    Gmail -->|Inbox Messages| ApiClient
    UI -->|Manual Text/URL| ApiClient

    ApiClient -->|HTTP POST /api/scan| Router
    Router --> Pre
    Pre --> Pipe
    Pipe --> E1 & E2 & E3 & E4 & E5 & E6 & E7
    E1 & E2 & E3 & E4 & E5 & E6 & E7 --> Fusion
    Fusion --> Policy
    Policy --> Explain
    Explain -->|UnifiedScanResponse| ApiClient
    ApiClient --> UI
    ApiClient --> Store
```

---

## 2. Detection Pipeline Lifecycle

1. **Ingestion & Sanitization (`backend/app/preprocessing/`):**
   - Normalizes unicode, decodes obfuscated URLs, bounds payload sizes, strips unsafe control characters.
   - Extracts nested URLs and metadata structures safely.

2. **Parallel Engine Execution (`backend/app/engines/`):**
   - Every active detection engine implements `BaseEngine`.
   - Engines execute concurrently with timeout bounding and isolated failure recovery.

3. **Risk Fusion & Scoring (`backend/app/fusion/`):**
   - Calculates a confidence-weighted threat score (0.0 to 100.0) from contributing engine results.
   - Applies deterministic category thresholds: `Safe`, `Suspicious`, `Deceptive`, `Phishing`, `Malware`.

4. **Explainability & Actions (`backend/app/explainability/`):**
   - Translates machine flags into human-readable evidence summaries.
   - Generates actionable safety advice (e.g., *"Do not enter login credentials on this domain"*).

---

## 3. Multi-Engine Detection Suite

| Engine | Primary Function | Key Indicators Detected |
| :--- | :--- | :--- |
| **URL Engine** | Heuristic URL analysis & reputation lookup | IP-based hosts, punycode spoofing, high-risk TLDs, Google Safe Browsing. |
| **Malware Engine** | Static binary validation | Extension vs Magic-byte mismatches, executable payloads, VirusTotal v3 lookup. |
| **NLP Engine** | Social engineering & linguistic analysis | Credential harvesting patterns, urgent threats, financial coercion, fake security alerts. |
| **Sender Behavior** | Historical sender anomaly tracking | First-time unseen senders, sudden volume spikes, domain divergence. |
| **Header Engine** | Email authentication verification | SPF / DKIM / DMARC failures, spoofed `From` vs `Return-Path` headers. |
| **Attachment Engine** | Static document & archive safety | Double extensions, VBA macros, embedded script elements, zip bomb structures. |
| **Visual Engine** | QR decoding & OCR extraction | Embedded phishing URLs in images, fake login screenshots, credential forms. |

---

## 4. Android Client Architecture

The Android application is organized into modular packages:

- **`accessibility/`**: `UniversalLinkGuardService` monitors on-screen window content in real time with content-hash debouncing and rate limiting.
- **`network/`**: `ApiClient` and `ServerSettings` manage Retrofit communication, runtime server switching, and health probes.
- **`history/`**: `ScanHistoryDatabase` provides SQLite local caching of past verdicts without storing sensitive raw user data.
- **`background/`**: `ThreatAlertWorker` executes periodic WorkManager sync for unread inbox threat analysis.
- **`feedback/`**: `FeedbackSubmissionManager` coordinates positive/negative scan verdict telemetry.
- **`share/`**: `SharedIntentRouter` handles implicit share intents from external apps (WhatsApp, Chrome, Gmail).
