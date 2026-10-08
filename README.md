# SecureShield AI

SecureShield AI is an intelligent mobile and email security platform consisting of a native Android client application and a modular FastAPI threat-detection backend. It provides multi-layered threat detection for shared URLs, uploaded files, real-time screen content (Guardian Mode), and user-authorized Gmail messages.

---

## 1. Project Overview

SecureShield AI protects users against phishing, malware, deceptive messaging, and email spoofing. It combines lightweight client-side protection with a multi-engine backend analysis pipeline, aggregating threat signals into clear risk scores (0–100), classifications, explainable reasons, and actionable security recommendations.

---

## 2. Main Capabilities

- **Global Share Target**: Accepts text, links, and files shared directly from any Android app via system share sheets.
- **Guardian Mode**: Accessibility-powered real-time protection detecting suspicious links and malicious content in active apps.
- **Gmail Intelligence**: On-demand and background scanning of unread Gmail messages using read-only Google OAuth scopes.
- **Background Protection**: Privacy-conscious background inbox monitoring via Android `WorkManager` with actionable alerts.
- **Multi-Engine Detection**: 7 specialized detection engines analyzing URLs, file payloads, text semantics, sender patterns, headers, attachments, and visual brand spoofing.
- **Fusion & Explainability**: Weighted risk score aggregation (0–100), categorical classification, evidence summaries, and clear mitigation advice.
- **Local Scan History**: Fully offline local SQLite storage for past scan results with filtering and deletion support.
- **User Feedback & Evaluation**: Anonymous scan-bound feedback reporting to track aggregate system performance metrics.

---

## 3. Architecture Overview

```mermaid
graph TD
    subgraph Android Client
        A[User Input / Share Sheet] --> G[MainActivity / ShareActivity]
        B[Active Apps] --> H[GuardianAccessibilityService]
        C[Gmail Inbox] --> I[GmailSyncWorker / WorkManager]
        G & H & I --> J[ApiClient]
    end

    subgraph FastAPI Backend
        J --> K["/api/scan Endpoint"]
        K --> L[V2 Preprocessor & Normalizer]
        L --> M[Concurrent Detection Engines]
        
        subgraph Detection Engines
            M --> E1[Lexical & URL Engine]
            M --> E2[Malware Engine]
            M --> E3[NLP Engine]
            M --> E4[Sender Behavior Engine]
            M --> E5[Header Analysis Engine]
            M --> E6[Attachment Engine]
            M --> E7[Visual Engine]
        end
        
        E1 & E2 & E3 & E4 & E5 & E6 & E7 --> N[Risk Fusion Layer]
        N --> O[Dynamic Classification Profile]
        O --> P[Explainability Generator]
        P --> Q[Unified Scan Response]
    end

    Q --> J
```

---

## 4. Android Application

The Android client is built with Kotlin and target SDK 34 (Android 14), with support back to Android 7.0 (API 24).

### Key Components
- **`MainActivity`**: Primary dashboard for direct URL/text scanning, scan results display, and navigation.
- **`ShareActivity`**: Global intent filter (`android.intent.action.SEND`) handling links and file shares from third-party apps.
- **`GuardianAccessibilityService`**: Real-time overlay alert system scanning URLs surfaced in active apps.
- **`GmailSyncWorker`**: WorkManager background job running periodic scans on new unread messages.
- **`ScanHistoryManager`**: Local SQLite database (`secure_scan_history.db`) for offline history viewing.
- **`ApiClient`**: Network client interacting with the FastAPI `/api/scan` and `/api/feedback` endpoints.

---

## 5. FastAPI Backend

The backend is built with Python 3.10+ and FastAPI, designed for high-concurrency asynchronous evaluation.

### Core Modules
- **`app/api/`**: API routes including `/api/scan`, `/api/feedback`, `/api/evaluation/metrics`, and `/health`.
- **`app/preprocessing/`**: Input sanitization, Unicode NFKC normalization, URL unshortening, and file bounds enforcement.
- **`app/engines/`**: 7 independent threat detection engine implementations.
- **`app/fusion/`**: Risk fusion algorithm calculating weighted threat scores and confidence levels.
- **`app/classification/`**: Dynamic classification profiles (`default`, `strict`, `enterprise`) mapping risk scores to categories: `Safe`, `Suspicious`, `Deceptive`, `Phishing`, `Malware`.
- **`app/explainability/`**: Rule-based narrative engine converting technical flags into user-friendly explanations.

---

## 6. Detection Engines

| Engine | Primary Function | Data Sources / Techniques |
| :--- | :--- | :--- |
| **Lexical & URL** | URL structure and reputation analysis | Heuristics, entropy analysis, Google Safe Browsing API |
| **Malware** | File payload inspection | Magic bytes validation, hash extraction, VirusTotal API |
| **NLP** | Social engineering & phishing intent | Urgency detection, credential lure patterns, keyword matching |
| **Sender Behavior** | Anomaly detection in sender behavior | Privacy-preserving SQLite behavioral state, frequency checks |
| **Header Analysis** | Email authentication and spoofing | SPF, DKIM, DMARC verification, Received hop analysis |
| **Attachment** | Static attachment safety | Static structure inspection, double-extension & RTLO detection, macro check |
| **Visual** | Phishing brand impersonation | Visual DOM similarity and favicon/brand impersonation heuristics |

---

## 7. How to Run Locally

### Backend Setup
1. **Prerequisites**: Python 3.10+ installed.
2. **Navigate to backend**:
   ```bash
   cd backend
   ```
3. **Create & activate virtual environment**:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux / macOS:
   source .venv/bin/activate
   ```
4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
5. **Configure environment variables**:
   Create a `.env` file from `.env.example`:
   ```env
   GOOGLE_SAFE_BROWSING_API_KEY=your_key_here  # Optional (graceful fallback)
   VIRUSTOTAL_API_KEY=your_key_here            # Optional (graceful fallback)
   ENVIRONMENT=development
   ```
6. **Start the backend server**:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```
   Or use the root convenience script: `.\start_backend.bat` (Windows).

### Android Client Setup
1. Open the `android/` directory in Android Studio.
2. Ensure Android 14 (API 34) SDK is installed.
3. Set the backend URL in `android/local.properties` (or use default `http://10.0.2.2:8000/` for emulator):
   ```properties
   BASE_URL="http://10.0.2.2:8000/"
   ```
4. Build and run on an Android device or emulator:
   ```bash
   cd android
   .\gradlew assembleDebug
   ```

---

## 8. Production & Cloud Backend

- **Live Production URL**: `https://secureshield-ai-production.up.railway.app`
- **Health Endpoint**: `https://secureshield-ai-production.up.railway.app/health`
- **Deployment Platform**: Railway (auto-deployed on push to `main`).
- **CI/CD**: GitHub Actions workflow (`.github/workflows/android-ci.yml`) automatically builds the Android APK and runs test suites on every pull request and push.

---

## 9. Testing

### Running Backend Tests
```bash
cd backend
python -m pytest app/tests -v --tb=short
```

### Running Android Tests
```bash
cd android
.\gradlew test
```

### Full Clean Build Verification
```bash
cd android
.\gradlew clean test assembleDebug
```

---

## 10. Project Structure

```text
SecureShield-AI/
├── .github/
│   └── workflows/
│       └── android-ci.yml        # CI build and automated test workflow
├── android/
│   ├── app/                      # Android application module (Kotlin)
│   │   ├── src/main/java/com/secureshield/ai/
│   │   │   ├── accessibility/    # Guardian Mode accessibility service
│   │   │   ├── background/       # WorkManager background Gmail scanning
│   │   │   ├── feedback/         # User feedback submission logic
│   │   │   ├── history/          # Local SQLite scan history repository
│   │   │   ├── network/          # Retrofit / ApiClient network layer
│   │   │   └── share/            # Android Share Target intent receiver
│   │   └── build.gradle.kts      # Android app build configuration
│   └── build.gradle.kts          # Top-level Gradle configuration
├── backend/
│   ├── app/
│   │   ├── api/                  # FastAPI endpoints & routes
│   │   ├── classification/       # Dynamic risk classification profiles
│   │   ├── config/               # Settings & environment configuration
│   │   ├── database/             # SQLite state & database access
│   │   ├── engines/              # 7 modular detection engines
│   │   ├── evaluation/           # Feedback & evaluation metrics
│   │   ├── explainability/       # Human-readable explanation generation
│   │   ├── fusion/               # Risk score fusion algorithms
│   │   ├── models/               # Pydantic data schemas & interfaces
│   │   ├── preprocessing/        # Input sanitization & normalization
│   │   └── tests/                # Pytest unit & integration test suite
│   ├── data/                     # SQLite database storage directory
│   ├── main.py                   # FastAPI application entry point
│   └── requirements.txt          # Python dependencies
├── documentation/
│   ├── API.md                    # REST API endpoint reference & schemas
│   ├── ARCHITECTURE.md           # Detailed architecture & engine pipeline
│   ├── DEPLOYMENT.md             # Cloud deployment & CI/CD guides
│   └── DEVELOPMENT.md            # Local setup, testing & signing guide
├── .env.example                  # Environment variable template
├── .gitignore                    # Git ignore rules
├── DEMO_SCRIPT.md                # Demonstration script for evaluations
├── DEPLOYMENT.md                 # Root deployment summary
├── README.md                     # Project overview & quick start guide
├── start_backend.bat             # Windows batch startup script
└── start_backend.ps1             # PowerShell startup script
```
