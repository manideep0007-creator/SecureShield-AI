# SecureShield AI

SecureShield AI is an end-to-end mobile security platform consisting of an Android client application and a modular Python (FastAPI) intelligence backend. It scans shared URLs/files and user-authorized unread Gmail messages through a highly modular threat-detection pipeline.

## Current Features
*   **Android Share Protocol Integration**: The Android app acts as a global implicit intent receiver for text and files, scanning inputs seamlessly.
*   **Gmail Intelligence**: Users can authorize Google OAuth to scan unread messages on demand, extracting headers, MIME text, and embedded URLs safely.
*   **Modular Detection Pipeline**: 
    *   **Lexical & URL Engine**: Applies offline heuristic checks and queries Google Safe Browsing API.
    *   **Malware Engine**: Identifies file type spoofing via Magic Bytes and hashes payloads against VirusTotal API v3.
    *   **NLP Engine**: Classifies raw message text using category patterns focusing on Social Engineering constraints.
    *   **Sender Behavior Engine**: A stateful anomaly tracker (via SQLite) identifying unusual sending patterns.
*   **Fusion & Explainability Layer**: Calculates confidence-weighted averages to assign scores (0-100) and distinct categories: Safe, Suspicious, Deceptive, Phishing, Malware. Translates flags into human-readable actions.
*   **Feedback Evaluation**: Scan-bound positive/negative feedback is stored locally in SQLite and summarized through read-only evaluation metrics. Metrics are measurement data, not a model-accuracy claim or automatic retuning signal.
*   **Secure Scan History**: Completed scan result metadata is stored locally for paginated browsing, details, and local deletion; scans still use the existing backend pipeline.

## Project Structure
```text
SecureShield AI/
├── documentation/       # Architecture maps, project audits, and baselines
├── backend/             # Python FastAPI backend
│   ├── app/             # V2 Application core 
│   │   ├── api/         # FastAPI router and endpoints
│   │   ├── config/      # Settings and environment configs
│   │   ├── database/    # SQLite persistence logic
│   │   ├── engines/     # Detection modules 
│   │   ├── explainability/ # Narrative logic (Planned)
│   │   ├── fusion/      # Risk aggregation
│   │   ├── models/      # Engine interfaces and Pydantic models
│   │   ├── preprocessing/ # URL resolution & sanitization
│   │   └── tests/       # Pipeline tests
│   ├── data/            # Local SQLite database files
│   └── main.py          # Uvicorn entry point
├── android/             # Kotlin Android client application
│   └── app/             # Application source (Activities, Network models, XML layouts)
└── .env.example         # Environment variable template
```

## How to Run Backend
1. Ensure Python 3.10+ is installed.
2. Navigate to the backend directory:
   ```bash
   cd backend
   ```
3. Prepare the environment (optional but recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Configure environment variables (see below).
6. Start the development server:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

## How to Run Android App
1. Open the `/android` directory in Android Studio.
2. Ensure you have the SDK for Android 14 (API 34) installed.
3. Sync Gradle files.
4. Set up an emulator or connect a physical device (min SDK 24).
5. Ensure your backend is running. If running the emulator, the app defaults to `http://10.0.2.2:8000/`. If running on a physical device, define your backend's local network IP in `android/local.properties` (e.g., `BASE_URL="http://192.168.x.x:8000/"`).
6. Click **Run** in Android Studio to build and deploy the APK.

## Gmail Intelligence Setup
1. In Google Cloud Console, create or select a project and enable the Gmail API.
2. Configure the OAuth consent screen for the intended test or production audience. Add only the Gmail read-only scope: `https://www.googleapis.com/auth/gmail.readonly`.
3. Create an Android OAuth client for package `com.secureshield.ai`. Register the SHA-1 signing certificate used by the installation; for local debug builds, obtain it with `cd android` then `gradlew signingReport`.
4. Install the app and choose **Connect Gmail & Scan Inbox**. Google Sign-In requests the Gmail read-only permission, fetches up to 20 unread messages, and passes each supported message through the existing `/api/scan` client.

The app does not store OAuth tokens or client secrets itself. Google Play Services and `GoogleAccountCredential` manage the signed-in account and refreshable authorization. SecureShield requests full message text and headers only; it does not mark messages as read, download attachments, or request send/modify Gmail scopes. Messages without a supported readable body are skipped and reported.

Gmail parsing, OAuth outcome mapping, unread-fetch behavior, and one-scan-per-message dispatch have local JVM tests with fake Gmail API responses. They do not require a Google account or credentials:

```bash
cd android
gradlew test
gradlew clean test assembleDebug
```

## Phase 12 Feedback and Evaluation
After a scan completes, the existing thumbs controls submit only the scan UUID, positive/negative choice, classification, risk score, confidence, and source type (`url`, `file`, `share`, `gmail`, or `unknown`). The feedback is tied to that exact scan; duplicate submissions are blocked in the app and rejected by a unique SQLite scan-ID index. A failed submission leaves the scan result and feedback controls available for retry. The API accepts the earlier Phase 9 feedback request shape only when its `analyzed_target` is a scan UUID.

Feedback extends the existing `backend/data/feedback.db` table with normalized scan-time fields. The legacy `target` column receives only the scan UUID for new records. Email bodies, URLs, file contents, attachments, OAuth data, credentials, and tokens are not included in feedback requests. Existing legacy rows are preserved and are not returned by metrics.

`POST /api/feedback` validates and stores a record, returning HTTP 409 for duplicate scan IDs. `GET /api/evaluation/metrics` returns aggregate counts/rates, counts by classification and source, per-classification positive/negative summaries, and average risk scores split by feedback value. It returns zero counts and rates for an empty database. The endpoint does not expose scan IDs or content. Feedback metrics measure user responses and do not establish detection accuracy or modify risk scoring/classification.

Run backend tests from `backend/` with `python -m pytest app/tests`. Android feedback tests use local fake responses and can be run from `android/` with `gradlew test`; no Gmail account or live backend is required.

## Phase 13 Scan History
History is a local Android `SQLiteOpenHelper` database (`secure_scan_history.db`) written asynchronously after a valid `/api/scan` response. It stores only scan ID, timestamp, source type, classification, risk score, confidence, recommended action, sanitized reasons, machine flags/evidence keys, and an optional local feedback state. It does not store input text, Gmail content, URLs, file/attachment bytes, evidence values, credentials, or tokens. History remains available when the backend is offline.

The history screen loads 25 newest records at a time, with additional pages on request. Classification/source filters and scan-ID lookup are supported by the local repository. Deleting one or all history rows affects only `secure_scan_history.db`; Phase 12 feedback remains independently stored in the backend feedback database and evaluation metrics. A feedback marker in history is only a local display association and is removed with its history row; deleting history never deletes or changes the backend feedback record.

SQLite schema upgrades are additive and preserve existing local tables/rows. Scan IDs are unique, timestamp/classification/source indexes support retrieval, and malformed summary JSON is ignored safely. JVM tests use a fake store for repository behavior and SQLite JDBC to execute the production schema/migration SQL against a local test file; no accounts or external services are used. Run them with `cd android && gradlew clean test assembleDebug`; run backend regressions separately with `cd backend && python -m pytest app/tests`.

## Environment Variables Required
To run the backend engines with full functionality, create a `.env` file in the root or `backend/` directory by copying `.env.example`:

```env
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ENVIRONMENT=development
```
*(Note: If API keys are omitted, the engines degrade gracefully and bypass the external lookups without crashing the pipeline.)*
