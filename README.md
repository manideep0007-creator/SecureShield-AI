# SecureShield AI

SecureShield AI is an end-to-end mobile security platform consisting of an Android client application and a modular Python (FastAPI) intelligence backend. It intercepts user communications (shared URLs, files, and background Gmail sweeps) and pushes them through a highly modular threat-detection pipeline.

## Current Features
*   **Android Share Protocol Integration**: The Android app acts as a global implicit intent receiver for text and files, scanning inputs seamlessly.
*   **Gmail API Polling**: Users can authenticate via Google OAuth to scan unread emails, extracting headers, body content, and embedded URLs safely.
*   **Modular Detection Pipeline**: 
    *   **Lexical & URL Engine**: Applies offline heuristic checks and queries Google Safe Browsing API.
    *   **Malware Engine**: Identifies file type spoofing via Magic Bytes and hashes payloads against VirusTotal API v3.
    *   **NLP Engine**: Classifies raw message text using category patterns focusing on Social Engineering constraints.
    *   **Sender Behavior Engine**: A stateful anomaly tracker (via SQLite) identifying unusual sending patterns.
*   **Fusion & Explainability Layer**: Calculates confidence-weighted averages to assign scores (0-100) and distinct categories: Safe, Suspicious, Deceptive, Phishing, Malware. Translates flags into human-readable actions.
*   **Feedback System**: In-app Thumbs Up / Thumbs Down mechanism fed into a local SQLite database for future metric evaluation.

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

## Environment Variables Required
To run the backend engines with full functionality, create a `.env` file in the root or `backend/` directory by copying `.env.example`:

```env
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ENVIRONMENT=development
```
*(Note: If API keys are omitted, the engines degrade gracefully and bypass the external lookups without crashing the pipeline.)*
