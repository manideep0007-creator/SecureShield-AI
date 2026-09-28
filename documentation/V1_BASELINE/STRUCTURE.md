# V1 BASELINE — Project Structure

**Snapshot Date**: 2026-09-28

---

## Root

```
SecureShield AI/
├── README.md                         # Project overview & architecture docs
├── DEMO_SCRIPT.md                    # 3-minute live demo script
├── PROJECT_AUDIT.md                  # Project audit report
├── V1_BASELINE/                      # ← This baseline snapshot (docs only)
│
├── backend/                          # Python FastAPI backend
│   ├── main.py                       # App entry point — FastAPI + Uvicorn
│   ├── requirements.txt              # Python dependencies (9 packages)
│   │
│   ├── api/
│   │   └── routes.py                 # 3 API endpoints (message, file, feedback)
│   │
│   ├── core/
│   │   └── config.py                 # Pydantic Settings — env vars, API keys
│   │
│   ├── engines/
│   │   ├── url_engine.py             # URL lexical heuristics + Google Safe Browsing
│   │   ├── malware_engine.py         # SHA-256 → VirusTotal v3 hash lookup
│   │   ├── nlp_engine.py             # Regex-based social engineering classifier
│   │   ├── sender_engine.py          # SQLite sender behavior anomaly tracker
│   │   ├── fusion.py                 # Weighted score aggregation + explainability
│   │   └── feedback.py               # User feedback persistence (SQLite)
│   │
│   ├── preprocessing/
│   │   └── data_prep.py              # URL redirect resolution + file magic-byte check
│   │
│   ├── security/
│   │   └── safe_url_fetcher.py       # SSRF-resistant URL fetcher (DNS rebind protection)
│   │
│   ├── data/
│   │   ├── sender_behavior.db        # SQLite — sender history tracking
│   │   └── feedback.db               # SQLite — user feedback storage
│   │
│   └── tests/
│       └── test_pipeline.py          # 5 end-to-end pipeline tests (mocked APIs)
│
└── android/                          # Android client (Kotlin)
    ├── build.gradle.kts              # Root Gradle — AGP 9.4.1, Kotlin 2.2.10
    ├── settings.gradle.kts           # Project settings, repository config
    ├── gradle.properties             # AndroidX, config-cache flags
    ├── local.properties              # Local SDK path + BASE_URL override
    ├── gradlew / gradlew.bat         # Gradle wrapper scripts
    │
    ├── gradle/
    │   ├── gradle-daemon-jvm.properties
    │   └── wrapper/
    │       └── gradle-wrapper.properties
    │
    └── app/
        ├── build.gradle.kts          # App-level — SDK 24-34, dependencies, buildConfig
        │
        └── src/main/
            ├── AndroidManifest.xml   # Permissions, share-intent filters, activity
            │
            ├── java/com/secureshield/ai/
            │   ├── MainActivity.kt       # UI controller — intents, scanning, feedback, notifications
            │   ├── GmailScanner.kt       # Gmail API client — fetches latest unread email
            │   └── network/
            │       └── ApiClient.kt      # Retrofit singleton + API interface + data classes
            │
            └── res/
                ├── layout/
                │   └── activity_main.xml     # Single-screen layout (badge, score, reasons, feedback)
                ├── values/
                │   └── strings.xml           # App name string resource
                ├── drawable/
                │   ├── ic_launcher_background.xml
                │   └── ic_launcher_foreground.xml
                └── mipmap-anydpi-v26/        # Adaptive icon resources
```

---

## Key Architecture Notes

- **No standalone web frontend** — the Android app is the sole client
- **Single Activity** architecture — `MainActivity` handles all UI flows
- **Backend runs standalone** — `uvicorn main:app` on port 8000
- **Emulator default** — Android `BASE_URL` defaults to `http://10.0.2.2:8000/` (Android emulator localhost)
- **SQLite databases** are colocated in `backend/data/`, auto-created on first import
- **No containerization** — no Dockerfile, docker-compose, or CI/CD config exists at V1
