# V1 BASELINE — Dependencies

**Snapshot Date**: 2026-09-28

---

## Backend (Python)

**Source**: `backend/requirements.txt`  
**Runtime**: Python 3.10+ (uses `str | None` union syntax)

| Package | Purpose |
|---|---|
| `fastapi` | Web framework — async API routing, request validation, OpenAPI docs |
| `uvicorn` | ASGI server — runs FastAPI in development and production |
| `python-dotenv` | Loads `.env` file into environment variables |
| `pydantic` | Data validation and serialization for request/response models |
| `pydantic-settings` | Settings management — reads env vars with type validation |
| `httpx` | Async HTTP client — external API calls (GSB, VirusTotal), URL resolution |
| `filetype` | File magic-byte detection — identifies actual file type regardless of extension |
| `cachetools` | TTLCache for VirusTotal results (10-min, 1000 items) |
| `python-multipart` | Multipart form parsing — required for file upload endpoint |

> **Note**: No version pins exist in V1. All packages install latest compatible versions.

---

## Android (Kotlin)

**Source**: `android/app/build.gradle.kts`

### Build Toolchain

| Tool | Version |
|---|---|
| Android Gradle Plugin (AGP) | 9.4.1 |
| Kotlin | 2.2.10 |
| Java compatibility | 17 |
| Compile SDK | 34 (Android 14) |
| Min SDK | 24 (Android 7.0) |
| Target SDK | 34 (Android 14) |

### AndroidX & UI

| Dependency | Version | Purpose |
|---|---|---|
| `androidx.core:core-ktx` | 1.12.0 | Kotlin extensions for Android core |
| `androidx.appcompat:appcompat` | 1.6.1 | Backward-compatible Activity/Fragment APIs |
| `com.google.android.material:material` | 1.11.0 | Material Design components |
| `androidx.constraintlayout:constraintlayout` | 2.1.4 | Flexible layout system |

### Networking

| Dependency | Version | Purpose |
|---|---|---|
| `com.squareup.retrofit2:retrofit` | 2.9.0 | Type-safe HTTP client for API calls |
| `com.squareup.retrofit2:converter-gson` | 2.9.0 | JSON serialization via Gson |
| `com.squareup.okhttp3:okhttp` | 4.12.0 | HTTP transport layer |

### Coroutines & Async

| Dependency | Version | Purpose |
|---|---|---|
| `org.jetbrains.kotlinx:kotlinx-coroutines-android` | 1.7.3 | Coroutine support for Android main thread |
| `org.jetbrains.kotlinx:kotlinx-coroutines-play-services` | 1.7.3 | Coroutine adapters for Play Services Tasks |

### Google Services

| Dependency | Version | Purpose |
|---|---|---|
| `com.google.android.gms:play-services-auth` | 21.0.0 | Google Sign-In SDK |
| `com.google.api-client:google-api-client-android` | 2.2.0 | Google API client for Android |
| `com.google.apis:google-api-services-gmail` | v1-rev20220404-2.0.0 | Gmail API Java client |

### Android Permissions (Manifest)

| Permission | Purpose |
|---|---|
| `INTERNET` | Network access for backend API calls |
| `ACCESS_NETWORK_STATE` | Check network connectivity |
| `READ_EXTERNAL_STORAGE` (max SDK 32) | Legacy file access |
| `READ_MEDIA_IMAGES` | Media file access (Android 13+) |
| `READ_MEDIA_VIDEO` | Media file access (Android 13+) |
| `POST_NOTIFICATIONS` | Push notification permission (Android 13+) |

---

## Databases (Embedded)

| Database | Engine | Created By |
|---|---|---|
| `backend/data/sender_behavior.db` | SQLite 3 | `sender_engine.py` — auto-created on import |
| `backend/data/feedback.db` | SQLite 3 | `feedback.py` — auto-created on import |

---

## External Services (API Keys Required)

| Service | Config Variable | Required |
|---|---|---|
| Google Safe Browsing API v4 | `GOOGLE_SAFE_BROWSING_API_KEY` | Optional — pipeline degrades gracefully |
| VirusTotal API v3 | `VIRUSTOTAL_API_KEY` | Optional — pipeline degrades gracefully |
| Google OAuth (Gmail) | Google Cloud Console SHA-1 registration | Optional — app falls back to demo mode |
