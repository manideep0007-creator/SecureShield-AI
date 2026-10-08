# SecureShield AI — Local Development & Testing Guide

This guide describes how to set up, run, and test the SecureShield AI backend and Android client locally.

---

## 1. Backend Setup (FastAPI / Python)

### Prerequisites
- Python 3.10, 3.11, or 3.12
- pip package manager

### Installation & Run
```bash
# 1. Navigate to backend directory
cd backend

# 2. Create and activate virtual environment
python -m venv .venv
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio httpx

# 4. Start the development server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Running Backend Tests
```bash
cd backend
python -m pytest app/tests -v --tb=short
```

---

## 2. Android Client Setup (Kotlin / Gradle)

### Prerequisites
- Android Studio Hedgehog (or newer)
- Android SDK 34 (Android 14)
- JDK 17

### Building & Running
1. Open the `/android` directory in Android Studio.
2. Allow Gradle to synchronize dependencies.
3. Select an emulator or physical device with USB debugging enabled.
4. Click **Run** (`Shift + F10`).

### Running Android Unit Tests
```bash
cd android
./gradlew test --stacktrace
```

### Building Debug APK Locally
```bash
cd android
./gradlew assembleDebug
```
Output APK location:
`android/app/build/outputs/apk/debug/app-debug.apk`

---

## 3. Signing Keystore & Google OAuth Info

The project uses a bundled, deterministic `android/app/debug.keystore` ensuring identical SHA-1 certificate fingerprints across all development environments:

- **Package Name:** `com.secureshield.ai`
- **SHA-1 Fingerprint:** `7E:66:D5:FD:FA:DF:00:72:A9:5F:CA:1B:0E:63:39:A5:1F:4D:54:8C`
- **Keystore Password:** `android`
- **Key Alias:** `androiddebugkey`
