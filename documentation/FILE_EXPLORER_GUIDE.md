# 📁 SecureShield AI - File Explorer Guide

This guide helps you navigate the project easily in **Windows File Explorer** (`D:\Secure Shield AI`) or **VS Code** without getting confused.

---

## 🧭 Root Directory Map

When you look at `D:\Secure Shield AI`, here is what each folder and file represents:

```
D:\Secure Shield AI\
├── 📱 android/              <-- [FRONTEND] Android mobile app source code (Kotlin + XML)
├── ⚙️ backend/              <-- [BACKEND] Threat detection API server (FastAPI / Python)
│   └── 🗄️ data/            <-- [SERVER DATABASE] SQLite files (feedback.db, sender_behavior.db)
├── 📖 documentation/        <-- Architecture, guides, API specs, and demo scripts
├── 🐍 .venv/                <-- Python virtual environment (auto-managed, hidden in VS Code)
├── ⚙️ .env                  <-- API keys and environment configuration
├── 🚀 start_backend.bat     <-- Double-click to start backend server locally
├── 📄 README.md             <-- Complete project overview & documentation
└── ⚙️ .vscode/              <-- VS Code workspace settings (hides build/cache noise)
```

---

## 📱 1. FRONTEND: Where to find UI and Mobile Code
Navigate to: **`android\app\src\main\`**

* 🎨 **Screens & User Interface (XML Layouts):**
  * Path: `android\app\src\main\res\layout\`
  * `activity_main.xml` — Main dashboard screen (URL input, scan button, risk card)
  * `activity_guardian_intercept.xml` — Guardian Mode threat alert overlay
  * `activity_scan_history.xml` — History list screen
  * `dialog_server_settings.xml` — Server IP / connection settings popup

* 💻 **App Logic & Features (Kotlin Code):**
  * Path: `android\app\src\main\java\com\secureshield\ai\`
  * `MainActivity.kt` — Dashboard actions and button clicks
  * `ShareActivity.kt` — Handles URLs/files shared from other apps
  * `network\ApiClient.kt` — Sends scan requests to the backend server
  * `guardian\GuardianAccessibilityService.kt` — Real-time screen link monitor
  * `gmail\GmailSyncWorker.kt` — Background email scanner
  * `history\ScanHistoryDatabase.kt` — Local offline database helper

---

## ⚙️ 2. BACKEND: Where to find Server & Detection Engines
Navigate to: **`backend\app\`**

* 🚀 **Server Entry & Routes:**
  * `backend\main.py` — Server entry point
  * `backend\app\api\routes.py` — REST API endpoints (`/api/scan`, `/api/feedback`)

* 🧠 **7 Threat Detection Engines:**
  * Path: `backend\app\engines\`
  * `url_engine.py` — Checks suspicious links and domains
  * `malware_engine.py` — File hash & signature checks
  * `nlp_engine.py` — Detects urgency, fraud, and deceptive language
  * `sender_engine.py` — Checks sender anomalies and spoofing
  * `header_engine.py` — Validates email security headers (SPF, DKIM, DMARC)
  * `attachment_engine.py` — Analyzes email attachment files
  * `visual_engine.py` — Detects logo and brand impersonation

* ⚖️ **Score Fusion & Explanations:**
  * `backend\app\fusion\` — Combines engine scores into a single 0–100 threat score
  * `backend\app\explainability\` — Generates human-readable explanations

---

## 🗄️ 3. DATABASES: Where Data is Stored

| What Database? | File Explorer Location | Description |
| :--- | :--- | :--- |
| **Server Databases** | `backend\data\feedback.db`<br>`backend\data\sender_behavior.db` | Stored in SQLite files on the server. Holds user ratings and sender baseline records. |
| **Phone Client Database** | `secure_scan_history.db`<br>*(On Android device/emulator)* | Kept private inside the Android app's private storage on the phone. Stores user's offline scan history. |

---

## ⚡ Quick Lookup: "Where do I go if I want to..."

| Goal | Exact Folder to Open |
| :--- | :--- |
| **Change the look of the Android screen** | `android\app\src\main\res\layout\` |
| **Change how the Android app behaves** | `android\app\src\main\java\com\secureshield\ai\` |
| **Change how URLs or emails are analyzed** | `backend\app\engines\` |
| **Inspect or back up server database files** | `backend\data\` |
| **Change API keys (Google Safe Browsing, etc.)** | Open `.env` in the root folder |
| **Start the backend server** | Double-click `start_backend.bat` in the root folder |
| **Open project in Android Studio** | Open the `android` folder in Android Studio |
