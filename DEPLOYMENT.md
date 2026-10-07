# SecureShield AI — Production Cloud & CI/CD Deployment Guide

This document provides a comprehensive guide for deploying the **SecureShield AI** FastAPI backend 24/7 to the cloud and configuring automated CI/CD pipelines via **GitHub Actions** and **Firebase App Distribution**.

---

## Architecture Overview

```
                          ┌───────────────────────────┐
                          │   GitHub Repository       │
                          └─────────────┬─────────────┘
                                        │ (Push / PR)
                   ┌────────────────────┴────────────────────┐
                   ▼                                         ▼
   ┌───────────────────────────────┐         ┌───────────────────────────────┐
   │  Backend CI/CD Workflow       │         │  Android CI/CD Workflow       │
   │  • Run Pytest (186 tests)     │         │  • Run Unit Tests             │
   │  • Build & Test Docker Image  │         │  • Build Debug & Release APKs │
   │  • Auto-Deploy to Railway     │         │  • Upload GitHub Artifacts    │
   └───────────────┬───────────────┘         │  • Firebase App Distribution  │
                   │ (Deploy)                └───────────────┬───────────────┘
                   ▼                                         ▼
   ┌───────────────────────────────┐         ┌───────────────────────────────┐
   │  24/7 Cloud Backend (HTTPS)   │ ◄────── │  Android Client App (Devices) │
   │  https://<app>.up.railway.app │ (POST   │  (On-Screen Guardian & Inbox) │
   │  or https://<app>.onrender.com│  /scan) │                               │
   └───────────────────────────────┘         └───────────────────────────────┘
```

---

## 1. Cloud Backend Deployment (Railway / Render)

### Option A: Deploy on Railway (Recommended)

1. Sign up on **[Railway.app](https://railway.app/)** with your GitHub account.
2. Click **New Project** → **Deploy from GitHub repo** → Select `SecureShield-AI`.
3. Set the **Root Directory** to `/backend`.
4. Railway automatically detects `Dockerfile` and `railway.json`.
5. Under **Variables**, add:
   * `ENVIRONMENT`: `production`
   * `PORT`: `8000` *(Railway provides this automatically)*
   * `GOOGLE_SAFE_BROWSING_API_KEY`: *(Optional: Your Google Safe Browsing Key)*
   * `VIRUSTOTAL_API_KEY`: *(Optional: Your VirusTotal Key)*
6. Under **Settings** → **Networking**, click **Generate Domain** to get your public HTTPS URL (e.g., `https://secureshield-production.up.railway.app`).

### Option B: Deploy on Render.com

1. Sign up on **[Render.com](https://render.com/)**.
2. Click **New Web Service** → Connect your repository.
3. Configuration:
   * **Root Directory:** `backend`
   * **Environment:** `Docker` (or `Python 3`)
   * **Build Command:** `pip install -r requirements.txt`
   * **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Render will generate a public HTTPS URL (e.g., `https://secureshield-ai.onrender.com`).

---

## 2. Health & Verification Check

Once deployed, verify your cloud backend is live by opening:
```text
https://<YOUR-CLOUD-DOMAIN>/health
```
**Expected JSON Response:**
```json
{
  "status": "running",
  "project": "SecureShield AI",
  "environment": "production"
}
```

---

## 3. GitHub Actions CI/CD Configuration

### Required GitHub Secrets

In your GitHub repository, navigate to **Settings** → **Secrets and variables** → **Actions** → **New repository secret**:

| Secret Name | Required For | Description |
| :--- | :--- | :--- |
| `RAILWAY_TOKEN` | Backend Auto-Deploy | Railway Account / Project Token for automated redeployment on push to `main`. |
| `PROD_BASE_URL` | Android Release APK | The public HTTPS backend URL (e.g. `https://secureshield-production.up.railway.app/`). |
| `FIREBASE_APP_ID` | Test Distribution *(Optional)* | Firebase Android App ID (e.g. `1:123456789:android:abcdef`). |
| `FIREBASE_TOKEN` | Test Distribution *(Optional)* | Firebase CLI Token (`firebase login:ci`). |
| `FIREBASE_SERVICE_CREDENTIALS` | Test Distribution *(Optional)* | JSON content of Firebase Service Account key. |

---

## 4. How the GitHub Workflows Work

### 1. Backend Pipeline (`.github/workflows/backend-ci-cd.yml`)
* **Trigger:** Any push or pull request touching `backend/**`.
* **Execution:**
  1. Sets up Python 3.11 with system graphics dependencies (`libgl1`, `libglib2.0-0`).
  2. Installs requirements and runs the 186-test pytest suite.
  3. **Quality Gate:** If any test fails, deployment is aborted.
  4. If tests pass on branch `main`, automatically deploys the latest version to Railway.

### 2. Android Pipeline (`.github/workflows/android-ci-cd.yml`)
* **Trigger:** Any push or pull request touching `android/**`.
* **Execution:**
  1. Sets up JDK 17 and caches Gradle dependencies.
  2. Runs unit test suite (`./gradlew test`).
  3. Injects `PROD_BASE_URL` and builds `app-debug.apk`.
  4. Stores the generated APK as an artifact under the GitHub Actions run for direct download.
  5. *(Optional)* If Firebase secrets are configured, pushes the APK to tester groups via Firebase App Distribution.

---

## 5. Firebase App Distribution Setup (Optional)

To enable automatic APK distribution to tester devices:
1. In the **[Firebase Console](https://console.firebase.google.com/)**, create or select your project.
2. Add an **Android App** with package name `com.secureshield.ai`.
3. In the left sidebar, navigate to **Release & Monitor** → **App Distribution**.
4. Create a tester group named `internal-testers` and invite tester emails.
5. In GitHub repository secrets, add:
   * `FIREBASE_APP_ID`: From Project Settings (e.g. `1:123456789:android:abcdef`).
   * `FIREBASE_SERVICE_CREDENTIALS`: Paste the contents of your Google Service Account JSON with `Firebase App Distribution Admin` role.

---

## 6. Development vs. Production Configuration

SecureShield uses a dual-environment configuration in `android/app/build.gradle.kts`:

| Environment | Build Type | Default URL | Description |
| :--- | :--- | :--- | :--- |
| **Development** | `debug` | `http://10.0.2.2:8000/` (or LAN IP) | Allows local testing on emulator and laptop Wi-Fi. Overridable via in-app Developer Settings. |
| **Production** | `release` | `https://secureshield-api.up.railway.app/` | Enforces HTTPS TLS (`cleartextTrafficPermitted=false`). Uses cloud backend. |

---

## 7. How to Download Pre-Built APKs from GitHub Actions

1. Open your repository on GitHub.
2. Click the **Actions** tab.
3. Select the latest run of **Android CI/CD Pipeline**.
4. Scroll down to the **Artifacts** section at the bottom.
5. Download **`secureshield-debug-apk`** (contains `app-debug.apk`) directly to your phone.

---

## 8. Exact Steps to Run SecureShield 24/7 Without Your Laptop

1. **Deploy Backend:**
   - Link your repo to Railway or Render and deploy the `backend/` directory.
   - Copy the resulting HTTPS URL (`https://your-app.up.railway.app/`).
2. **Add Secret to GitHub:**
   - Add `PROD_BASE_URL = https://your-app.up.railway.app/` to your GitHub repository secrets.
3. **Trigger Build:**
   - Push a commit or trigger the Android workflow manually in GitHub Actions.
4. **Install on Phone:**
   - Download the generated APK artifact from GitHub Actions and install it on your mobile phone.
   - SecureShield will communicate with your 24/7 cloud backend anywhere over mobile data/Wi-Fi without your laptop running!
