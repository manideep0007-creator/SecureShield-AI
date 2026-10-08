# SecureShield AI — Production & CI/CD Deployment

This guide outlines deployment options for hosting the FastAPI backend and configuring GitHub Actions for automated Android APK releases.

---

## 1. Cloud Backend Hosting

### Option A: Railway (Recommended)
1. Link your GitHub repository in [Railway.app](https://railway.app/).
2. Set root directory to `backend`.
3. Add environment variables:
   - `API_KEY`: `your_secureshield_api_key_here`
   - `ENVIRONMENT`: `production`
   - `PORT`: `8000`
   - `GOOGLE_SAFE_BROWSING_API_KEY`: *(Optional)*
   - `VIRUSTOTAL_API_KEY`: *(Optional)*
4. Railway detects `Dockerfile` and deploys automatically.

### Option B: Render.com
1. Create a Web Service linked to the repo on [Render.com](https://render.com/).
2. Set Root Directory to `backend`.
3. Set Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`.
4. Add environment variables: `API_KEY`, `DATA_DIR` (e.g. `/var/data`), `ENVIRONMENT`, etc.
5. *Note*: Mount a Persistent Disk at `DATA_DIR` if you wish to preserve SQLite tables (`sender_behavior.db`, `feedback.db`) across free-tier cold starts.

---

## 2. GitHub Actions CI/CD Pipeline

The repository includes two automated workflows in `.github/workflows/`:

### 1. `android-ci-cd.yml`
- **Triggers:** Pushes and pull requests touching `android/**`, plus tag pushes (`v*`).
- **Steps:**
  1. Sets up JDK 17 with Gradle caching.
  2. Runs unit test suite (`./gradlew test`).
  3. Builds `app-debug.apk` using deterministic bundled `debug.keystore`.
  4. Publishes downloadable APKs directly to **GitHub Releases** and GitHub Actions artifacts.

### 2. `backend-ci-cd.yml`
- **Triggers:** Pushes and pull requests touching `backend/**`.
- **Steps:**
  1. Sets up Python 3.11 with system dependencies.
  2. Executes full pytest suite (199 tests).
  3. Auto-deploys to Railway on push to `main` if `RAILWAY_TOKEN` secret is present.

---

## 3. GitHub Secrets Reference

| Secret | Target | Description |
| :--- | :--- | :--- |
| `API_KEY` / `SECURESHIELD_API_KEY` | Backend & Android Build | Shared secret API key for backend auth and client requests |
| `RAILWAY_TOKEN` | Backend CI/CD | Railway deployment token |
| `PROD_BASE_URL` | Android Build | Cloud backend URL |
| `FIREBASE_APP_ID` | Android CI/CD | Optional Firebase App Distribution ID |
| `FIREBASE_SERVICE_CREDENTIALS` | Android CI/CD | Optional Firebase service account JSON |
