# V1 BASELINE — API Surface

**Snapshot Date**: 2026-09-28

---

## Backend Endpoints (FastAPI)

All endpoints are prefixed with `/api` via the router mount in `main.py`.

---

### `GET /`

**Purpose**: Health check  
**Auth**: None  

**Response**:
```json
{
  "status": "running",
  "project": "SecureShield AI"
}
```

---

### `POST /api/analyze/message`

**Purpose**: Analyze a text message, URL, and/or sender for threats  
**Auth**: None  
**Content-Type**: `application/json`

**Request Body** (`MessageScanRequest`):
```json
{
  "message_text": "string | null",
  "url": "string (valid URL) | null",
  "sender_id": "string | null"
}
```
- At least one of `message_text` or `url` must be provided (HTTP 400 otherwise)

**Response** (`ScanResponse`):
```json
{
  "final_score": 85,
  "category": "Phishing",
  "reasons": [
    "The link hides its true destination using an IP address instead of a standard domain name.",
    "The message contains urgent language trying to force immediate action."
  ],
  "recommended_action": "Avoid the link. Block this sender and delete the message immediately.",
  "analyzed_target": "http://192.168.1.1@example.xyz/login",
  "details": {
    "url": { "lexical_score": 0.9, "lexical_flags": [...], "gsb_score": 0.0, ... },
    "nlp": { ... },
    "sender": { ... }
  },
  "errors": ["GSB_API_KEY_NOT_CONFIGURED"]
}
```
- `final_score`: Integer 0–100
- `category`: One of `Safe`, `Suspicious`, `Deceptive`, `Phishing`, `Malware`
- `errors`: Only present if one or more engines encountered an error
- `analyzed_target`: The resolved URL or first 50 chars of message text

---

### `POST /api/analyze/file`

**Purpose**: Analyze an uploaded file for malware  
**Auth**: None  
**Content-Type**: `multipart/form-data`

**Request**:
| Field | Type | Required | Description |
|---|---|---|---|
| `file` | File upload | Yes | Max 10 MB; HTTP 400 if empty, HTTP 413 if over limit |
| `sender_id` | string (form field) | No | Optional sender identifier for behavioral analysis |

**Response**: Same `ScanResponse` shape as `/api/analyze/message`

---

### `POST /api/feedback`

**Purpose**: Submit user feedback on a scan result  
**Auth**: None  
**Content-Type**: `application/json`

**Request Body** (`FeedbackRequest`):
```json
{
  "analyzed_target": "string",
  "score": 85,
  "category": "Phishing",
  "feedback_value": "up | down"
}
```

**Response**:
```json
{
  "status": "success"
}
```

---

## External API Integrations

### Google Safe Browsing API v4

| Property | Value |
|---|---|
| **Used in** | `engines/url_engine.py` → `check_google_safe_browsing()` |
| **Endpoint** | `https://safebrowsing.googleapis.com/v4/threatMatches:find` |
| **Method** | POST |
| **Auth** | API key via query parameter (`?key=...`) |
| **Config key** | `GOOGLE_SAFE_BROWSING_API_KEY` (env var or `.env`) |
| **Threat types** | MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION |
| **Timeout** | 5 seconds |
| **Failure mode** | Returns `gsb_score: 0.0` + error string; never crashes pipeline |

### VirusTotal API v3

| Property | Value |
|---|---|
| **Used in** | `engines/malware_engine.py` → `check_virustotal()` |
| **Endpoint** | `https://www.virustotal.com/api/v3/files/{sha256_hash}` |
| **Method** | GET |
| **Auth** | API key via `x-apikey` header |
| **Config key** | `VIRUSTOTAL_API_KEY` (env var or `.env`) |
| **Caching** | TTLCache — 1000 items, 10-minute TTL |
| **404 handling** | File unknown to VT → flagged as `vt_not_found` (score 0.0) |
| **Timeout** | 5 seconds |
| **Failure mode** | Returns `score: 0.0` + error string; never crashes pipeline |

### Gmail API (Android-side only)

| Property | Value |
|---|---|
| **Used in** | `GmailScanner.kt` |
| **Scope** | `gmail.readonly` |
| **Auth** | Google Sign-In OAuth via Play Services |
| **Query** | Latest 1 unread message (`is:unread`, `maxResults=1`) |
| **Format** | `full` — extracts `From` header, snippet body, first URL via regex |

---

## Android → Backend Communication

| Property | Value |
|---|---|
| **HTTP client** | Retrofit 2.9.0 + OkHttp 4.12.0 |
| **Serialization** | Gson |
| **Base URL** | `BuildConfig.BASE_URL` (default: `http://10.0.2.2:8000/`) |
| **Coroutine dispatcher** | `Dispatchers.IO` for all network calls |

### Retrofit Interface (`SecureShieldApi`)

```kotlin
@POST("/api/analyze/message")
suspend fun analyzeMessage(@Body request: MessageScanRequest): Response<ScanResponse>

@Multipart
@POST("/api/analyze/file")
suspend fun analyzeFile(@Part file: MultipartBody.Part): Response<ScanResponse>

@POST("/api/feedback")
suspend fun sendFeedback(@Body request: FeedbackRequest): Response<Unit>
```

### Android Data Classes

```kotlin
data class MessageScanRequest(val message_text: String?, val url: String?, val sender_id: String?)
data class FeedbackRequest(val analyzed_target: String, val score: Int, val category: String, val feedback_value: String)
data class ScanResponse(val final_score: Int, val category: String, val reasons: List<String>, val recommended_action: String, val analyzed_target: String)
```
