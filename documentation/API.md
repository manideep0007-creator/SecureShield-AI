# SecureShield AI — REST API Reference

The SecureShield AI intelligence backend is a high-performance Python FastAPI service providing synchronous, multi-engine threat detection.

---

## Base Endpoints

| Method | Path | Description | Authentication | Rate Limit |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` or `/` | Service health & environment probe | None | None |
| `POST` | `/api/scan` | Unified multi-engine threat scan | `X-API-Key` header (if configured) | 30 req/min |
| `POST` | `/api/feedback` | User verdict feedback submission | `X-API-Key` header (if configured) | 30 req/min |
| `GET` | `/api/evaluation/metrics` | Read-only aggregate feedback metrics | `X-API-Key` header (if configured) | 30 req/min |

---

## 1. Health Check (`GET /health`)

Returns immediate runtime status, project identifier, and environment mode.

### Response `200 OK`
```json
{
  "status": "running",
  "project": "SecureShield-AI",
  "environment": "production"
}
```

---

## 2. Unified Scan (`POST /api/scan`)

Performs concurrent multi-engine analysis across URLs, raw message text, email headers, visual media, and binary attachments.

### Request Body (`ScanInput`)
```json
{
  "url": "http://192.168.1.1@secure-login-verify.xyz/account",
  "text": "URGENT: Your bank account has been suspended. Please verify identity immediately.",
  "source_channel": "manual",
  "classification_profile": "standard",
  "file_bytes_base64": null,
  "file_name": null,
  "metadata": {
    "sender": "security-alert@fakebank-update.xyz",
    "recipient": "user@gmail.com",
    "subject": "URGENT: Account Action Required"
  }
}
```

### Response `200 OK` (`UnifiedScanResponse`)
```json
{
  "scan_id": "8f3e2d1a-4b5c-6d7e-8f9a-0b1c2d3e4f5a",
  "status": "completed",
  "total_engines": 7,
  "completed_engines": 7,
  "skipped_engines": 0,
  "risk_score": 88.5,
  "classification": "Phishing",
  "warnings": [],
  "results": [
    {
      "engine_name": "url_engine",
      "risk_score": 85.0,
      "classification": "Phishing",
      "confidence": 0.95,
      "flags": ["ip_based_host", "suspicious_tld", "userinfo_in_url"],
      "evidence": {
        "host": "192.168.1.1@secure-login-verify.xyz",
        "heuristics_triggered": 3
      },
      "reasons": ["URL contains an embedded userinfo credentials trick and suspicious host."]
    },
    {
      "engine_name": "nlp_engine",
      "risk_score": 92.0,
      "classification": "Deceptive",
      "confidence": 0.90,
      "flags": ["urgent_coercion", "credential_harvesting_pattern"],
      "evidence": {
        "matched_keywords": ["suspended", "verify identity", "urgent"]
      },
      "reasons": ["Linguistic markers indicate social engineering and urgency coercion."]
    }
  ],
  "risk_assessment": {
    "risk_score": 88.5,
    "classification": "Phishing",
    "confidence": 0.93,
    "contributing_engines": ["url_engine", "nlp_engine", "header_analysis_engine"],
    "ignored_engines": ["visual_engine"],
    "flags": ["ip_based_host", "urgent_coercion", "credential_harvesting_pattern"],
    "evidence": [
      {
        "engine": "url_engine",
        "detail": "High-risk domain with credential spoofing"
      }
    ],
    "reasons": [
      "The URL uses deceptive credentials formatting.",
      "Message text contains high-urgency social engineering patterns."
    ],
    "recommended_action": "Do not enter passwords, OTPs, or financial details. Delete this message."
  }
}
```

---

## 3. Submit Feedback (`POST /api/feedback`)

Allows users to submit positive/negative telemetry for a completed scan.

### Request Body (`FeedbackRequest`)
```json
{
  "scan_id": "8f3e2d1a-4b5c-6d7e-8f9a-0b1c2d3e4f5a",
  "feedback": "down",
  "classification": "Phishing",
  "risk_score": 88.5,
  "confidence": 0.93,
  "source_type": "gmail"
}
```

### Response `200 OK`
```json
{
  "status": "success",
  "message": "Feedback recorded."
}
```

---

## 4. Evaluation Metrics (`GET /api/evaluation/metrics`)

Returns aggregate telemetry data summarizing user feedback rates across threat classifications.

### Response `200 OK`
```json
{
  "total_feedback": 42,
  "positive_feedback": 38,
  "negative_feedback": 4,
  "positive_rate": 0.904,
  "classification_counts": {
    "Phishing": 20,
    "Malware": 8,
    "Suspicious": 6,
    "Safe": 8
  }
}
```
