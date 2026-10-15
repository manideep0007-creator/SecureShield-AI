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
  "classification_profile": "default",
  "file_name": null,
  "file_bytes": null,
  "image_bytes": null,
  "client_id": "8f3e2d1a-4b5c-6d7e-8f9a-0b1c2d3e4f5a",
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
      "confidence": 0.80,
      "flags": ["ip_based_host", "suspicious_tld", "at_symbol_present"],
      "evidence": [
        {
          "key": "IP_HOST",
          "value": "192.168.1.1",
          "description": "IP-based hostname detected"
        }
      ],
      "status": "success",
      "error_message": null,
      "metadata": {}
    }
  ],
  "risk_assessment": {
    "risk_score": 88.5,
    "classification": "Phishing",
    "confidence": 0.93,
    "contributing_engines": ["url_engine", "nlp_engine", "header_analysis_engine"],
    "ignored_engines": [],
    "flags": ["ip_based_host", "suspicious_tld", "nlp_urgency", "nlp_credential_request"],
    "evidence": [
      {
        "key": "IP_HOST",
        "value": "192.168.1.1",
        "description": "IP-based hostname detected"
      }
    ],
    "reasons": [
      "The URL uses an IP address instead of a standard domain name.",
      "Natural language processing found signs of urgency.",
      "Natural language processing found signs of credential request."
    ],
    "recommended_action": "Do not click any links or provide credentials. Report and delete this message."
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
  "user_feedback": "negative",
  "classification_at_scan_time": "Phishing",
  "risk_score_at_scan_time": 88.5,
  "confidence_at_scan_time": 0.93,
  "source_type": "gmail"
}
```

### Response `200 OK` (`FeedbackSubmissionResponse`)
```json
{
  "status": "success",
  "scan_id": "8f3e2d1a-4b5c-6d7e-8f9a-0b1c2d3e4f5a",
  "timestamp": "2026-10-15T11:00:00Z"
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
