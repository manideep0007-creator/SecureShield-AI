# V1 BASELINE — Database Schemas

**Snapshot Date**: 2026-09-28

---

## Overview

SecureShield AI V1 uses **two local SQLite databases**, both auto-created on first module import. No external database servers are used.

| Database | File Path | Created By | Purpose |
|---|---|---|---|
| Sender Behavior DB | `backend/data/sender_behavior.db` | `engines/sender_engine.py` | Track per-sender messaging history for behavioral anomaly detection |
| Feedback DB | `backend/data/feedback.db` | `engines/feedback.py` | Store user accuracy feedback for future model retuning |

---

## sender_behavior.db

### Table: `senders`

```sql
CREATE TABLE IF NOT EXISTS senders (
    sender_id     TEXT PRIMARY KEY,
    message_count INTEGER DEFAULT 0,
    link_count    INTEGER DEFAULT 0,
    file_count    INTEGER DEFAULT 0
);
```

| Column | Type | Description |
|---|---|---|
| `sender_id` | TEXT (PK) | Unique sender identifier (email address, phone number, etc.) |
| `message_count` | INTEGER | Total messages received from this sender |
| `link_count` | INTEGER | Total messages containing links from this sender |
| `file_count` | INTEGER | Total messages containing files from this sender |

**Behavior**:
- New sender → INSERT with `message_count=1`, link/file counts set to 1 or 0 based on current message
- Existing sender → UPDATE incrementing `message_count` and adjusting link/file counts
- Used to detect `first_time_sender`, `out_of_character_link`, `out_of_character_file` anomalies

---

## feedback.db

### Table: `feedback`

```sql
CREATE TABLE IF NOT EXISTS feedback (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT,
    score          INTEGER,
    category       TEXT,
    feedback_value TEXT,
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER (PK, auto) | Auto-incrementing feedback entry ID |
| `target` | TEXT | The analyzed target (URL, filename, or truncated message text) |
| `score` | INTEGER | The fusion engine's final score (0–100) at time of feedback |
| `category` | TEXT | The fusion engine's category at time of feedback (Safe/Suspicious/Deceptive/Phishing/Malware) |
| `feedback_value` | TEXT | User feedback: `"up"` (accurate) or `"down"` (inaccurate) |
| `timestamp` | DATETIME | Auto-populated UTC timestamp of feedback submission |

**Behavior**:
- INSERT-only — feedback records are never updated or deleted
- Designed for future batch processing to retune fusion engine confidence weights
- No retraining pipeline exists in V1; data accumulates for future use
