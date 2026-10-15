import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from app.config.config import settings

_DEFAULT_FEEDBACK_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "feedback.db"))
DB_PATH = _DEFAULT_FEEDBACK_DB_PATH

def get_db_path(custom_path: str | None = None) -> str:
    if custom_path:
        return custom_path
    if DB_PATH != _DEFAULT_FEEDBACK_DB_PATH and DB_PATH != os.path.join(settings.resolved_data_dir, "feedback.db"):
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        return DB_PATH
    data_dir = settings.resolved_data_dir
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "feedback.db")


@contextmanager
def _connection(path: str):
    connection = sqlite3.connect(path, timeout=5)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db(db_path: str | None = None) -> None:
    path = get_db_path(db_path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with _connection(path) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT,
                        score REAL,
                        category TEXT,
                        feedback_value TEXT,
                        timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        scan_id TEXT,
                        user_feedback TEXT CHECK (
                            user_feedback IS NULL OR user_feedback IN ('positive', 'negative')
                        ),
                        classification_at_scan_time TEXT CHECK (
                            classification_at_scan_time IS NULL OR classification_at_scan_time IN
                            ('Safe', 'Suspicious', 'Deceptive', 'Phishing', 'Malware')
                        ),
                        risk_score_at_scan_time REAL CHECK (
                            risk_score_at_scan_time IS NULL OR risk_score_at_scan_time BETWEEN 0 AND 100
                        ),
                        confidence_at_scan_time REAL CHECK (
                            confidence_at_scan_time IS NULL OR confidence_at_scan_time BETWEEN 0 AND 1
                        ),
                        source_type TEXT CHECK (
                            source_type IS NULL OR source_type IN ('url', 'file', 'share', 'gmail', 'unknown')
                        )
                      )''')
        columns = {row[1] for row in conn.execute("PRAGMA table_info(feedback)")}
        migrations = {
            "scan_id": "ALTER TABLE feedback ADD COLUMN scan_id TEXT",
            "user_feedback": "ALTER TABLE feedback ADD COLUMN user_feedback TEXT",
            "classification_at_scan_time": "ALTER TABLE feedback ADD COLUMN classification_at_scan_time TEXT",
            "risk_score_at_scan_time": "ALTER TABLE feedback ADD COLUMN risk_score_at_scan_time REAL",
            "confidence_at_scan_time": "ALTER TABLE feedback ADD COLUMN confidence_at_scan_time REAL",
            "source_type": "ALTER TABLE feedback ADD COLUMN source_type TEXT",
        }
        for column, statement in migrations.items():
            if column not in columns:
                conn.execute(statement)
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_feedback_scan_id_unique "
            "ON feedback(scan_id) WHERE scan_id IS NOT NULL"
        )


def save_feedback(record, db_path: str | None = None) -> tuple[bool, str]:
    """Persist only the normalized scan ID and scan-time evaluation fields."""
    path = get_db_path(db_path)
    init_db(path)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    legacy_value = "up" if record.user_feedback == "positive" else "down"
    with _connection(path) as conn:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO feedback (
                target, score, category, feedback_value, timestamp, scan_id,
                user_feedback, classification_at_scan_time, risk_score_at_scan_time,
                confidence_at_scan_time, source_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.scan_id,
                record.risk_score_at_scan_time,
                record.classification_at_scan_time,
                legacy_value,
                timestamp,
                record.scan_id,
                record.user_feedback,
                record.classification_at_scan_time,
                record.risk_score_at_scan_time,
                record.confidence_at_scan_time,
                record.source_type or "unknown",
            ),
        )
        return cursor.rowcount == 1, timestamp


def read_feedback_records(db_path: str | None = None) -> list[dict]:
    """Read normalized feedback only; legacy target values are never returned."""
    path = get_db_path(db_path)
    init_db(path)
    with _connection(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT user_feedback, classification_at_scan_time,
                      risk_score_at_scan_time, confidence_at_scan_time, source_type
                    FROM feedback WHERE scan_id IS NOT NULL ORDER BY id"""
        ).fetchall()
    return [dict(row) for row in rows]
