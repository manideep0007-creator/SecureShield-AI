import hashlib
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from app.config.config import settings

logger = logging.getLogger(__name__)

# PBKDF2 Iteration Counts (OWASP recommended baseline)
CURRENT_ITERATIONS = 310_000
LEGACY_ITERATIONS = 100_000


def get_data_dir() -> Path:
    data_dir_path = Path(settings.resolved_data_dir)
    data_dir_path.mkdir(parents=True, exist_ok=True)
    return data_dir_path


def get_auth_db_path() -> Path:
    return get_data_dir() / "auth.db"


def get_user_dbs_dir() -> Path:
    users_dir = get_data_dir() / "users"
    users_dir.mkdir(parents=True, exist_ok=True)
    return users_dir


# For backward compatibility in tests
AUTH_DB_PATH = property(lambda self: get_auth_db_path())
USER_DBS_DIR = property(lambda self: get_user_dbs_dir())


def get_current_iso_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db_connection(db_path: Path | str) -> sqlite3.Connection:
    """Thread-safe SQLite connection configured with WAL mode and busy timeout."""
    conn = sqlite3.connect(str(db_path), timeout=15.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_auth_db() -> None:
    auth_path = get_auth_db_path()
    get_user_dbs_dir()

    with get_db_connection(auth_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                full_name TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT 'local',
                db_file TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
        conn.commit()


def hash_password(password: str) -> str:
    """Hashes password with random salt using PBKDF2-HMAC-SHA256 (310,000 rounds)."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        CURRENT_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${CURRENT_ITERATIONS}${salt}${key}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies password against stored hash with backward compatibility
    for both legacy (100,000 rounds) and current (310,000 rounds) formats.
    """
    if not stored_hash:
        return False

    parts = stored_hash.split("$")
    if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
        # Format: pbkdf2_sha256$<iterations>$<salt>$<key>
        try:
            iterations = int(parts[1])
        except ValueError:
            return False
        salt = parts[2]
        expected_key = parts[3]
        recalculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations
        ).hex()
        return secrets.compare_digest(recalculated, expected_key)
    elif len(parts) == 2:
        # Legacy format: <salt>$<key> (100,000 rounds)
        salt, expected_key = parts
        recalculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            LEGACY_ITERATIONS
        ).hex()
        return secrets.compare_digest(recalculated, expected_key)

    return False


def init_user_isolated_db(user_id: str) -> str:
    """
    Initializes an isolated SQLite database per user.
    Validates user_id format to prevent directory traversal attacks.
    """
    if not re.match(r"^usr_[a-zA-Z0-9_-]{8,64}$", user_id):
        raise ValueError(f"Invalid user_id format: potential path traversal prevented: {user_id}")

    users_dir = get_user_dbs_dir()
    db_file_name = f"{user_id}.db"
    db_path = users_dir / db_file_name

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_scans (
                scan_id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                threat_score REAL NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_scans_date ON user_scans(created_at DESC)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()

    return str(db_path)


def get_user_db_path(user_id: str) -> Path:
    if not re.match(r"^usr_[a-zA-Z0-9_-]{8,64}$", user_id):
        raise ValueError(f"Invalid user_id format: potential path traversal prevented: {user_id}")
    return get_user_dbs_dir() / f"{user_id}.db"


def save_user_scan(
    user_id: str,
    scan_id: str,
    scan_type: str,
    target: str,
    threat_level: str,
    threat_score: float,
    details_json: str = "{}"
) -> None:
    db_path = get_user_db_path(user_id)
    if not db_path.exists():
        init_user_isolated_db(user_id)
    now = get_current_iso_timestamp()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO user_scans (scan_id, scan_type, target, threat_level, threat_score, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, scan_type, target, threat_level, threat_score, details_json, now))
        conn.commit()


def get_user_scans(user_id: str, limit: int = 50) -> list[dict]:
    db_path = get_user_db_path(user_id)
    if not db_path.exists():
        return []
    with get_db_connection(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_scans ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]


def save_user_telemetry(user_id: str, event_type: str, event_data: str) -> None:
    db_path = get_user_db_path(user_id)
    if not db_path.exists():
        init_user_isolated_db(user_id)
    now = get_current_iso_timestamp()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_telemetry (event_type, event_data, timestamp)
            VALUES (?, ?, ?)
        """, (event_type, event_data, now))
        conn.commit()


def get_user_telemetry(user_id: str, limit: int = 50) -> list[dict]:
    db_path = get_user_db_path(user_id)
    if not db_path.exists():
        return []
    with get_db_connection(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_telemetry ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]


def set_user_setting(user_id: str, key: str, value: str) -> None:
    db_path = get_user_db_path(user_id)
    if not db_path.exists():
        init_user_isolated_db(user_id)
    now = get_current_iso_timestamp()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO user_settings (key, value, updated_at)
            VALUES (?, ?, ?)
        """, (key, value, now))
        conn.commit()


def get_user_settings(user_id: str) -> dict[str, str]:
    db_path = get_user_db_path(user_id)
    if not db_path.exists():
        return {}
    with get_db_connection(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM user_settings")
        return {row["key"]: row["value"] for row in cursor.fetchall()}


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    init_auth_db()
    clean_email = email.strip().lower()
    with get_db_connection(get_auth_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email) = ?", (clean_email,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    init_auth_db()
    with get_db_connection(get_auth_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def create_user(
    email: str,
    password: Optional[str] = None,
    full_name: str = "",
    provider: str = "local"
) -> Dict[str, Any]:
    """
    Creates a new user record atomically.
    Raises ValueError('user_already_exists') if email is already taken.
    """
    init_auth_db()
    clean_email = email.strip().lower()
    user_id = f"usr_{secrets.token_hex(12)}"
    now = get_current_iso_timestamp()
    pwd_hash = hash_password(password) if password else None
    display_name = full_name.strip() if full_name and full_name.strip() else clean_email.split("@")[0].capitalize()

    # Initialize user's separate isolated database
    db_path = init_user_isolated_db(user_id)

    try:
        with get_db_connection(get_auth_db_path()) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (user_id, email, password_hash, full_name, provider, db_file, created_at, last_login_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, clean_email, pwd_hash, display_name, provider, db_path, now, now))
            conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("user_already_exists")

    return {
        "user_id": user_id,
        "email": clean_email,
        "full_name": display_name,
        "provider": provider,
        "db_file": db_path,
        "created_at": now,
        "last_login_at": now
    }


def authenticate_user(
    email: str,
    password: str
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Strict user authentication (Phase 1: Separate registration and login):
    - Rejects non-existent accounts (does NOT auto-create).
    - Rejects password login on Google accounts without a configured password.
    - Verifies password against cryptographic hash.
    Returns (success, user_dict, status_message)
    """
    clean_email = email.strip().lower()
    user = get_user_by_email(clean_email)

    if not user:
        return False, None, "user_not_found"

    # Reject accounts that have no password (e.g. Google-only sign-ins)
    stored_hash = user.get("password_hash")
    if not stored_hash:
        return False, None, "no_password_set"

    # Verify password securely
    if not verify_password(password, stored_hash):
        return False, None, "invalid_password"

    # Update last login timestamp
    now = get_current_iso_timestamp()
    with get_db_connection(get_auth_db_path()) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login_at = ? WHERE user_id = ?", (now, user["user_id"]))
        conn.commit()
    user["last_login_at"] = now
    return True, user, "authenticated"


def authenticate_or_auto_register(
    email: str,
    password: str,
    full_name: Optional[str] = None
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Deprecated helper kept for interface compatibility; forwards to strict authenticate_user.
    """
    return authenticate_user(email, password)


def authenticate_or_create_google_user(
    email: str,
    full_name: str = "",
    google_id: Optional[str] = None
) -> Tuple[Dict[str, Any], str]:
    """
    Authenticates an existing user via Google, or provisions a new Google account.
    If the account previously existed with local provider, safely links Google.
    """
    clean_email = email.strip().lower()
    user = get_user_by_email(clean_email)
    now = get_current_iso_timestamp()

    if user:
        # Secure account linking / update last login
        updated_provider = user.get("provider", "local")
        if updated_provider == "local":
            updated_provider = "both"

        with get_db_connection(get_auth_db_path()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET last_login_at = ?, provider = ? WHERE user_id = ?",
                (now, updated_provider, user["user_id"])
            )
            conn.commit()
        user["last_login_at"] = now
        user["provider"] = updated_provider
        return user, "authenticated"

    # Provision new Google user
    display_name = full_name.strip() if full_name and full_name.strip() else clean_email.split("@")[0].capitalize()
    new_user = create_user(
        email=clean_email,
        password=None,
        full_name=display_name,
        provider="google"
    )
    return new_user, "auto_created"


def create_session(user_id: str, duration_seconds: int = 30 * 86400) -> str:
    """Generates an unguessable CSPRNG session token with expiration."""
    init_auth_db()
    clean_expired_sessions()
    token = f"ss_token_{secrets.token_urlsafe(32)}"
    created_at = get_current_iso_timestamp()
    expires_at = datetime.fromtimestamp(time.time() + duration_seconds, tz=timezone.utc).isoformat()

    with get_db_connection(get_auth_db_path()) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        """, (token, user_id, created_at, expires_at))
        conn.commit()

    return token


def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Resolves active user session; returns None if invalid or expired."""
    if not token:
        return None
    init_auth_db()
    now_iso = get_current_iso_timestamp()

    with get_db_connection(get_auth_db_path()) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.* FROM users u
            JOIN sessions s ON u.user_id = s.user_id
            WHERE s.token = ? AND s.expires_at > ?
        """, (token.strip(), now_iso))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def invalidate_session(token: str) -> bool:
    """Revokes a session token immediately on logout."""
    if not token:
        return False
    init_auth_db()
    with get_db_connection(get_auth_db_path()) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token.strip(),))
        conn.commit()
        return cursor.rowcount > 0


def clean_expired_sessions() -> int:
    """Removes expired sessions to prevent database bloat."""
    now_iso = get_current_iso_timestamp()
    try:
        with get_db_connection(get_auth_db_path()) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso,))
            conn.commit()
            return cursor.rowcount
    except Exception as exc:
        logger.warning("Session cleanup encountered non-fatal error: %s", exc)
        return 0
