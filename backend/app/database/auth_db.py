import hashlib
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
AUTH_DB_PATH = DATA_DIR / "auth.db"
USER_DBS_DIR = DATA_DIR / "users"


def get_current_iso_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_auth_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    USER_DBS_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(AUTH_DB_PATH) as conn:
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
        conn.commit()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()
    return f"{salt}${key}"


def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash or "$" not in stored_hash:
        return False
    salt, expected_key = stored_hash.split("$", 1)
    recalculated = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()
    return secrets.compare_digest(recalculated, expected_key)


def init_user_isolated_db(user_id: str) -> str:
    USER_DBS_DIR.mkdir(parents=True, exist_ok=True)
    db_file_name = f"{user_id}.db"
    db_path = USER_DBS_DIR / db_file_name

    with sqlite3.connect(db_path) as conn:
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


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    init_auth_db()
    with sqlite3.connect(AUTH_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    init_auth_db()
    with sqlite3.connect(AUTH_DB_PATH) as conn:
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
    init_auth_db()
    clean_email = email.strip().lower()
    user_id = f"usr_{secrets.token_hex(12)}"
    now = get_current_iso_timestamp()
    pwd_hash = hash_password(password) if password else None
    display_name = full_name.strip() if full_name and full_name.strip() else clean_email.split("@")[0].capitalize()
    
    # Initialize user's separate database
    db_path = init_user_isolated_db(user_id)

    with sqlite3.connect(AUTH_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (user_id, email, password_hash, full_name, provider, db_file, created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, clean_email, pwd_hash, display_name, provider, db_path, now, now))
        conn.commit()

    return {
        "user_id": user_id,
        "email": clean_email,
        "full_name": display_name,
        "provider": provider,
        "db_file": db_path,
        "created_at": now,
        "last_login_at": now
    }


def authenticate_or_auto_register(
    email: str,
    password: str,
    full_name: Optional[str] = None
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Handles sign-in:
    - If user does not exist: auto-creates user account transparently!
    - If user exists: checks password.
    Returns (success, user_dict, status_message)
    """
    clean_email = email.strip().lower()
    user = get_user_by_email(clean_email)

    if not user:
        # User doesn't exist -> Auto-create account!
        new_user = create_user(
            email=clean_email,
            password=password,
            full_name=full_name or "",
            provider="local"
        )
        return True, new_user, "auto_created"

    # User exists -> Verify password
    if user["password_hash"] and not verify_password(password, user["password_hash"]):
        return False, None, "invalid_password"

    # Update last login
    now = get_current_iso_timestamp()
    with sqlite3.connect(AUTH_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login_at = ? WHERE user_id = ?", (now, user["user_id"]))
        conn.commit()
    user["last_login_at"] = now
    return True, user, "authenticated"


def authenticate_or_create_google_user(
    email: str,
    full_name: str = "",
    google_id: Optional[str] = None
) -> Tuple[Dict[str, Any], str]:
    clean_email = email.strip().lower()
    user = get_user_by_email(clean_email)

    now = get_current_iso_timestamp()
    if user:
        with sqlite3.connect(AUTH_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET last_login_at = ? WHERE user_id = ?", (now, user["user_id"]))
            conn.commit()
        user["last_login_at"] = now
        return user, "authenticated"

    # Auto create Google user
    display_name = full_name.strip() if full_name and full_name.strip() else clean_email.split("@")[0].capitalize()
    new_user = create_user(
        email=clean_email,
        password=None,
        full_name=display_name,
        provider="google"
    )
    return new_user, "auto_created"


def create_session(user_id: str, duration_seconds: int = 30 * 86400) -> str:
    init_auth_db()
    token = f"ss_token_{secrets.token_urlsafe(32)}"
    created_at = get_current_iso_timestamp()
    expires_at = datetime.fromtimestamp(time.time() + duration_seconds, tz=timezone.utc).isoformat()

    with sqlite3.connect(AUTH_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        """, (token, user_id, created_at, expires_at))
        conn.commit()

    return token


def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    init_auth_db()
    now_iso = get_current_iso_timestamp()

    with sqlite3.connect(AUTH_DB_PATH) as conn:
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
    if not token:
        return False
    init_auth_db()
    with sqlite3.connect(AUTH_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token.strip(),))
        conn.commit()
        return cursor.rowcount > 0
