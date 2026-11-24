import ipaddress
import logging
import math
import os
import secrets
import sqlite3
import time
from threading import Lock
from typing import Callable, Tuple
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config.config import settings

logger = logging.getLogger(__name__)


# Redis Lua script for strictly atomic sliding-window rate limiting.
# Executes eviction, count check, insertion, and expiration in a single single-threaded Redis transaction.
REDIS_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window

-- 1. Evict expired entries outside the sliding window
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)

-- 2. Count active entries within current window
local count = redis.call('ZCARD', key)

if count >= max_requests then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local oldest_ts = cutoff
    if oldest and #oldest >= 2 then
        oldest_ts = tonumber(oldest[2])
    end
    local retry_after = math.ceil(oldest_ts + window - now)
    if retry_after < 1 then retry_after = 1 end
    return {0, retry_after}
else
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window * 2))
    return {1, 0}
end
"""


class SharedRateLimiter:
    """
    Multi-worker shared sliding-window rate limiter.
    Stores window timestamps in Redis (via atomic Lua script) or SQLite database
    (via atomic BEGIN IMMEDIATE transaction locking) for multi-worker process safety.
    If rate-limit storage fails, sensitive limiters fail closed (fail_closed=True)
    to protect against brute-force attacks and resource exhaustion.
    """

    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: float = 60.0,
        db_name: str = "rate_limits.db",
        fail_closed: bool = False
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.db_path = os.path.join(settings.resolved_data_dir, db_name)
        self.fail_closed = fail_closed
        self._lock = Lock()
        self._redis_client = None
        self._redis_script = None
        self._db_initialized = False

        # Always initialize fallback SQLite database schema at startup
        # Ensures that if Redis drops connection mid-flight, fallback to SQLite succeeds immediately
        self._init_db()

        if settings.REDIS_URL:
            try:
                import redis
                self._redis_client = redis.from_url(
                    settings.REDIS_URL,
                    socket_timeout=2.0,
                    socket_connect_timeout=2.0,
                    decode_responses=True
                )
                self._redis_client.ping()
                self._redis_script = self._redis_client.register_script(REDIS_SLIDING_WINDOW_LUA)
            except Exception as e:
                logger.warning("Could not connect to Redis at startup: %s. Using SQLite fallback.", e)
                self._redis_client = None
                self._redis_script = None

    def _init_db(self):
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS rate_records (
                        key TEXT NOT NULL,
                        timestamp REAL NOT NULL
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_key_time ON rate_records (key, timestamp);")
                conn.commit()
            self._db_initialized = True
        except Exception as exc:
            logger.warning("SharedRateLimiter SQLite init warning: %s", exc)

    def check_and_record(self, key: str, now: float | None = None) -> Tuple[bool, int]:
        """
        Checks if the request key exceeds rate limit.
        Returns (is_allowed, retry_after_seconds).
        If rate-limit storage fails:
          - If fail_closed=True: rejects request with retry_after window (safe fail-closed).
          - If fail_closed=False: allows request with warning (fail-open for general non-sensitive metrics).
        """
        if now is None:
            now = time.time()

        # Atomic Redis sliding window check via Lua script
        if self._redis_client and self._redis_script:
            try:
                member = f"{now}_{secrets.token_hex(4)}"
                result = self._redis_script(
                    keys=[key],
                    args=[now, self.window_seconds, self.max_requests, member]
                )
                is_allowed = bool(result[0] == 1)
                retry_after = int(result[1])
                return is_allowed, retry_after
            except Exception as e:
                logger.warning("Atomic Redis rate limit script error, falling back to SQLite: %s", e)

        # Atomic SQLite sliding window check using BEGIN IMMEDIATE transaction
        cutoff = now - self.window_seconds
        with self._lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("DELETE FROM rate_records WHERE timestamp <= ?", (cutoff,))
                cursor.execute("SELECT timestamp FROM rate_records WHERE key = ? ORDER BY timestamp ASC", (key,))
                rows = cursor.fetchall()

                if len(rows) >= self.max_requests:
                    oldest = rows[0][0]
                    retry_after = max(1, math.ceil(oldest + self.window_seconds - now))
                    conn.execute("COMMIT")
                    return False, retry_after

                cursor.execute("INSERT INTO rate_records (key, timestamp) VALUES (?, ?)", (key, now))
                conn.execute("COMMIT")
                return True, 0
            except Exception as exc:
                if conn:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                logger.error("SharedRateLimiter SQLite storage error: %s", exc)
                if self.fail_closed:
                    # Fail closed on sensitive endpoints: never silently allow unlimited requests
                    return False, int(self.window_seconds)
                return True, 0
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def reset(self):
        """Clears all recorded rate limit windows (useful for testing)."""
        if self._redis_client:
            try:
                self._redis_client.flushdb()
            except Exception:
                pass
        with self._lock:
            try:
                with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                    conn.execute("DELETE FROM rate_records")
                    conn.commit()
            except Exception:
                pass


# Maintain backward-compatible class alias
InMemoryRateLimiter = SharedRateLimiter

# Shared limiters for sensitive actions (Phase 2: API Security & Rate Limiting)
# Sensitive auth endpoints FAIL CLOSED if rate-limit storage fails.
rate_limiter = SharedRateLimiter(max_requests=30, window_seconds=60.0, fail_closed=False)          # General scan
auth_login_limiter = SharedRateLimiter(max_requests=10, window_seconds=60.0, fail_closed=True)    # 10 attempts / min (Fail Closed)
auth_register_limiter = SharedRateLimiter(max_requests=5, window_seconds=60.0, fail_closed=True)  # 5 registrations / min (Fail Closed)
general_api_limiter = SharedRateLimiter(max_requests=60, window_seconds=60.0, fail_closed=False)   # 60 req / min

PUBLIC_HEALTH_PATHS = {
    "/",
    "/health",
    "/api/health",
    "/api/threat-intelligence/status",
    "/docs",
    "/openapi.json",
    "/redoc",
}

PUBLIC_AUTH_PATHS = {
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/google",
    "/api/auth/me",
    "/api/auth/logout",
}


def is_health_or_doc_path(path: str) -> bool:
    normalized = path.rstrip("/")
    if not normalized:
        return True
    return normalized in PUBLIC_HEALTH_PATHS or path in PUBLIC_HEALTH_PATHS


def is_auth_path(path: str) -> bool:
    normalized = path.rstrip("/")
    return normalized in PUBLIC_AUTH_PATHS or path in PUBLIC_AUTH_PATHS


def is_trusted_proxy(ip_str: str) -> bool:
    """Verifies whether an incoming peer IP is an authorized reverse proxy."""
    if not ip_str or ip_str == "unknown":
        return False
    if ip_str == "testclient":
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        for trusted in settings.trusted_proxy_list:
            if trusted == "testclient":
                continue
            try:
                if "/" in trusted:
                    if ip in ipaddress.ip_network(trusted, strict=False):
                        return True
                else:
                    if ip == ipaddress.ip_address(trusted):
                        return True
            except ValueError:
                continue
    except ValueError:
        return False
    return False


def verify_api_key_header(api_key: str | None) -> bool:
    """
    Restricted legacy/server-to-server API key verification.
    SECURITY POLICY:
    - API keys grant access strictly in a system/anonymous context (request.state.user = None).
    - API keys CANNOT access, query, or modify user-isolated vaults, telemetry, or settings.
    - Mobile clients authenticate exclusively via authenticated user sessions (Bearer tokens).
    - In production, default development keys are strictly rejected.
    """
    if not api_key:
        return False
    expected_key = os.getenv("API_KEY") or settings.API_KEY
    if settings.ENVIRONMENT == "production" and (not expected_key or expected_key == "secureshield_dev_secret_key_2026"):
        # In production, default development keys are rejected
        return False
    expected_key = expected_key or "secureshield_dev_secret_key_2026"
    return secrets.compare_digest(api_key, expected_key)


class SecurityAndRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # 1. Allow preflight OPTIONS requests
        if request.method == "OPTIONS":
            return await call_next(request)

        # Extract client IP with trusted proxy verification (prevents header spoofing)
        peer_ip = request.client.host if request.client else "unknown"
        client_ip = peer_ip
        if is_trusted_proxy(peer_ip):
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip() or peer_ip

        now = time.time()

        # 2. Allow unauthenticated health & docs
        if is_health_or_doc_path(path):
            return await call_next(request)

        # 3. Apply dedicated strict rate limiting to Authentication endpoints (Phase 2)
        if path == "/api/auth/register":
            allowed, retry_after = auth_register_limiter.check_and_record(f"reg:{client_ip}", now=now)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many registration attempts. Please retry later."},
                    headers={"Retry-After": str(retry_after)},
                )
            return await call_next(request)

        if path in ("/api/auth/login", "/api/auth/google"):
            allowed, retry_after = auth_login_limiter.check_and_record(f"auth:{client_ip}", now=now)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many authentication attempts. Please retry later."},
                    headers={"Retry-After": str(retry_after)},
                )
            return await call_next(request)

        if is_auth_path(path):
            return await call_next(request)

        # 4. Enforce API Key or User Session Bearer authentication on protected endpoints
        if path.startswith("/api/"):
            user = None
            auth_header = request.headers.get("Authorization")
            token = None
            if auth_header and auth_header.strip().lower().startswith("bearer "):
                token = auth_header.strip()[7:].strip()
            elif request.headers.get("X-Auth-Token"):
                token = request.headers.get("X-Auth-Token").strip()

            if token:
                from app.database.auth_db import get_user_from_token
                user = get_user_from_token(token)

            api_key = request.headers.get("X-API-Key")
            has_valid_api_key = verify_api_key_header(api_key)

            if not user and not has_valid_api_key:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required: Invalid or missing API key or session token."},
                    headers={"WWW-Authenticate": "Bearer, ApiKey"},
                )

            # Sensitive user-vault endpoints strictly require an authenticated user session
            # An API key alone CANNOT access, query, or modify user vaults, scans, settings, or telemetry.
            if path.startswith("/api/auth/user/") or path == "/api/auth/me":
                if not user:
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "User session token required. API key alone cannot access private user data."},
                        headers={"WWW-Authenticate": "Bearer"},
                    )

            request.state.user = user

            # 5. Rate limiting per IP and per identity (User ID or API Key)
            ip_allowed, ip_retry_after = rate_limiter.check_and_record(f"ip:{client_ip}", now=now)
            if not ip_allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please retry later."},
                    headers={"Retry-After": str(ip_retry_after)},
                )

            identity_key = f"usr:{user['user_id']}" if user else f"key:{api_key}"
            id_allowed, id_retry_after = rate_limiter.check_and_record(identity_key, now=now)
            if not id_allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please retry later."},
                    headers={"Retry-After": str(id_retry_after)},
                )

        return await call_next(request)
