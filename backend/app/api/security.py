import math
import os
import secrets
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Callable, Tuple
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config.config import settings


class InMemoryRateLimiter:
    """Thread-safe in-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = 30, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._records: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check_and_record(self, key: str, now: float | None = None) -> Tuple[bool, int]:
        """
        Checks if the request key exceeds rate limit.
        Returns (is_allowed, retry_after_seconds).
        """
        if now is None:
            now = time.time()
        with self._lock:
            timestamps = self._records[key]
            # Evict timestamps outside the sliding window
            cutoff = now - self.window_seconds
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                oldest = timestamps[0]
                retry_after = max(1, math.ceil(oldest + self.window_seconds - now))
                return False, retry_after

            timestamps.append(now)
            return True, 0

    def reset(self):
        """Clears all recorded rate limit windows (useful for testing)."""
        with self._lock:
            self._records.clear()


# Separate limiters for sensitive actions (Phase 2: API Security & Rate Limiting)
rate_limiter = InMemoryRateLimiter(max_requests=30, window_seconds=60.0)          # General scan
auth_login_limiter = InMemoryRateLimiter(max_requests=10, window_seconds=60.0)    # 10 attempts / min
auth_register_limiter = InMemoryRateLimiter(max_requests=5, window_seconds=60.0)  # 5 registrations / min
general_api_limiter = InMemoryRateLimiter(max_requests=60, window_seconds=60.0)   # 60 req / min

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


def verify_api_key_header(api_key: str | None) -> bool:
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

        # Extract client IP
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
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

        # 4. Enforce API Key authentication on all other /api/* endpoints
        if path.startswith("/api/"):
            api_key = request.headers.get("X-API-Key")
            if not verify_api_key_header(api_key):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key."},
                    headers={"WWW-Authenticate": "ApiKey"},
                )

            # 5. Rate limiting per IP and per API Key on scan and protected endpoints
            ip_allowed, ip_retry_after = rate_limiter.check_and_record(f"ip:{client_ip}", now=now)
            if not ip_allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please retry later."},
                    headers={"Retry-After": str(ip_retry_after)},
                )

            key_allowed, key_retry_after = rate_limiter.check_and_record(f"key:{api_key}", now=now)
            if not key_allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please retry later."},
                    headers={"Retry-After": str(key_retry_after)},
                )

        return await call_next(request)
