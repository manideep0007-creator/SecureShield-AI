import os
import sys
import time
import unittest
from fastapi.testclient import TestClient

# Add backend directory to path so imports resolve cleanly
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from main import app
from app.api.security import rate_limiter, auth_login_limiter, auth_register_limiter

TEST_API_KEY = "secureshield-test-secret-key-12345"


class TestAuthAndRateLimit(unittest.TestCase):
    def setUp(self):
        os.environ["API_KEY"] = TEST_API_KEY
        rate_limiter.reset()
        auth_login_limiter.reset()
        auth_register_limiter.reset()
        self.client = TestClient(app)

    def tearDown(self):
        rate_limiter.reset()
        auth_login_limiter.reset()
        auth_register_limiter.reset()
        self.client.close()

    def test_health_and_root_endpoints_open_without_api_key(self):
        """Root and health check endpoints must remain publicly accessible without auth."""
        res_root = self.client.get("/")
        self.assertEqual(res_root.status_code, 200)
        self.assertEqual(res_root.json()["status"], "running")

        res_health = self.client.get("/health")
        self.assertEqual(res_health.status_code, 200)
        self.assertEqual(res_health.json()["status"], "running")

        res_api_health = self.client.get("/api/health")
        self.assertEqual(res_api_health.status_code, 200)
        self.assertEqual(res_api_health.json()["status"], "running")

    def test_missing_api_key_returns_401(self):
        """Protected /api/* routes must return 401 when X-API-Key header is omitted."""
        # /api/scan
        res_scan = self.client.post("/api/scan", json={"url": "https://example.com"})
        self.assertEqual(res_scan.status_code, 401)
        self.assertIn("Invalid or missing API key", res_scan.json()["detail"])

        # /api/feedback
        res_feedback = self.client.post("/api/feedback", json={})
        self.assertEqual(res_feedback.status_code, 401)

        # /api/evaluation/metrics
        res_metrics = self.client.get("/api/evaluation/metrics")
        self.assertEqual(res_metrics.status_code, 401)

    def test_wrong_api_key_returns_401(self):
        """Protected /api/* routes must return 401 when an invalid X-API-Key is provided."""
        res_scan = self.client.post(
            "/api/scan",
            json={"url": "https://example.com"},
            headers={"X-API-Key": "incorrect-api-key-999"},
        )
        self.assertEqual(res_scan.status_code, 401)
        self.assertIn("Invalid or missing API key", res_scan.json()["detail"])

    def test_valid_api_key_allows_access(self):
        """Protected /api/* routes succeed with 200 when a valid X-API-Key is supplied."""
        # /api/evaluation/metrics returns 200 with valid key
        res_metrics = self.client.get(
            "/api/evaluation/metrics",
            headers={"X-API-Key": TEST_API_KEY},
        )
        self.assertEqual(res_metrics.status_code, 200)

        # /api/scan returns 200 with valid key and payload
        res_scan = self.client.post(
            "/api/scan",
            json={"url": "https://example.com"},
            headers={"X-API-Key": TEST_API_KEY},
        )
        self.assertEqual(res_scan.status_code, 200)

    def test_rate_limiting_burst_returns_429_with_retry_after(self):
        """Sending more than 30 requests in a minute returns 429 with Retry-After header."""
        # Send 30 allowed requests
        for i in range(30):
            res = self.client.get(
                "/api/evaluation/metrics",
                headers={"X-API-Key": TEST_API_KEY, "X-Forwarded-For": "198.51.100.1"},
            )
            self.assertEqual(
                res.status_code,
                200,
                f"Request {i+1} of 30 should succeed under rate limit",
            )

        # 31st request exceeds rate limit (burst)
        burst_res = self.client.get(
            "/api/evaluation/metrics",
            headers={"X-API-Key": TEST_API_KEY, "X-Forwarded-For": "198.51.100.1"},
        )
        self.assertEqual(burst_res.status_code, 429)
        self.assertIn("Rate limit exceeded", burst_res.json()["detail"])
        self.assertIn("Retry-After", burst_res.headers)
        self.assertGreaterEqual(int(burst_res.headers["Retry-After"]), 1)

    def test_rate_limiting_tracks_per_ip_and_per_key(self):
        """Rate limit enforces both per-IP and per-API key buckets."""
        # Exhaust key quota from IP 1
        for _ in range(30):
            res = self.client.get(
                "/api/evaluation/metrics",
                headers={"X-API-Key": TEST_API_KEY, "X-Forwarded-For": "198.51.100.1"},
            )
            self.assertEqual(res.status_code, 200)

        # Request with same key from IP 2 is blocked (per-key quota exhausted)
        res_ip2 = self.client.get(
            "/api/evaluation/metrics",
            headers={"X-API-Key": TEST_API_KEY, "X-Forwarded-For": "198.51.100.2"},
        )
        self.assertEqual(res_ip2.status_code, 429)

    def test_registration_rate_limiting(self):
        """Mass account creation rate limiting (max 5 per min per IP)."""
        ip = "203.0.113.50"
        ts = int(time.time() * 1000)
        for i in range(5):
            res = self.client.post(
                "/api/auth/register",
                json={"email": f"mass_user_{ts}_{i}@shield.ai", "password": "Password123!", "full_name": "Mass"},
                headers={"X-Forwarded-For": ip}
            )
            self.assertEqual(res.status_code, 201)

        # 6th attempt is blocked with 429
        blocked = self.client.post(
            "/api/auth/register",
            json={"email": f"mass_user_{ts}_blocked@shield.ai", "password": "Password123!", "full_name": "Mass"},
            headers={"X-Forwarded-For": ip}
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Too many registration attempts", blocked.json()["detail"])

    def test_login_brute_force_rate_limiting(self):
        """Login brute-force rate limiting (max 10 per min per IP)."""
        ip = "203.0.113.60"
        for _ in range(10):
            res = self.client.post(
                "/api/auth/login",
                json={"email": "victim@shield.ai", "password": "WrongPassword!"},
                headers={"X-Forwarded-For": ip}
            )
            self.assertEqual(res.status_code, 401)

        # 11th attempt is blocked with 429
        blocked = self.client.post(
            "/api/auth/login",
            json={"email": "victim@shield.ai", "password": "WrongPassword!"},
            headers={"X-Forwarded-For": ip}
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Too many authentication attempts", blocked.json()["detail"])

    def test_bearer_user_token_authorizes_protected_endpoints(self):
        """User session token allows access to protected endpoints without API key."""
        from app.database.auth_db import create_user, create_session
        user = create_user(email=f"bearer_test_{time.time()}@shield.ai", password="SessionPassword123!", full_name="Bearer Tester")
        token = create_session(user["user_id"])

        # Access with Bearer token, NO X-API-Key
        res = self.client.get(
            "/api/evaluation/metrics",
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res.status_code, 200)

        # Access with invalid Bearer token fails with 401
        bad_res = self.client.get(
            "/api/evaluation/metrics",
            headers={"Authorization": "Bearer invalid_or_expired_token_123"}
        )
        self.assertEqual(bad_res.status_code, 401)
        self.assertIn("Authentication required", bad_res.json()["detail"])

    def test_untrusted_proxy_cannot_spoof_client_ip(self):
        """When peer host is not in trusted proxy list, X-Forwarded-For is ignored."""
        from app.api.security import is_trusted_proxy
        self.assertFalse(is_trusted_proxy("203.0.113.195"))
        self.assertTrue(is_trusted_proxy("127.0.0.1"))
        self.assertTrue(is_trusted_proxy("10.0.0.5"))
        self.assertTrue(is_trusted_proxy("testclient"))

    def test_shared_rate_limiter_cross_worker_concurrency(self):
        """Verify that separate rate limiter instances sharing the same DB file share quota."""
        from app.api.security import SharedRateLimiter
        db_name = f"worker_test_{int(time.time() * 1000)}.db"
        worker_1 = SharedRateLimiter(max_requests=3, window_seconds=60.0, db_name=db_name)
        worker_2 = SharedRateLimiter(max_requests=3, window_seconds=60.0, db_name=db_name)

        try:
            worker_1.reset()
            # Worker 1 records 2 requests
            ok1, _ = worker_1.check_and_record("shared_key")
            ok2, _ = worker_1.check_and_record("shared_key")
            self.assertTrue(ok1)
            self.assertTrue(ok2)

            # Worker 2 records 3rd request (should succeed)
            ok3, _ = worker_2.check_and_record("shared_key")
            self.assertTrue(ok3)

            # Worker 1 records 4th request (should be rejected across processes!)
            ok4, retry = worker_1.check_and_record("shared_key")
            self.assertFalse(ok4)
            self.assertGreaterEqual(retry, 1)
        finally:
            worker_1.reset()
            worker_2.reset()

    def test_rate_limiter_fails_closed_on_storage_failure(self):
        """Sensitive limiters configured with fail_closed=True must reject requests when storage fails."""
        from app.api.security import SharedRateLimiter
        from unittest.mock import patch
        import sqlite3

        limiter = SharedRateLimiter(
            max_requests=5,
            window_seconds=60.0,
            fail_closed=True
        )
        with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("Database disk I/O error")):
            allowed, retry_after = limiter.check_and_record("sensitive_key")
            self.assertFalse(allowed)
            self.assertEqual(retry_after, 60)

    def test_rate_limiter_redis_atomic_lua_script(self):
        """Verify Redis Lua script structure handles atomic sliding window."""
        from app.api.security import REDIS_SLIDING_WINDOW_LUA
        self.assertIn("ZREMRANGEBYSCORE", REDIS_SLIDING_WINDOW_LUA)
        self.assertIn("ZCARD", REDIS_SLIDING_WINDOW_LUA)
        self.assertIn("ZADD", REDIS_SLIDING_WINDOW_LUA)
        self.assertIn("EXPIRE", REDIS_SLIDING_WINDOW_LUA)
