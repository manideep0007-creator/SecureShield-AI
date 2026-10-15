import os
import sys
import unittest
from fastapi.testclient import TestClient

# Add backend directory to path so imports resolve cleanly
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from main import app
from app.api.security import rate_limiter

TEST_API_KEY = "secureshield-test-secret-key-12345"


class TestAuthAndRateLimit(unittest.TestCase):
    def setUp(self):
        os.environ["API_KEY"] = TEST_API_KEY
        rate_limiter.reset()
        self.client = TestClient(app)

    def tearDown(self):
        rate_limiter.reset()
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
