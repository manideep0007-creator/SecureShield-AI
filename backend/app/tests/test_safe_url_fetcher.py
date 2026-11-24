"""
Tests for SafeURLFetcher SSRF Prevention.

Validates that:
1. Requests targeting 127.0.0.1 never reach a real local HTTP server.
2. Requests targeting localhost never reach a real local HTTP server.
3. Redirects pointing to 127.0.0.1 or localhost are blocked before connection.
4. is_safe_ip correctly identifies unsafe IP ranges.
"""

import http.server
import os
import socket
import sys
import threading
import unittest
from unittest.mock import patch, AsyncMock
import httpx

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.preprocessing.safe_url_fetcher import SafeURLFetcher, is_safe_ip


class TrackingHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that records any requests that reach the server."""

    def do_HEAD(self):
        self.server.received_requests.append({
            "method": "HEAD",
            "path": self.path,
            "headers": dict(self.headers),
        })
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.server.received_requests.append({
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
        })
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress standard logging during tests
        pass


class TestSSRFPrevention(unittest.IsolatedAsyncioTestCase):
    """Test suite ensuring SSRF protection reliably blocks loopback and internal requests."""

    def _start_server(self, host: str):
        server = http.server.HTTPServer((host, 0), TrackingHandler)
        server.received_requests = []
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, port

    async def test_ssrf_blocked_on_127_0_0_1(self):
        """A real local HTTP server listening on 127.0.0.1 must NEVER receive requests."""
        server, port = self._start_server("127.0.0.1")
        try:
            target_url = f"http://127.0.0.1:{port}/admin/internal-keys"
            resolved = await SafeURLFetcher.resolve_redirects(target_url)

            # Assert the request was never transmitted to the local server
            self.assertEqual(
                len(server.received_requests),
                0,
                f"SSRF violation: request reached 127.0.0.1 server: {server.received_requests}"
            )
            # SafeURLFetcher safely returns the target URL without opening an HTTP connection
            self.assertEqual(resolved, target_url)
        finally:
            server.shutdown()
            server.server_close()

    async def test_ssrf_blocked_on_localhost(self):
        """A real local HTTP server listening on localhost must NEVER receive requests."""
        server, port = self._start_server("localhost")
        try:
            target_url = f"http://localhost:{port}/v1/cloud-metadata"
            resolved = await SafeURLFetcher.resolve_redirects(target_url)

            # Assert the request was never transmitted to the local server
            self.assertEqual(
                len(server.received_requests),
                0,
                f"SSRF violation: request reached localhost server: {server.received_requests}"
            )
            self.assertEqual(resolved, target_url)
        finally:
            server.shutdown()
            server.server_close()

    async def test_ssrf_blocked_on_redirect_to_local(self):
        """Chained redirect targeting 127.0.0.1 must be blocked before the second hop connects."""
        secret_server, secret_port = self._start_server("127.0.0.1")

        # Create a redirector handler that attempts to pivot to the internal secret server
        redirector_requests = []

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                redirector_requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{secret_port}/leak-secret")
                self.end_headers()

            def do_GET(self):
                redirector_requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{secret_port}/leak-secret")
                self.end_headers()

            def log_message(self, *args):
                pass

        redirector_server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirector_port = redirector_server.server_address[1]
        threading.Thread(target=redirector_server.serve_forever, daemon=True).start()

        try:
            # When resolve_redirects is called on the redirector (which itself is 127.0.0.1),
            # it should block even the first hop because 127.0.0.1 is unsafe.
            res = await SafeURLFetcher.resolve_redirects(f"http://127.0.0.1:{redirector_port}/redirect")
            self.assertEqual(len(secret_server.received_requests), 0)
            self.assertEqual(len(redirector_requests), 0)
        finally:
            secret_server.shutdown()
            secret_server.server_close()
            redirector_server.shutdown()
            redirector_server.server_close()

    async def test_ssrf_blocked_on_open_redirect_pivot(self):
        """When an external site redirects to 127.0.0.1, the second hop is blocked before connecting to the real local server."""
        secret_server, secret_port = self._start_server("127.0.0.1")

        orig_getaddrinfo = socket.getaddrinfo
        def fake_getaddrinfo(host, port, *args, **kwargs):
            if host == "safe-redirector.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', port or 80))]
            return orig_getaddrinfo(host, port, *args, **kwargs)

        fake_resp = httpx.Response(302, headers={"Location": f"http://127.0.0.1:{secret_port}/stolen-data"})
        
        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with patch("httpx.AsyncClient.head", new_callable=AsyncMock) as mock_head:
                mock_head.return_value = fake_resp
                res = await SafeURLFetcher.resolve_redirects("http://safe-redirector.com/go")

        # The first hop simulated contacting the external redirector
        self.assertEqual(mock_head.call_count, 1)
        # But the real local server on 127.0.0.1 NEVER received any request
        self.assertEqual(
            len(secret_server.received_requests),
            0,
            f"SSRF violation: secret server reached on redirect: {secret_server.received_requests}"
        )
        self.assertEqual(res, f"http://127.0.0.1:{secret_port}/stolen-data")

        secret_server.shutdown()
        secret_server.server_close()

    def test_is_safe_ip_boundaries(self):
        """Validate is_safe_ip accurately blocks all loopback, private, and reserved ranges."""
        # Unsafe IPv4
        self.assertFalse(is_safe_ip("127.0.0.1"))
        self.assertFalse(is_safe_ip("127.0.0.2"))
        self.assertFalse(is_safe_ip("0.0.0.0"))
        self.assertFalse(is_safe_ip("10.0.0.1"))
        self.assertFalse(is_safe_ip("172.16.0.1"))
        self.assertFalse(is_safe_ip("192.168.1.1"))
        self.assertFalse(is_safe_ip("169.254.169.254"))
        self.assertFalse(is_safe_ip("100.64.0.1"))
        self.assertFalse(is_safe_ip("224.0.0.1"))
        self.assertFalse(is_safe_ip("240.0.0.1"))

        # Unsafe IPv6
        self.assertFalse(is_safe_ip("::1"))
        self.assertFalse(is_safe_ip("::"))
        self.assertFalse(is_safe_ip("fe80::1"))
        self.assertFalse(is_safe_ip("::ffff:127.0.0.1"))
        self.assertFalse(is_safe_ip("::ffff:192.168.1.1"))
        self.assertFalse(is_safe_ip("::ffff:169.254.169.254"))

        # Safe public IPs
        self.assertTrue(is_safe_ip("8.8.8.8"))
        self.assertTrue(is_safe_ip("1.1.1.1"))
        self.assertTrue(is_safe_ip("2606:4700:4700::1111"))

        # Invalid strings
        self.assertFalse(is_safe_ip("invalid_ip"))
        self.assertFalse(is_safe_ip(""))

    def test_is_safe_ip_extended_ranges(self):
        """Validate extended cloud metadata and reserved IP ranges are blocked."""
        # Cloud metadata and internal services
        self.assertFalse(is_safe_ip("168.63.129.16"))
        self.assertFalse(is_safe_ip("100.100.100.200"))

        # 0.0.0.0/8 source-only network
        self.assertFalse(is_safe_ip("0.0.0.1"))
        self.assertFalse(is_safe_ip("0.255.255.255"))

        # Broadcast
        self.assertFalse(is_safe_ip("255.255.255.255"))

        # Documentation and benchmark ranges
        self.assertFalse(is_safe_ip("198.18.0.5"))
        self.assertFalse(is_safe_ip("192.0.2.100"))
        self.assertFalse(is_safe_ip("198.51.100.42"))
        self.assertFalse(is_safe_ip("203.0.113.1"))

        # IPv6 documentation and discard
        self.assertFalse(is_safe_ip("100::1"))
        self.assertFalse(is_safe_ip("2001:db8::1"))
        self.assertFalse(is_safe_ip("fc00::1"))

    def test_validate_url_syntax_blocks_prohibited_hosts(self):
        """Validate that internal hostnames and internal suffixes are rejected at syntax validation."""
        for url in [
            "http://localhost/test",
            "http://metadata.google.internal/computeMetadata",
            "http://instance-data/latest/meta-data",
            "http://metadata.azure.com/metadata",
            "http://database.local/admin",
            "http://internal-service.internal/api",
            "http://corp-router.lan/config",
            "http://files.localdomain/secret",
            "http://server.corp/login",
            "http://nas.home/backups",
            "http://domain.arpa/dns",
        ]:
            with self.assertRaises(ValueError, msg=f"Should reject {url}"):
                SafeURLFetcher.validate_url_syntax(url)

    def test_validate_url_syntax_blocks_integer_and_hex_ips(self):
        """Validate integer and hex IP obfuscation targeting loopback or internal addresses is rejected."""
        # 2130706433 == 127.0.0.1
        with self.assertRaises(ValueError):
            SafeURLFetcher.validate_url_syntax("http://2130706433/path")

        # 0x7f000001 == 127.0.0.1
        with self.assertRaises(ValueError):
            SafeURLFetcher.validate_url_syntax("http://0x7f000001/path")

        # 2852039166 == 169.254.169.254
        with self.assertRaises(ValueError):
            SafeURLFetcher.validate_url_syntax("http://2852039166/latest")

    async def test_circular_redirect_handling(self):
        """Verify circular redirect loop terminates without exceeding limit or hanging."""
        # Simulate A -> B -> A redirect loop
        call_count = 0

        async def fake_head(url, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if "page-a" in url:
                return httpx.Response(302, headers={"Location": "http://safe-site.com/page-b"})
            else:
                return httpx.Response(302, headers={"Location": "http://safe-site.com/page-a"})

        orig_getaddrinfo = socket.getaddrinfo
        def fake_getaddrinfo(host, port, *args, **kwargs):
            if host == "safe-site.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', port or 80))]
            return orig_getaddrinfo(host, port, *args, **kwargs)

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with patch("httpx.AsyncClient.head", side_effect=fake_head):
                result = await SafeURLFetcher.resolve_redirects("http://safe-site.com/page-a", max_redirects=5)

        # Loop must terminate early due to visited_urls detection
        self.assertLessEqual(call_count, 3)
        self.assertIn("safe-site.com", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
