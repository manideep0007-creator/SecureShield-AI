"""
Unit and Integration Tests for Phase 18 — V2 Preprocessing & Input Normalization.

Tests all 20 required scenarios:
1. normal text normalization
2. whitespace normalization
3. Unicode normalization
4. empty input
5. malformed text input
6. valid URL normalization
7. malformed URL handling
8. URL credentials rejection compatibility
9. file metadata normalization
10. 10 MB file boundary
11. oversized file rejection
12. filename sanitization
13. email metadata normalization
14. Authentication-Results preservation
15. Received-chain bounding
16. oversized metadata/list handling
17. deterministic preprocessing
18. preprocessing failure isolation
19. Android/API regression compatibility
20. complete unified pipeline regression
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.engines.pipeline import UnifiedScanPipeline
from main import app
from app.models.scan_input import ScanInput
from app.preprocessing import (
    MAX_FILE_BYTES,
    MAX_FILENAME_LENGTH,
    MAX_METADATA_ITEMS,
    MAX_RECEIVED_HOPS,
    MAX_TEXT_LENGTH,
    MAX_URL_LENGTH,
    PreprocessingResult,
    PreprocessingStatus,
    SafeURLFetcher,
    V2Preprocessor,
    normalize_email_metadata,
    normalize_file,
    normalize_text,
    normalize_url,
)


class TestV2Preprocessing(unittest.TestCase):
    def setUp(self):
        self.preprocessor = V2Preprocessor()

    # 1. normal text normalization
    def test_normal_text_normalization(self):
        text = "URGENT! Please verify your password immediately to avoid suspension."
        norm_text, warnings = normalize_text(text)
        self.assertEqual(norm_text, text)
        self.assertEqual(warnings, [])

        res = self.preprocessor.preprocess(ScanInput(text=text))
        self.assertEqual(res.status, PreprocessingStatus.SUCCESS)
        self.assertEqual(res.normalized_input.text, text)
        self.assertEqual(res.warnings, [])

    # 2. whitespace normalization
    def test_whitespace_normalization(self):
        messy_text = "  Line   one with   spaces.  \t\n\n\n\n\nLine   two.\r\nLine   three.  "
        norm_text, warnings = normalize_text(messy_text)
        expected = "Line one with spaces.\n\nLine two.\nLine three."
        self.assertEqual(norm_text, expected)

    # 3. Unicode normalization
    def test_unicode_normalization(self):
        # Fullwidth 'Password' -> 'Password' via NFKC
        fullwidth_text = "\uff30\uff41\uff53\uff53\uff57\uff4f\uff52\uff44"
        norm_text, warnings = normalize_text(fullwidth_text)
        self.assertEqual(norm_text, "Password")

        # Ligature 'fi' and non-breaking space
        ligature_text = "\ufb01le\u00a0name"
        norm_text, warnings = normalize_text(ligature_text)
        self.assertEqual(norm_text, "file name")

        # Multilingual content preserved
        intl_text = "Sécurité de connexion: ログインしてください"
        norm_text, warnings = normalize_text(intl_text)
        self.assertEqual(norm_text, intl_text)

    # 4. empty input
    def test_empty_input(self):
        empty_input = ScanInput()
        res = self.preprocessor.preprocess(empty_input)
        self.assertEqual(res.status, PreprocessingStatus.REJECTED)
        self.assertIn("no valid scannable content", res.error_message)

        whitespace_input = ScanInput(text="   \n\t   ")
        res_ws = self.preprocessor.preprocess(whitespace_input)
        self.assertEqual(res_ws.status, PreprocessingStatus.REJECTED)

    # 5. malformed text input
    def test_malformed_text_input(self):
        # Stripping ASCII control characters except \n, \r, \t
        control_text = "Hello\x00\x01\x02\x07World\x7f!"
        norm_text, warnings = normalize_text(control_text)
        self.assertEqual(norm_text, "HelloWorld!")
        self.assertIn("control_characters_stripped", warnings)

        # Bounding long text
        oversized_text = "A" * (MAX_TEXT_LENGTH + 500)
        norm_text, warnings = normalize_text(oversized_text)
        self.assertEqual(len(norm_text), MAX_TEXT_LENGTH)
        self.assertIn("text_truncated_to_max_length", warnings)

    # 6. valid URL normalization
    def test_valid_url_normalization(self):
        # Lowercase scheme/host and strip default port 443
        url = "  HTTPS://ExAmPlE.Com:443/Path/To/Page?key=Val#Sec  "
        norm_url, warnings, is_valid = normalize_url(url)
        self.assertTrue(is_valid)
        self.assertEqual(norm_url, "https://example.com/Path/To/Page?key=Val#Sec")

        # Strip enclosing angle brackets
        bracket_url = "<http://example.com/test>"
        norm_url, warnings, is_valid = normalize_url(bracket_url)
        self.assertTrue(is_valid)
        self.assertEqual(norm_url, "http://example.com/test")

        # Default scheme to http when missing
        no_scheme = "example.com/login"
        norm_url, warnings, is_valid = normalize_url(no_scheme)
        self.assertTrue(is_valid)
        self.assertEqual(norm_url, "http://example.com/login")
        self.assertIn("url_scheme_defaulted_to_http", warnings)

    # 7. malformed URL handling
    def test_malformed_url_handling(self):
        # Dangerous schemes
        for bad_scheme in ["javascript:alert(1)", "file:///etc/passwd", "data:text/html;base64,PHNjcmlwdD4="]:
            norm_url, warnings, is_valid = normalize_url(bad_scheme)
            self.assertFalse(is_valid)
            self.assertTrue(any("unsupported_scheme" in w for w in warnings))

        # Missing host
        norm_url, warnings, is_valid = normalize_url("http://")
        self.assertFalse(is_valid)
        self.assertIn("missing_url_host", warnings)

        # Oversized URL
        huge_url = "http://example.com/" + "a" * (MAX_URL_LENGTH + 10)
        norm_url, warnings, is_valid = normalize_url(huge_url)
        self.assertFalse(is_valid)
        self.assertIn("url_exceeds_max_length", warnings)

    # 8. URL credentials rejection compatibility
    def test_url_credentials_rejection_compatibility(self):
        url_with_creds = "http://admin:secret@phishing-target.com/login"
        norm_url, warnings, is_valid = normalize_url(url_with_creds)
        self.assertTrue(is_valid)
        self.assertIn("url_embedded_credentials_present", warnings)
        self.assertEqual(norm_url, "http://admin:secret@phishing-target.com/login")

        # Verify that existing SSRF protection in SafeURLFetcher rejects it
        with self.assertRaises(ValueError) as ctx:
            SafeURLFetcher.validate_url_syntax(norm_url)
        self.assertIn("Embedded URL credentials are not allowed", str(ctx.exception))

    # 9. file metadata normalization
    def test_file_metadata_normalization(self):
        # PDF disguised as txt
        pdf_bytes = b"%PDF-1.4\n%Fake PDF content"
        clean_name, out_bytes, details, warnings, is_valid = normalize_file(
            file_name="invoice.txt", file_bytes=pdf_bytes
        )
        self.assertTrue(is_valid)
        self.assertEqual(clean_name, "invoice.txt")
        self.assertEqual(out_bytes, pdf_bytes)
        self.assertTrue(details.get("extension_mismatch"))
        self.assertEqual(details.get("actual_ext"), "pdf")

    # 10. 10 MB file boundary
    def test_10mb_file_boundary(self):
        exact_10mb_bytes = b"X" * MAX_FILE_BYTES
        clean_name, out_bytes, details, warnings, is_valid = normalize_file(
            file_name="safe.bin", file_bytes=exact_10mb_bytes
        )
        self.assertTrue(is_valid)
        self.assertEqual(len(out_bytes), MAX_FILE_BYTES)

    # 11. oversized file rejection
    def test_oversized_file_rejection(self):
        oversized_bytes = b"X" * (MAX_FILE_BYTES + 1)
        clean_name, out_bytes, details, warnings, is_valid = normalize_file(
            file_name="huge.bin", file_bytes=oversized_bytes
        )
        self.assertFalse(is_valid)
        self.assertIn("file_exceeds_10mb_limit", warnings)

        res = self.preprocessor.preprocess(
            ScanInput(file_name="huge.bin", file_bytes=oversized_bytes)
        )
        self.assertEqual(res.status, PreprocessingStatus.REJECTED)
        self.assertEqual(res.error_message, "File exceeds maximum allowed size of 10MB")

    # 12. filename sanitization
    def test_filename_sanitization(self):
        # Path traversal removal
        traversal_name = "../../etc/passwd"
        clean_name, _, _, _, is_valid = normalize_file(traversal_name, b"safe content")
        self.assertEqual(clean_name, "passwd")

        # Windows backslash path traversal
        win_traversal = "..\\..\\windows\\system32\\calc.exe"
        clean_name, _, _, _, is_valid = normalize_file(win_traversal, b"safe content")
        self.assertEqual(clean_name, "calc.exe")

        # Control characters in filename
        ctrl_name = "doc\x00ument.pdf"
        clean_name, _, _, warnings, is_valid = normalize_file(ctrl_name, b"safe content")
        self.assertEqual(clean_name, "document.pdf")
        self.assertIn("filename_control_characters_stripped", warnings)

        # Long filename truncation
        long_name = "A" * (MAX_FILENAME_LENGTH + 50) + ".pdf"
        clean_name, _, _, warnings, is_valid = normalize_file(long_name, b"safe content")
        self.assertEqual(len(clean_name), MAX_FILENAME_LENGTH)
        self.assertIn("filename_truncated_to_max_length", warnings)

    # 13. email metadata normalization
    def test_email_metadata_normalization(self):
        # Sender with display name
        sender_raw = "Security Notification <Alerts@BankOfAmerica.COM>"
        clean_sender, _, _ = normalize_email_metadata(sender_raw, {})
        self.assertEqual(clean_sender, "alerts@bankofamerica.com")

        # Plain email
        sender_plain = "  User@Company.Org  "
        clean_sender, _, _ = normalize_email_metadata(sender_plain, {})
        self.assertEqual(clean_sender, "user@company.org")

        # Name without @ preserved
        sender_name = "Internal IT Helpdesk"
        clean_sender, _, _ = normalize_email_metadata(sender_name, {})
        self.assertEqual(clean_sender, "Internal IT Helpdesk")

    # 14. Authentication-Results preservation
    def test_authentication_results_preservation(self):
        auth_headers = {
            "Authentication-Results": "mx.google.com; dkim=pass header.i=@secure.com; spf=pass",
            "Received-SPF": "pass (google.com: domain of alert@secure.com designates 1.2.3.4 as permitted sender)",
            "Message-ID": "<abc.123@secure.com>",
            "Date": "Wed, 01 Oct 2026 12:00:00 +0000",
            "Return-Path": "<alert@secure.com>",
            "Reply-To": "support@secure.com",
        }
        _, meta, warnings = normalize_email_metadata("test@example.com", {"headers": auth_headers})
        norm_headers = meta["headers"]
        self.assertEqual(norm_headers["Authentication-Results"], auth_headers["Authentication-Results"])
        self.assertEqual(norm_headers["Received-SPF"], auth_headers["Received-SPF"])
        self.assertEqual(norm_headers["Message-ID"], auth_headers["Message-ID"])
        self.assertEqual(norm_headers["Date"], auth_headers["Date"])
        self.assertEqual(norm_headers["Return-Path"], auth_headers["Return-Path"])
        self.assertEqual(norm_headers["Reply-To"], auth_headers["Reply-To"])

    # 15. Received-chain bounding
    def test_received_chain_bounding(self):
        hops = [f"from mail{i}.server.com by mx.google.com" for i in range(50)]
        metadata = {"headers": {"received": hops}}
        _, meta, warnings = normalize_email_metadata("test@example.com", metadata)
        norm_received = meta["headers"]["received"]
        self.assertEqual(len(norm_received), MAX_RECEIVED_HOPS)
        self.assertIn("received_chain_hops_truncated", warnings)

    # 16. oversized metadata/list handling
    def test_oversized_metadata_list_handling(self):
        huge_meta = {f"custom_key_{i}": f"val_{i}" for i in range(MAX_METADATA_ITEMS + 30)}
        _, meta, warnings = normalize_email_metadata("test@example.com", huge_meta)
        self.assertEqual(len(meta), MAX_METADATA_ITEMS)
        self.assertIn("metadata_items_limit_exceeded", warnings)

    # 17. deterministic preprocessing
    def test_deterministic_preprocessing(self):
        input_data = ScanInput(
            text="Please  verify   your account.\r\nThanks!",
            url="HTTPS://SECURE-BANK.COM:443/login",
            sender_id="Security <Admin@Secure-Bank.COM>",
            file_name="..\\invoice.pdf",
            file_bytes=b"%PDF-1.4\nTest",
            metadata={"headers": {"Authentication-Results": "spf=pass"}},
        )

        run1 = self.preprocessor.preprocess(input_data)
        run2 = self.preprocessor.preprocess(input_data)

        self.assertEqual(run1.status, run2.status)
        self.assertEqual(run1.normalized_input.text, run2.normalized_input.text)
        self.assertEqual(run1.normalized_input.url, run2.normalized_input.url)
        self.assertEqual(run1.normalized_input.sender_id, run2.normalized_input.sender_id)
        self.assertEqual(run1.normalized_input.file_name, run2.normalized_input.file_name)
        self.assertEqual(run1.warnings, run2.warnings)
        self.assertEqual(run1.details, run2.details)

    # 18. preprocessing failure isolation
    def test_preprocessing_failure_isolation(self):
        # Create an input that throws an unexpected error during preprocessing
        with patch("app.preprocessing.v2_preprocessor.normalize_text", side_effect=RuntimeError("Unexpected text failure")):
            res = self.preprocessor.preprocess(ScanInput(text="test text"))
            self.assertEqual(res.status, PreprocessingStatus.REJECTED)
            self.assertIn("Unexpected text failure", res.error_message)
            self.assertTrue(any("preprocessing_error" in w for w in res.warnings))


class TestV2PipelineAndAPIRegression(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.pipeline = UnifiedScanPipeline()
        self.client = TestClient(app)

    # 19. Android/API regression compatibility
    def test_android_api_regression_compatibility(self):
        # Valid message scan via /api/scan
        resp = self.client.post("/api/scan", json={"text": "Hello, this is a test message"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("classification", data)
        self.assertIn("risk_score", data)
        self.assertIn("results", data)

        # Empty scan payload rejected with 400
        empty_resp = self.client.post("/api/scan", json={})
        self.assertEqual(empty_resp.status_code, 400)

        # Malformed URL rejected with 400
        bad_url_resp = self.client.post("/api/scan", json={"url": "javascript:alert(1)"})
        self.assertEqual(bad_url_resp.status_code, 400)

    # 20. complete unified pipeline regression
    @patch("app.engines.url_engine.check_google_safe_browsing", new_callable=AsyncMock)
    @patch("app.engines.malware_engine.check_virustotal", new_callable=AsyncMock)
    async def test_complete_unified_pipeline_regression(self, mock_vt, mock_gsb):
        mock_gsb.return_value = {"gsb_score": 0.0, "gsb_threats": []}
        mock_vt.return_value = {"score": 0.0, "flags": []}

        input_data = ScanInput(
            text="  URGENT:   Verify your credentials now!  \r\n\r\n",
            url="  HTTPS://SECURE-LOGIN.COM:443/auth  ",
            sender_id="Billing Team <billing@secure-login.com>",
            file_name="../../documents/receipt.txt",
            file_bytes=b"%PDF-1.4\nFake Receipt",
            metadata={
                "headers": {
                    "Authentication-Results": "spf=pass dkim=pass",
                    "Received": [f"hop {i}" for i in range(10)],
                }
            },
        )

        results = await self.pipeline.run(input_data)
        self.assertGreater(len(results), 0)

        # Ensure all expected engines executed
        executed_engines = {r.engine_name for r in results}
        self.assertIn("nlp_engine", executed_engines)
        self.assertIn("url_engine", executed_engines)
        self.assertIn("malware_engine", executed_engines)
        self.assertIn("sender_engine", executed_engines)
        self.assertIn("header_analysis_engine", executed_engines)
        self.assertIn("attachment_behavior_engine", executed_engines)

        # Verify extension mismatch flag added to malware engine
        malware_res = next(r for r in results if r.engine_name == "malware_engine")
        self.assertIn("extension_mismatch", malware_res.flags)

        # Verify NLP detected urgency
        nlp_res = next(r for r in results if r.engine_name == "nlp_engine")
        self.assertIn("nlp_urgency", nlp_res.flags)


if __name__ == "__main__":
    unittest.main(verbosity=2)
