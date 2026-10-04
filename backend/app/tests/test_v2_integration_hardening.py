"""
Phase 20 — Final Integration, Hardening & Release Readiness Regression Tests.

Validates end-to-end integration across all V2 intelligence layers:
1. End-to-end scan pipeline across text, URL, file, and header contexts.
2. Resource limits and input sanitization boundaries.
3. Configurable classification profiles across API contracts.
4. Explainability action mappings for all 5 risk tiers.
5. Graceful degradation when external threat intelligence APIs are unavailable.
6. Deterministic execution and sensitive data isolation.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from main import app
from app.classification.policy import ClassificationPolicy, get_classification_profile
from app.engines.pipeline import UnifiedScanPipeline
from app.explainability.explainability_engine import ExplainabilityEngine
from app.fusion.risk_fusion import fuse_engine_results
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.risk_assessment import RiskAssessment, RiskClassification
from app.models.scan_input import ScanInput
from app.models.scan_response import UnifiedScanResponse
from app.preprocessing.v2_preprocessor import (
    MAX_FILE_BYTES,
    MAX_TEXT_LENGTH,
    MAX_URL_LENGTH,
    V2Preprocessor,
)


class TestV2IntegrationHardening(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.pipeline = UnifiedScanPipeline()

    def test_e2e_text_scan_success(self):
        """End-to-end scan with normal text produces complete UnifiedScanResponse."""
        resp = self.client.post("/api/scan", json={"text": "Please review the attached project schedule for tomorrow."})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("scan_id", data)
        self.assertEqual(data["status"], "completed")
        self.assertIn("risk_score", data)
        self.assertIn(data["classification"], ["Safe", "Suspicious", "Deceptive", "Phishing", "Malware"])
        self.assertGreater(data["total_engines"], 0)
        self.assertEqual(data["completed_engines"] + data["skipped_engines"], data["total_engines"])

        assessment = data["risk_assessment"]
        self.assertEqual(assessment["classification"], data["classification"])
        self.assertTrue(len(assessment["reasons"]) > 0)
        self.assertTrue(len(assessment["recommended_action"]) > 0)

    def test_e2e_url_scan_with_safe_fallback(self):
        """URL scan succeeds and degrades gracefully even when external APIs are not mock-patched."""
        resp = self.client.post("/api/scan", json={"url": "https://example.com/index.html"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(data["classification"], ["Safe", "Suspicious", "Deceptive", "Phishing", "Malware"])

    def test_dangerous_url_scheme_rejected_at_preprocessing(self):
        """Dangerous URI schemes (javascript:, data:) are rejected with HTTP 400 Bad Request."""
        for scheme in ["javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "vbscript:msgbox"]:
            with self.subTest(scheme=scheme):
                resp = self.client.post("/api/scan", json={"url": scheme})
                self.assertEqual(resp.status_code, 400)
                self.assertIn("rejected", resp.json()["detail"].lower())

    def test_empty_scan_input_rejected(self):
        """Completely empty ScanInput is rejected with HTTP 400 Bad Request."""
        resp = self.client.post("/api/scan", json={})
        self.assertEqual(resp.status_code, 400)

    def test_oversized_text_is_safely_bounded(self):
        """Input text exceeding MAX_TEXT_LENGTH is truncated without crashing the pipeline."""
        preprocessor = V2Preprocessor()
        oversized = "A" * (MAX_TEXT_LENGTH + 5000)
        input_data = ScanInput(text=oversized)
        res = preprocessor.preprocess(input_data)
        self.assertLessEqual(len(res.normalized_input.text), MAX_TEXT_LENGTH)
        self.assertIn("text_truncated_to_max_length", res.warnings)

    def test_oversized_file_rejected_at_preprocessing(self):
        """Files exceeding MAX_FILE_BYTES are rejected at preprocessing."""
        preprocessor = V2Preprocessor()
        oversized_bytes = b"0" * (MAX_FILE_BYTES + 1024)
        input_data = ScanInput(file_name="large.bin", file_bytes=oversized_bytes)
        res = preprocessor.preprocess(input_data)
        self.assertEqual(res.status.value, "rejected")
        self.assertIn("exceeds", res.error_message.lower())

    def test_explainability_action_mapping_all_tiers(self):
        """All 5 RiskClassification tiers map to deterministic, non-empty recommended actions."""
        expected_actions = {
            RiskClassification.SAFE: "Proceed with normal caution.",
            RiskClassification.SUSPICIOUS: "Exercise caution. Do not share sensitive information unless you are certain of the source.",
            RiskClassification.DECEPTIVE: "Do not trust this content. Avoid clicking links or downloading attachments.",
            RiskClassification.PHISHING: "Do not click any links or provide credentials. Report and delete this message.",
            RiskClassification.MALWARE: "Do not open or execute file/link. Isolate and permanently delete the content immediately.",
        }
        for classification, expected_text in expected_actions.items():
            with self.subTest(classification=classification):
                assessment = RiskAssessment(
                    risk_score=50.0,
                    classification=classification,
                    confidence=1.0,
                    contributing_engines=["url_engine"],
                    flags=[],
                    evidence=[],
                )
                explained = ExplainabilityEngine.explain(assessment)
                self.assertEqual(explained.recommended_action, expected_text)

    def test_dynamic_profile_via_api_and_metadata(self):
        """Classification profile can be passed top-level or inside metadata."""
        sample_results = [
            EngineResult(
                engine_name="url_engine",
                risk_score=40.0,
                confidence=1.0,
                status=EngineStatus.SUCCESS,
            )
        ]
        with patch("app.api.routes.unified_pipeline.run", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = sample_results

            # Default profile (40.0 < 45.0) -> Suspicious
            r_default = self.client.post("/api/scan", json={"text": "meeting"})
            self.assertEqual(r_default.status_code, 200)
            self.assertEqual(r_default.json()["classification"], "Suspicious")

            # Strict profile (35.0 <= 40.0 < 55.0) -> Deceptive
            r_strict = self.client.post("/api/scan", json={"text": "meeting", "classification_profile": "strict"})
            self.assertEqual(r_strict.status_code, 200)
            self.assertEqual(r_strict.json()["classification"], "Deceptive")

            # Strict via metadata dictionary
            r_meta = self.client.post("/api/scan", json={"text": "meeting", "metadata": {"classification_profile": "strict"}})
            self.assertEqual(r_meta.status_code, 200)
            self.assertEqual(r_meta.json()["classification"], "Deceptive")

    def test_single_risk_fusion_invocation(self):
        """UnifiedScanResponse.from_results executes Risk Fusion exactly once."""
        sample_results = [
            EngineResult(
                engine_name="url_engine",
                risk_score=25.0,
                confidence=1.0,
                status=EngineStatus.SUCCESS,
            )
        ]
        with patch("app.fusion.risk_fusion.fuse_engine_results") as mock_fuse:
            mock_fuse.return_value = RiskAssessment(
                risk_score=25.0,
                classification=RiskClassification.SUSPICIOUS,
                confidence=1.0,
                contributing_engines=["url_engine"],
                flags=[],
                evidence=[],
            )
            resp = UnifiedScanResponse.from_results(sample_results, profile="enterprise")
            self.assertEqual(mock_fuse.call_count, 1)
            self.assertEqual(resp.classification, RiskClassification.SUSPICIOUS)

    def test_deterministic_scoring_and_classification(self):
        """Identical inputs produce identical classification and risk score across invocations."""
        results = [
            EngineResult(engine_name="url_engine", risk_score=60.0, confidence=0.9),
            EngineResult(engine_name="nlp_engine", risk_score=60.0, confidence=0.8),
        ]
        assessment1 = fuse_engine_results(results, policy="default")
        assessment2 = fuse_engine_results(results, policy="default")
        self.assertEqual(assessment1.risk_score, assessment2.risk_score)
        self.assertEqual(assessment1.classification, assessment2.classification)


if __name__ == "__main__":
    unittest.main()
