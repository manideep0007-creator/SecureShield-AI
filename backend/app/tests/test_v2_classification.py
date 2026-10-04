"""
Unit and Integration Tests for Phase 19 — V2 Dynamic Risk Classification.

Tests all 20 required scenarios:
1. Default profile reproduces current classification exactly.
2. Safe boundary.
3. Suspicious boundary.
4. Deceptive boundary.
5. Phishing boundary.
6. 90+ non-malware score remains Phishing.
7. Malware signal produces Malware under the existing malware rule.
8. Strict profile.
9. Enterprise profile.
10. Unknown profile handling.
11. Invalid threshold ordering.
12. Threshold values outside 0–100.
13. Deterministic classification.
14. Risk score exactly at every boundary.
15. Explainability receives the correct classification.
16. API response compatibility.
17. Feedback data cannot automatically change classification.
18. Existing Phase 7 Risk Fusion regression.
19. Existing Phase 8 Explainability regression.
20. Complete unified pipeline regression.
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from main import app
from app.classification import (
    ClassificationPolicy,
    DEFAULT_PROFILE,
    STRICT_PROFILE,
    ENTERPRISE_PROFILE,
    PROFILES,
    get_classification_profile,
    apply_feedback_tuning,
    is_feedback_tuning_allowed,
)
from app.engines.pipeline import UnifiedScanPipeline
from app.explainability.explainability_engine import ExplainabilityEngine
from app.fusion.risk_fusion import fuse_engine_results, _classification
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.risk_assessment import RiskAssessment, RiskClassification
from app.models.scan_input import ScanInput
from app.models.scan_response import UnifiedScanResponse


def make_engine_result(
    name: str,
    score: float,
    confidence: float = 1.0,
    *,
    flags: list[str] | None = None,
    status: EngineStatus = EngineStatus.SUCCESS,
    evidence: list[EvidenceItem] | None = None,
) -> EngineResult:
    return EngineResult(
        engine_name=name,
        risk_score=score,
        confidence=confidence,
        flags=flags or [],
        status=status,
        evidence=evidence or [],
    )


class TestV2Classification(unittest.TestCase):
    def setUp(self):
        self.default_policy = DEFAULT_PROFILE
        self.strict_policy = STRICT_PROFILE
        self.enterprise_policy = ENTERPRISE_PROFILE

    # 1. Default profile reproduces current classification exactly
    def test_default_profile_reproduces_current_classification(self):
        test_scores = [0.0, 10.0, 19.99, 20.0, 35.0, 44.99, 45.0, 60.0, 69.99, 70.0, 85.0, 89.99, 90.0, 95.0, 100.0]
        for score in test_scores:
            for malware_sig in [False, True]:
                with self.subTest(score=score, malware_signal=malware_sig):
                    expected = _classification(score, malware_sig)
                    policy_result = self.default_policy.classify(score, malware_signal=malware_sig)
                    self.assertEqual(policy_result, expected)

    # 2. Safe boundary
    def test_safe_boundary(self):
        # Default: Safe is < 20.0
        self.assertEqual(self.default_policy.classify(0.0), RiskClassification.SAFE)
        self.assertEqual(self.default_policy.classify(19.99), RiskClassification.SAFE)
        self.assertEqual(self.default_policy.classify(20.0), RiskClassification.SUSPICIOUS)

    # 3. Suspicious boundary
    def test_suspicious_boundary(self):
        # Default: Suspicious is 20.0 <= score < 45.0
        self.assertEqual(self.default_policy.classify(20.0), RiskClassification.SUSPICIOUS)
        self.assertEqual(self.default_policy.classify(44.99), RiskClassification.SUSPICIOUS)
        self.assertEqual(self.default_policy.classify(45.0), RiskClassification.DECEPTIVE)

    # 4. Deceptive boundary
    def test_deceptive_boundary(self):
        # Default: Deceptive is 45.0 <= score < 70.0
        self.assertEqual(self.default_policy.classify(45.0), RiskClassification.DECEPTIVE)
        self.assertEqual(self.default_policy.classify(69.99), RiskClassification.DECEPTIVE)
        self.assertEqual(self.default_policy.classify(70.0), RiskClassification.PHISHING)

    # 5. Phishing boundary
    def test_phishing_boundary(self):
        # Default: Phishing is 70.0 <= score < 90.0
        self.assertEqual(self.default_policy.classify(70.0), RiskClassification.PHISHING)
        self.assertEqual(self.default_policy.classify(89.99), RiskClassification.PHISHING)
        self.assertEqual(self.default_policy.classify(90.0, malware_signal=False), RiskClassification.PHISHING)

    # 6. 90+ non-malware score remains Phishing
    def test_90_plus_non_malware_remains_phishing(self):
        for score in [90.0, 95.5, 99.9, 100.0]:
            with self.subTest(score=score):
                self.assertEqual(
                    self.default_policy.classify(score, malware_signal=False),
                    RiskClassification.PHISHING,
                )

    # 7. Malware signal produces Malware under the existing malware rule
    def test_malware_signal_produces_malware_under_existing_rule(self):
        # Score >= 90.0 with malware signal -> Malware
        self.assertEqual(
            self.default_policy.classify(90.0, malware_signal=True),
            RiskClassification.MALWARE,
        )
        self.assertEqual(
            self.default_policy.classify(100.0, malware_signal=True),
            RiskClassification.MALWARE,
        )
        # Score < 90.0 even with malware signal -> Not Malware (Phishing or below)
        self.assertEqual(
            self.default_policy.classify(89.9, malware_signal=True),
            RiskClassification.PHISHING,
        )
        self.assertEqual(
            self.default_policy.classify(40.0, malware_signal=True),
            RiskClassification.SUSPICIOUS,
        )

    def test_executable_attachment_alone_cannot_produce_malware(self):
        # EXECUTABLE_ATTACHMENT flag alone at high score (>90) must yield Phishing, NOT Malware
        self.assertEqual(
            self.default_policy.classify(95.0, flags=["EXECUTABLE_ATTACHMENT"]),
            RiskClassification.PHISHING,
        )
        self.assertEqual(
            self.strict_policy.classify(95.0, flags=["EXECUTABLE_ATTACHMENT"]),
            RiskClassification.PHISHING,
        )
        self.assertEqual(
            self.enterprise_policy.classify(95.0, flags=["EXECUTABLE_ATTACHMENT"]),
            RiskClassification.PHISHING,
        )

    def test_attachment_type_mismatch_alone_cannot_produce_malware(self):
        # ATTACHMENT_TYPE_MISMATCH flag alone at high score (>90) must yield Phishing, NOT Malware
        self.assertEqual(
            self.default_policy.classify(95.0, flags=["ATTACHMENT_TYPE_MISMATCH"]),
            RiskClassification.PHISHING,
        )
        self.assertEqual(
            self.strict_policy.classify(95.0, flags=["ATTACHMENT_TYPE_MISMATCH"]),
            RiskClassification.PHISHING,
        )
        self.assertEqual(
            self.enterprise_policy.classify(95.0, flags=["ATTACHMENT_TYPE_MISMATCH"]),
            RiskClassification.PHISHING,
        )

    def test_genuine_phase7_malware_flags_produce_malware(self):
        # Score >= 90.0 with any authentic Phase 7 malware flag -> Malware
        for genuine_flag in ["MALWARE", "malware_detected", "vt_malicious", "vt_suspicious"]:
            with self.subTest(flag=genuine_flag):
                self.assertEqual(
                    self.default_policy.classify(90.0, flags=[genuine_flag]),
                    RiskClassification.MALWARE,
                )
                self.assertEqual(
                    self.default_policy.classify(100.0, flags=[genuine_flag]),
                    RiskClassification.MALWARE,
                )
                # Below threshold must still be Phishing even with genuine malware flag
                self.assertEqual(
                    self.default_policy.classify(85.0, flags=[genuine_flag]),
                    RiskClassification.PHISHING,
                )

    # 8. Strict profile
    def test_strict_profile(self):
        # Strict: safe < 15, suspicious < 35, deceptive < 55, phishing < 80
        self.assertEqual(self.strict_policy.safe_upper, 15.0)
        self.assertEqual(self.strict_policy.suspicious_upper, 35.0)
        self.assertEqual(self.strict_policy.deceptive_upper, 55.0)
        self.assertEqual(self.strict_policy.phishing_upper, 80.0)

        # Comparative tests against default:
        # Score 18.0 is Safe in default, but Suspicious in strict
        self.assertEqual(self.default_policy.classify(18.0), RiskClassification.SAFE)
        self.assertEqual(self.strict_policy.classify(18.0), RiskClassification.SUSPICIOUS)

        # Score 40.0 is Suspicious in default, but Deceptive in strict
        self.assertEqual(self.default_policy.classify(40.0), RiskClassification.SUSPICIOUS)
        self.assertEqual(self.strict_policy.classify(40.0), RiskClassification.DECEPTIVE)

        # Score 60.0 is Deceptive in default, but Phishing in strict
        self.assertEqual(self.default_policy.classify(60.0), RiskClassification.DECEPTIVE)
        self.assertEqual(self.strict_policy.classify(60.0), RiskClassification.PHISHING)

    # 9. Enterprise profile
    def test_enterprise_profile(self):
        # Enterprise: safe < 10, suspicious < 30, deceptive < 50, phishing < 75
        self.assertEqual(self.enterprise_policy.safe_upper, 10.0)
        self.assertEqual(self.enterprise_policy.suspicious_upper, 30.0)
        self.assertEqual(self.enterprise_policy.deceptive_upper, 50.0)
        self.assertEqual(self.enterprise_policy.phishing_upper, 75.0)

        # Score 12.0 is Safe in default, but Suspicious in enterprise
        self.assertEqual(self.default_policy.classify(12.0), RiskClassification.SAFE)
        self.assertEqual(self.enterprise_policy.classify(12.0), RiskClassification.SUSPICIOUS)

        # Score 32.0 is Suspicious in default, but Deceptive in enterprise
        self.assertEqual(self.default_policy.classify(32.0), RiskClassification.SUSPICIOUS)
        self.assertEqual(self.enterprise_policy.classify(32.0), RiskClassification.DECEPTIVE)

    # 10. Unknown profile handling
    def test_unknown_profile_handling(self):
        # Safe fallback to default
        fallback = get_classification_profile("non_existent_profile", fallback_to_default=True)
        self.assertEqual(fallback.name, "default")
        self.assertEqual(fallback.safe_upper, 20.0)

        # Strict validation without fallback
        with self.assertRaises(ValueError) as ctx:
            get_classification_profile("non_existent_profile", fallback_to_default=False)
        self.assertIn("Unknown classification profile", str(ctx.exception))

    # 11. Invalid threshold ordering
    def test_invalid_threshold_ordering(self):
        # safe_upper >= suspicious_upper
        with self.assertRaises(ValueError):
            ClassificationPolicy(safe_upper=50.0, suspicious_upper=40.0, deceptive_upper=70.0, phishing_upper=90.0)

        # suspicious_upper >= deceptive_upper
        with self.assertRaises(ValueError):
            ClassificationPolicy(safe_upper=20.0, suspicious_upper=75.0, deceptive_upper=70.0, phishing_upper=90.0)

        # deceptive_upper >= phishing_upper
        with self.assertRaises(ValueError):
            ClassificationPolicy(safe_upper=20.0, suspicious_upper=45.0, deceptive_upper=95.0, phishing_upper=90.0)

        # equal thresholds
        with self.assertRaises(ValueError):
            ClassificationPolicy(safe_upper=30.0, suspicious_upper=30.0, deceptive_upper=70.0, phishing_upper=90.0)

    # 12. Threshold values outside 0–100
    def test_threshold_values_outside_0_100(self):
        # Negative threshold
        with self.assertRaises(ValueError):
            ClassificationPolicy(safe_upper=-5.0, suspicious_upper=45.0, deceptive_upper=70.0, phishing_upper=90.0)

        # Threshold > 100
        with self.assertRaises(ValueError):
            ClassificationPolicy(safe_upper=20.0, suspicious_upper=45.0, deceptive_upper=70.0, phishing_upper=105.0)

    # 13. Deterministic classification
    def test_deterministic_classification(self):
        score = 62.5
        flags = ["first_time_sender", "suspicious_tld"]
        first = self.default_policy.classify(score, flags=flags)
        for _ in range(100):
            self.assertEqual(self.default_policy.classify(score, flags=flags), first)

    # 14. Risk score exactly at every boundary
    def test_risk_score_exactly_at_every_boundary(self):
        # default boundaries: 20.0, 45.0, 70.0, 90.0
        # Check boundary - epsilon vs boundary
        eps = 1e-6
        self.assertEqual(self.default_policy.classify(20.0 - eps), RiskClassification.SAFE)
        self.assertEqual(self.default_policy.classify(20.0), RiskClassification.SUSPICIOUS)

        self.assertEqual(self.default_policy.classify(45.0 - eps), RiskClassification.SUSPICIOUS)
        self.assertEqual(self.default_policy.classify(45.0), RiskClassification.DECEPTIVE)

        self.assertEqual(self.default_policy.classify(70.0 - eps), RiskClassification.DECEPTIVE)
        self.assertEqual(self.default_policy.classify(70.0), RiskClassification.PHISHING)

        self.assertEqual(self.default_policy.classify(90.0 - eps), RiskClassification.PHISHING)
        self.assertEqual(self.default_policy.classify(90.0, malware_signal=False), RiskClassification.PHISHING)
        self.assertEqual(self.default_policy.classify(90.0, malware_signal=True), RiskClassification.MALWARE)

    # 15. Explainability receives the correct classification
    def test_explainability_receives_the_correct_classification(self):
        assessment = RiskAssessment(
            risk_score=35.0,
            classification=RiskClassification.SUSPICIOUS,
            confidence=0.9,
            contributing_engines=["nlp_engine"],
            flags=[],
            evidence=[],
        )
        explained = ExplainabilityEngine.explain(assessment)
        self.assertIn("Exercise caution", explained.recommended_action)

        # Now classify under strict policy -> becomes Deceptive (35.0 in strict is Deceptive)
        strict_assessment = self.strict_policy.classify_assessment(assessment)
        self.assertEqual(strict_assessment.classification, RiskClassification.DECEPTIVE)
        explained_strict = ExplainabilityEngine.explain(strict_assessment)
        self.assertIn("Do not trust this content", explained_strict.recommended_action)

    # 16. API response compatibility
    def test_api_response_compatibility(self):
        client = TestClient(app)

        # Standard scan uses default profile
        res_default = client.post("/api/scan", json={"text": "Test message"})
        self.assertEqual(res_default.status_code, 200)
        data_default = res_default.json()
        self.assertIn("classification", data_default)
        self.assertIn("risk_score", data_default)
        self.assertIn("risk_assessment", data_default)

        # Scan with explicit classification_profile="strict"
        res_strict = client.post(
            "/api/scan",
            json={"text": "Test message", "classification_profile": "strict"},
        )
        self.assertEqual(res_strict.status_code, 200)
        data_strict = res_strict.json()
        self.assertIn("classification", data_strict)
        self.assertIn("risk_score", data_strict)

    # 17. Feedback data cannot automatically change classification
    def test_feedback_data_cannot_automatically_change_classification(self):
        # 1. Explicit function check
        self.assertFalse(is_feedback_tuning_allowed())

        # 2. Applying feedback tuning raises PermissionError
        with self.assertRaises(PermissionError):
            apply_feedback_tuning(self.default_policy, {"false_positive_count": 100})

        # 3. Policy thresholds remain completely unchanged
        self.assertEqual(self.default_policy.safe_upper, 20.0)
        self.assertEqual(self.default_policy.suspicious_upper, 45.0)
        self.assertEqual(self.default_policy.deceptive_upper, 70.0)
        self.assertEqual(self.default_policy.phishing_upper, 90.0)

    # 18. Existing Phase 7 Risk Fusion regression
    def test_existing_phase_7_risk_fusion_regression(self):
        results = [
            make_engine_result("url_engine", 80.0, confidence=1.0),
            make_engine_result("nlp_engine", 20.0, confidence=0.5),
        ]
        assessment = fuse_engine_results(results)
        self.assertEqual(assessment.risk_score, 61.54)
        self.assertEqual(assessment.classification, RiskClassification.DECEPTIVE)

        # Fusion with explicit policy passed
        assessment_strict = fuse_engine_results(results, policy="strict")
        self.assertEqual(assessment_strict.risk_score, 61.54)
        # 61.54 in strict is Phishing (>= 55.0 and < 80.0)
        self.assertEqual(assessment_strict.classification, RiskClassification.PHISHING)

    # 19. Existing Phase 8 Explainability regression
    def test_existing_phase_8_explainability_regression(self):
        for cls_type in [
            RiskClassification.SAFE,
            RiskClassification.SUSPICIOUS,
            RiskClassification.DECEPTIVE,
            RiskClassification.PHISHING,
            RiskClassification.MALWARE,
        ]:
            assessment = RiskAssessment(
                risk_score=50.0,
                classification=cls_type,
                confidence=1.0,
                contributing_engines=["url_engine"],
                flags=["suspicious_tld"],
                evidence=[],
            )
            explained = ExplainabilityEngine.explain(assessment)
            self.assertEqual(explained.classification, cls_type)
            self.assertIsNotNone(explained.recommended_action)
            self.assertTrue(len(explained.reasons) > 0)


class TestV2PipelineClassificationIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.pipeline = UnifiedScanPipeline()

    # 20. Complete unified pipeline regression
    @patch("app.engines.url_engine.check_google_safe_browsing", new_callable=AsyncMock)
    @patch("app.engines.malware_engine.check_virustotal", new_callable=AsyncMock)
    async def test_complete_unified_pipeline_regression(self, mock_vt, mock_gsb):
        mock_gsb.return_value = {"gsb_score": 0.0, "gsb_threats": []}
        mock_vt.return_value = {"score": 0.0, "flags": []}

        # Scan text with moderate risk indicators
        input_data = ScanInput(
            text="Please verify your password immediately to avoid suspension.",
            classification_profile="strict",
        )
        results = await self.pipeline.run(input_data)
        self.assertTrue(len(results) > 0)

        # Verify response generated with strict profile
        response = UnifiedScanResponse.from_results(results, profile="strict")
        self.assertEqual(response.status, "completed")
        self.assertIn(response.classification, [
            RiskClassification.SAFE,
            RiskClassification.SUSPICIOUS,
            RiskClassification.DECEPTIVE,
            RiskClassification.PHISHING,
            RiskClassification.MALWARE,
        ])
        self.assertEqual(response.classification, response.risk_assessment.classification)
        self.assertIsNotNone(response.risk_assessment.recommended_action)


if __name__ == "__main__":
    unittest.main(verbosity=2)
