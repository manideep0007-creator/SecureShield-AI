import unittest

from app.fusion.risk_fusion import fuse_engine_results
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.scan_response import UnifiedScanResponse


def result(
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


class TestRiskFusion(unittest.TestCase):
    def test_single_engine_result(self):
        assessment = fuse_engine_results([result("nlp_engine", 30.0)])

        self.assertEqual(assessment.risk_score, 30.0)
        self.assertEqual(assessment.classification, "Suspicious")
        self.assertEqual(assessment.contributing_engines, ["nlp_engine"])

    def test_multi_engine_confidence_weighted_fusion(self):
        assessment = fuse_engine_results([
            result("url_engine", 80.0, confidence=1.0),
            result("nlp_engine", 20.0, confidence=0.5),
        ])

        self.assertEqual(assessment.risk_score, 61.54)
        self.assertEqual(assessment.classification, "Deceptive")

    def test_conflicting_engines_are_weighted_deterministically(self):
        results = [
            result("nlp_engine", 0.0, confidence=0.1),
            result("url_engine", 100.0, confidence=1.0),
        ]

        first = fuse_engine_results(results)
        second = fuse_engine_results(list(reversed(results)))

        self.assertEqual(first, second)
        self.assertEqual(first.classification, "Phishing")

    def test_low_confidence_result_does_not_dominate(self):
        assessment = fuse_engine_results([
            result("nlp_engine", 20.0, confidence=1.0),
            result("unknown_engine", 100.0, confidence=0.05),
        ])

        self.assertLess(assessment.risk_score, 30.0)
        self.assertEqual(assessment.classification, "Suspicious")

    def test_low_confidence_malware_signal_does_not_override_score(self):
        assessment = fuse_engine_results([
            result("url_engine", 20.0, confidence=1.0),
            result("malware_engine", 100.0, confidence=0.1, flags=["vt_malicious"]),
        ])

        self.assertEqual(assessment.classification, "Suspicious")

    def test_skipped_and_error_results_are_ignored(self):
        assessment = fuse_engine_results([
            result("url_engine", 40.0),
            result("malware_engine", 100.0, status=EngineStatus.SKIPPED),
            result("visual_engine", 100.0, status=EngineStatus.ERROR),
        ])

        self.assertEqual(assessment.risk_score, 40.0)
        self.assertEqual(assessment.ignored_engines, ["malware_engine", "visual_engine"])

    def test_partial_results_contribute_at_reduced_weight(self):
        assessment = fuse_engine_results([
            result("url_engine", 20.0),
            result("malware_engine", 100.0, status=EngineStatus.PARTIAL),
        ])

        self.assertEqual(assessment.risk_score, 48.57)

    def test_classification_boundaries(self):
        cases = [
            (0.0, "Safe"),
            (19.99, "Safe"),
            (20.0, "Suspicious"),
            (44.99, "Suspicious"),
            (45.0, "Deceptive"),
            (69.99, "Deceptive"),
            (70.0, "Phishing"),
            (89.99, "Phishing"),
            (90.0, "Phishing"),
        ]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(fuse_engine_results([result("url_engine", score)]).classification, expected)

        self.assertEqual(
            fuse_engine_results([result("malware_engine", 90.0)]).classification,
            "Malware",
        )

    def test_empty_or_failed_inputs_are_safe(self):
        assessment = fuse_engine_results([
            result("url_engine", 100.0, status=EngineStatus.ERROR),
            result("nlp_engine", 100.0, status=EngineStatus.SKIPPED),
        ])

        self.assertEqual(assessment.risk_score, 0.0)
        self.assertEqual(assessment.classification, "Safe")
        self.assertEqual(assessment.confidence, 0.0)

    def test_response_preserves_engine_data_and_adds_assessment(self):
        evidence = EvidenceItem(key="keyword", value="urgent", description="Urgency")
        engine_result = result("nlp_engine", 70.0, flags=["nlp_urgency"], evidence=[evidence])

        response = UnifiedScanResponse.from_results([engine_result])

        self.assertEqual(response.results, [engine_result])
        self.assertEqual(response.risk_score, 70.0)
        self.assertEqual(response.classification, "Phishing")
        self.assertEqual(response.risk_assessment.flags, ["nlp_urgency"])
        self.assertEqual(response.risk_assessment.evidence, [evidence])