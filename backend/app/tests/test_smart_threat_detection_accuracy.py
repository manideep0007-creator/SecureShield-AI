import pytest
from app.engines.url_engine import URLEngine, lexical_heuristics
from app.models.scan_input import ScanInput
from app.models.risk_assessment import RiskClassification
from app.fusion.risk_fusion import fuse_engine_results


@pytest.mark.asyncio
class TestSmartThreatDetectionAccuracy:
    """
    Comprehensive accuracy and false-alarm prevention benchmark suite.
    Verifies that safe browsing activity generates ZERO threat alarms while
    actively deceptive, homograph, and malware threats are reliably detected.
    """

    async def test_safe_popular_services_produce_zero_threat_alarms(self):
        engine = URLEngine()
        safe_urls = [
            "https://www.google.com/search?q=cybersecurity+defense",
            "https://accounts.google.com/signin/v2/identifier",
            "https://support.microsoft.com/en-us/account-billing/help",
            "https://login.live.com/login.srf",
            "https://en.wikipedia.org/wiki/Computer_security",
            "https://github.com/torvalds/linux",
            "https://www.amazon.com/gp/help/customer/display.html",
            "https://appleid.apple.com/sign-in",
        ]

        for url in safe_urls:
            result = await engine.analyze(ScanInput(url=url))
            assessment = fuse_engine_results([result])
            
            # Safe sites must have zero or minimal risk and be classified as SAFE
            assert assessment.risk_score < 20.0, f"False positive score {assessment.risk_score} on {url}"
            assert assessment.classification == RiskClassification.SAFE, f"False positive classification {assessment.classification} on {url}"
            assert "brand_impersonation_spoofing" not in result.flags
            assert "homograph_punycode_attack" not in result.flags

    async def test_brand_impersonation_spoofing_detected(self):
        engine = URLEngine()
        phishing_urls = [
            "http://paypal.com.account-update.xyz/login",
            "http://accounts.google.com.profile-verification.top/signin",
            "https://netflix-billing-renew.xyz/update",
            "http://chase-bank-security-alert.cc/verify",
        ]

        for url in phishing_urls:
            result = await engine.analyze(ScanInput(url=url))
            assessment = fuse_engine_results([result])
            
            assert assessment.risk_score >= 80.0, f"Phishing failed to reach high threshold: {assessment.risk_score} for {url}"
            assert assessment.classification in (RiskClassification.PHISHING, RiskClassification.DECEPTIVE), (
                f"Expected Phishing or Deceptive but got {assessment.classification} for {url}"
            )
            assert "brand_impersonation_spoofing" in result.flags or "suspicious_tld" in result.flags

    async def test_homograph_punycode_attack_detected(self):
        engine = URLEngine()
        # Cyrillic 'а' (U+0430) instead of Latin 'a' in 'paypal.com'
        cyrillic_url = "https://pаypal.com/signin"
        punycode_url = "http://xn--gogle-pra.com/login"

        for url in [cyrillic_url, punycode_url]:
            result = await engine.analyze(ScanInput(url=url))
            assessment = fuse_engine_results([result])

            assert "homograph_punycode_attack" in result.flags
            assert assessment.risk_score >= 80.0
            assert assessment.classification == RiskClassification.PHISHING

    async def test_known_threat_intelligence_feed_match(self):
        from app.intelligence.threat_feeds import threat_store
        # Pre-seed a test malicious URL in threat intelligence feed
        test_bad_url = "http://malware-c2-drop.bad/infect.exe"
        threat_store.add_malicious_url(test_bad_url, source="URLhaus", threat_type="malware_download", tags="exe,c2")

        engine = URLEngine()
        result = await engine.analyze(ScanInput(url=test_bad_url))
        assessment = fuse_engine_results([result])

        assert result.risk_score == 100.0
        assert "known_malicious_url" in result.flags
        assert assessment.risk_score == 100.0
        assert assessment.classification in (RiskClassification.MALWARE, RiskClassification.PHISHING)

    async def test_detection_benchmark_accuracy_metrics(self):
        """
        Calculates precision, recall, F1-score, and false positive rate
        across a balanced labeled evaluation dataset.
        """
        engine = URLEngine()

        labeled_dataset = [
            # Ground truth: Safe (0)
            ("https://www.google.com", 0),
            ("https://accounts.google.com/signin", 0),
            ("https://support.microsoft.com", 0),
            ("https://en.wikipedia.org/wiki/Main_Page", 0),
            ("https://github.com", 0),
            ("https://www.apple.com", 0),
            ("https://www.amazon.com", 0),
            ("https://stackoverflow.com/questions", 0),
            # Ground truth: Malicious/Phishing (1)
            ("http://paypal.com.account-update.xyz/login", 1),
            ("http://accounts.google.com.profile-verification.top/signin", 1),
            ("https://pаypal.com/signin", 1),
            ("http://xn--gogle-pra.com/login", 1),
            ("http://chase-bank-security-alert.cc/verify", 1),
            ("https://netflix-billing-renew.xyz/update", 1),
        ]

        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for url, ground_truth in labeled_dataset:
            result = await engine.analyze(ScanInput(url=url))
            assessment = fuse_engine_results([result])
            
            # Predict malicious if score >= 60.0 (High Risk / Deceptive / Phishing)
            predicted_positive = 1 if assessment.risk_score >= 60.0 else 0

            if ground_truth == 1 and predicted_positive == 1:
                tp += 1
            elif ground_truth == 0 and predicted_positive == 1:
                fp += 1
            elif ground_truth == 0 and predicted_positive == 0:
                tn += 1
            elif ground_truth == 1 and predicted_positive == 0:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        print(f"\n--- ACCURACY BENCHMARK EVALUATION ---")
        print(f"TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
        print(f"Precision: {precision:.4f} ({precision * 100:.1f}%)")
        print(f"Recall: {recall:.4f} ({recall * 100:.1f}%)")
        print(f"F1 Score: {f1_score:.4f}")
        print(f"False Positive Rate (FPR): {fpr:.4f} ({fpr * 100:.2f}%)")

        assert fp == 0, f"Detected {fp} false positives on benign safe URLs!"
        assert precision >= 0.95, f"Precision {precision:.4f} below 0.95 target"
        assert recall >= 0.95, f"Recall {recall:.4f} below 0.95 target"
        assert f1_score >= 0.95, f"F1-score {f1_score:.4f} below 0.95 target"
        assert fpr == 0.0, f"False Positive Rate {fpr:.4f} is not 0.0%"

