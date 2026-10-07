import sys
import os
import unittest
import asyncio
from unittest.mock import patch, AsyncMock
from datetime import datetime, timedelta, timezone

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.models.scan_input import ScanInput
from app.engines.url_engine import URLEngine
from app.engines.malware_engine import MalwareEngine
from app.engines.nlp_engine import NLPEngine
from app.engines.sender_engine import SenderEngine
from app.classification.policy import DEFAULT_PROFILE
from app.models.risk_assessment import RiskClassification

class TestEnginesScanInput(unittest.IsolatedAsyncioTestCase):

    async def test_url_engine_skipped(self):
        engine = URLEngine()
        # No URL provided -> skipped
        res = await engine.analyze(ScanInput(text="Just text"))
        self.assertEqual(res.status, "skipped")

    async def test_url_engine_analysis(self):
        engine = URLEngine()
        # The check_google_safe_browsing calls real network but we don't patch it here.
        # It's fine; it will return 0.0 or network error (PARTIAL), but risk_score won't crash.
        # Actually it's better to test deterministic heuristic
        res = await engine.analyze(ScanInput(url="http://192.168.1.1@malbad.xyz"))
        self.assertNotEqual(res.status, "skipped")
        self.assertGreater(res.risk_score, 0)
        self.assertIn("ip_based_host", res.flags)

    async def test_url_engine_phase2_features(self):
        engine = URLEngine()
        # Normal URL below thresholds
        res_normal = await engine.analyze(ScanInput(url="https://google.com/search"))
        self.assertNotIn("url_length_anomaly", res_normal.flags)
        self.assertNotIn("path_length_anomaly", res_normal.flags)
        self.assertNotIn("subdomain_depth_anomaly", res_normal.flags)
        self.assertNotIn("suspicious_keywords", res_normal.flags)
        
        # Suspicious URL hitting thresholds
        bad_url = "https://secure.login.update.banking.xyz/verify/account/details/verylongpaththatgoesforevertomakeitexceedseventyfivecharactersinlength"
        res_bad = await engine.analyze(ScanInput(url=bad_url))
        self.assertIn("url_length_anomaly", res_bad.flags)
        self.assertIn("path_length_anomaly", res_bad.flags)
        self.assertIn("subdomain_depth_anomaly", res_bad.flags)
        self.assertIn("suspicious_keywords", res_bad.flags)
        
        ev_keys = [e.key for e in res_bad.evidence]
        self.assertIn("URL_LENGTH", ev_keys)
        self.assertIn("PATH_LENGTH", ev_keys)
        self.assertIn("SUBDOMAIN_DEPTH", ev_keys)
        self.assertIn("SUSPICIOUS_KEYWORDS", ev_keys)

    async def test_url_engine_phase2_features_10_to_13(self):
        engine = URLEngine()
        # Normal URL below thresholds
        res_normal = await engine.analyze(ScanInput(url="https://google.com/search"))
        self.assertNotIn("double_slash_redirect", res_normal.flags)
        self.assertNotIn("http_without_https", res_normal.flags)
        self.assertNotIn("non_standard_port", res_normal.flags)
        self.assertNotIn("https_in_hostname", res_normal.flags)
        
        # Suspicious URL matching features 10-13 explicitly
        bad_url = "http://www.https-secure-login.xyz:8080/redirect//malicious"
        res_bad = await engine.analyze(ScanInput(url=bad_url))
        self.assertIn("double_slash_redirect", res_bad.flags)
        self.assertIn("http_without_https", res_bad.flags)
        self.assertIn("non_standard_port", res_bad.flags)
        self.assertIn("https_in_hostname", res_bad.flags)
        
        ev_keys = [e.key for e in res_bad.evidence]
        self.assertIn("DOUBLE_SLASH_REDIRECT", ev_keys)
        self.assertIn("HTTP_WITHOUT_HTTPS", ev_keys)
        self.assertIn("NON_STANDARD_PORT", ev_keys)
        self.assertIn("HTTPS_IN_HOSTNAME", ev_keys)

    async def test_url_engine_phase2_features_14_to_17(self):
        engine = URLEngine()
        # Normal URL below thresholds
        res_normal = await engine.analyze(ScanInput(url="https://google.com/search"))
        self.assertNotIn("high_shannon_entropy", res_normal.flags)
        self.assertNotIn("high_digit_ratio", res_normal.flags)
        self.assertNotIn("special_char_overload", res_normal.flags)
        self.assertNotIn("base64_obfuscation", res_normal.flags)
        
        # Suspicious URL matching features 14-17 explicitly
        # Entropy high (>4.0) hostname: '12345678qzwxecrvtbynumiopa.xyz'
        # Contains Base64 query >= 30 chars, >= 5 special chars
        bad_url_entropy = "https://12345678qzwxecrvtbynumiopa.xyz/?payload=VGhpcyBpcyBwdXJlIGJhc2U2NCB0ZXN0aW5nIHN0cmluZyBmb3IgZGV0ZWN0aW9u&x=_1&y=2%3"
        res_bad = await engine.analyze(ScanInput(url=bad_url_entropy))
        
        self.assertIn("high_shannon_entropy", res_bad.flags)
        self.assertIn("high_digit_ratio", res_bad.flags)
        self.assertIn("special_char_overload", res_bad.flags)
        self.assertIn("base64_obfuscation", res_bad.flags)
        
        ev_keys = [e.key for e in res_bad.evidence]
        self.assertIn("SHANNON_ENTROPY", ev_keys)
        self.assertIn("DIGIT_TO_LETTER_RATIO", ev_keys)
        self.assertIn("SPECIAL_CHAR_COUNT", ev_keys)
        self.assertIn("BASE64_OBFUSCATION", ev_keys)

    @patch("app.engines.url_engine.asyncwhois.aio_whois_domain", new_callable=AsyncMock)
    async def test_url_engine_domain_age_new(self, mock_whois):
        class MockWhoisResult:
            def __init__(self, created):
                self.parser_dict = {'created': created}
        
        # Newly registered (5 days old) & Multi-part TLD test (co.uk)
        recent_date = datetime.now(timezone.utc) - timedelta(days=5)
        mock_whois.return_value = MockWhoisResult(recent_date)
        
        engine = URLEngine()
        res = await engine.analyze(ScanInput(url="https://secure.login.bank.co.uk"))
        
        # tldextract properly extracts `bank.co.uk`, WHOIS returns 5 days.
        self.assertIn("newly_registered_domain", res.flags)
        
        ev = next((e for e in res.evidence if e.key == "DOMAIN_AGE_DAYS"), None)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.value, 5)

    @patch("app.engines.url_engine.asyncwhois.aio_whois_domain", new_callable=AsyncMock)
    async def test_url_engine_domain_age_old(self, mock_whois):
        class MockWhoisResult:
            def __init__(self, created):
                self.parser_dict = {'created': created}
        
        # Old domain (2000 days old)
        old_date = datetime.now(timezone.utc) - timedelta(days=2000)
        mock_whois.return_value = MockWhoisResult(old_date)
        
        engine = URLEngine()
        res = await engine.analyze(ScanInput(url="https://google.com"))
        
        self.assertNotIn("newly_registered_domain", res.flags)
        ev = next((e for e in res.evidence if e.key == "DOMAIN_AGE_DAYS"), None)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.value, 2000)

    @patch("app.engines.url_engine.asyncwhois.aio_whois_domain", new_callable=AsyncMock)
    async def test_url_engine_domain_age_missing_or_error(self, mock_whois):
        class MockWhoisResult:
            def __init__(self, created):
                self.parser_dict = {'created': created}
                
        # 1. Missing creation date
        mock_whois.return_value = MockWhoisResult(None)
        engine = URLEngine()
        res1 = await engine.analyze(ScanInput(url="https://example.com"))
        self.assertNotIn("newly_registered_domain", res1.flags)
        self.assertIsNone(next((e for e in res1.evidence if e.key == "DOMAIN_AGE_DAYS"), None))

        # 2. Timeout / Error
        mock_whois.side_effect = asyncio.TimeoutError
        res2 = await engine.analyze(ScanInput(url="https://example.org"))
        # Must not crash the engine
        self.assertNotIn("newly_registered_domain", res2.flags)
        self.assertIsNone(next((e for e in res2.evidence if e.key == "DOMAIN_AGE_DAYS"), None))

    @patch("app.engines.url_engine.check_google_safe_browsing", new_callable=AsyncMock)
    @patch("app.engines.url_engine.lexical_heuristics")
    @patch("app.engines.url_engine._get_domain_age_days", new_callable=AsyncMock)
    async def test_url_engine_gsb_confirmed_threat_floor(self, mock_age, mock_lex, mock_gsb):
        mock_age.return_value = 100
        engine = URLEngine()

        # 1. gsb_score=1.0 with lexical_score=0.2 and MALWARE threat
        mock_lex.return_value = {"lexical_score": 0.2, "lexical_flags": [], "evidence": []}
        mock_gsb.return_value = {"gsb_score": 1.0, "gsb_threats": ["MALWARE"]}
        res = await engine.analyze(ScanInput(url="https://example.com/malware"))
        
        # Risk score must be exactly 92.0 (0.90 floor + 0.2 * 0.10)
        self.assertAlmostEqual(res.risk_score, 92.0, places=2)
        self.assertGreaterEqual(res.risk_score, 90.0)
        # Classifies as Malware, not Deceptive
        classification = DEFAULT_PROFILE.classify(res.risk_score, flags=res.flags)
        self.assertEqual(classification, RiskClassification.MALWARE)
        self.assertNotEqual(classification, RiskClassification.DECEPTIVE)

        # 2. gsb_score=1.0 with lexical_score=0.2 and SOCIAL_ENGINEERING (Phishing) threat
        mock_gsb.return_value = {"gsb_score": 1.0, "gsb_threats": ["SOCIAL_ENGINEERING"]}
        res_phish = await engine.analyze(ScanInput(url="https://example.com/phish"))
        self.assertAlmostEqual(res_phish.risk_score, 92.0, places=2)
        classification_phish = DEFAULT_PROFILE.classify(res_phish.risk_score, flags=res_phish.flags)
        self.assertEqual(classification_phish, RiskClassification.PHISHING)
        self.assertNotEqual(classification_phish, RiskClassification.DECEPTIVE)

        # 3. gsb_score=1.0 with lexical_score=0.0 -> reaches the 90.0 floor
        mock_lex.return_value = {"lexical_score": 0.0, "lexical_flags": [], "evidence": []}
        res_floor = await engine.analyze(ScanInput(url="https://example.com/floor"))
        self.assertAlmostEqual(res_floor.risk_score, 90.0, places=2)

        # 4. gsb_score=1.0 with lexical_score=1.0 -> reaches 100.0
        mock_lex.return_value = {"lexical_score": 1.0, "lexical_flags": [], "evidence": []}
        res_max = await engine.analyze(ScanInput(url="https://example.com/max"))
        self.assertAlmostEqual(res_max.risk_score, 100.0, places=2)

    async def test_malware_engine_skipped(self):
        engine = MalwareEngine()
        # No file -> skipped
        res = await engine.analyze(ScanInput(url="http://example.com"))
        self.assertEqual(res.status, "skipped")

    async def test_nlp_engine_analysis(self):
        engine = NLPEngine()
        res = await engine.analyze(ScanInput(text="URGENT! update your password immediately!"))
        self.assertEqual(res.status, "success")
        self.assertGreater(res.risk_score, 0)
        self.assertIn("nlp_urgency", res.flags)
        self.assertIn("nlp_credential_request", res.flags)
        
        # Verify evidence generation
        self.assertGreater(len(res.evidence), 0)
        urgency_evidence = next((e for e in res.evidence if e.key == "urgency"), None)
        self.assertIsNotNone(urgency_evidence)
        self.assertIn("urgent", urgency_evidence.value)
        self.assertIn("immediately", urgency_evidence.value)
        self.assertEqual(urgency_evidence.description, "urgency language was detected.")
        
        cred_evidence = next((e for e in res.evidence if e.key == "credential_request"), None)
        self.assertIsNotNone(cred_evidence)
        self.assertIn("password", cred_evidence.value)
        self.assertEqual(cred_evidence.description, "credential-request language was detected.")
        
    async def test_nlp_engine_skipped(self):
        engine = NLPEngine()
        res = await engine.analyze(ScanInput(url="https://example.com"))
        self.assertEqual(res.status, "skipped")

    async def test_nlp_engine_remaining_categories(self):
        engine = NLPEngine()
        
        # 1. account_suspension
        res_susp = await engine.analyze(ScanInput(text="We will suspend your unauthorized access."))
        self.assertIn("nlp_account_suspension", res_susp.flags)
        susp_ev = next((e for e in res_susp.evidence if e.key == "account_suspension"), None)
        self.assertIsNotNone(susp_ev)
        self.assertIn("suspend", susp_ev.value)
        self.assertIn("unauthorized access", susp_ev.value)

        # 2. prize_lottery
        res_prize = await engine.analyze(ScanInput(text="You are selected to win a free gift giveaway!"))
        self.assertIn("nlp_prize_lottery", res_prize.flags)
        prize_ev = next((e for e in res_prize.evidence if e.key == "prize_lottery"), None)
        self.assertIsNotNone(prize_ev)
        self.assertIn("giveaway", prize_ev.value)
        
        # 3. unusual_payment
        res_pay = await engine.analyze(ScanInput(text="Send bitcoin or western union gift card now."))
        self.assertIn("nlp_unusual_payment", res_pay.flags)
        pay_ev = next((e for e in res_pay.evidence if e.key == "unusual_payment"), None)
        self.assertIsNotNone(pay_ev)
        self.assertIn("bitcoin", pay_ev.value)

    async def test_nlp_benign_text(self):
        engine = NLPEngine()
        res = await engine.analyze(ScanInput(text="Hey team, just wanted to check if we are still on for lunch tomorrow?"))
        self.assertEqual(res.status, "success")
        self.assertEqual(res.risk_score, 0.0)
        self.assertEqual(res.flags, [])
        self.assertEqual(res.evidence, [])

    async def test_nlp_score_capping(self):
        engine = NLPEngine()
        # Triggering 4 out of 5 categories: 
        # urgency: "act now"
        # credential_request: "password"
        # prize_lottery: "winner"
        # unusual_payment: "bitcoin"
        malicious_text = "act now! You are a winner! Send your password to claim bitcoin."
        res = await engine.analyze(ScanInput(text=malicious_text))
        
        # Expecting exactly 100.0 (since 0.35 * 4 = 1.4 -> capped to 1.0 * 100 = 100.0)
        self.assertEqual(res.risk_score, 100.0)
        
        self.assertIn("nlp_urgency", res.flags)
        self.assertIn("nlp_credential_request", res.flags)
        self.assertIn("nlp_prize_lottery", res.flags)
        self.assertIn("nlp_unusual_payment", res.flags)
        self.assertEqual(len(res.evidence), 4)

    async def test_nlp_engine_suspension_inflections_and_otp_disclaimer(self):
        engine = NLPEngine()

        # Case 1: Suspension inflection + credential request -> positive score
        res1 = await engine.analyze(ScanInput(text="Your account has been suspended. Verify your account now."))
        self.assertGreater(res1.risk_score, 0.0)
        self.assertIn("nlp_account_suspension", res1.flags)
        self.assertIn("nlp_credential_request", res1.flags)

        # Case 2: Past-tense suspension inflection alone -> positive score
        res2 = await engine.analyze(ScanInput(text="Your account was suspended"))
        self.assertGreater(res2.risk_score, 0.0)
        self.assertIn("nlp_account_suspension", res2.flags)

        # Case 3: Legitimate OTP delivery message with safety warning -> score 0.0, no flags
        res3 = await engine.analyze(ScanInput(text="Your SBI OTP is 483920. Do not share it with anyone."))
        self.assertEqual(res3.risk_score, 0.0)
        self.assertEqual(res3.flags, [])

        # Case 4: Urgent message requesting login -> positive score
        res4 = await engine.analyze(ScanInput(text="Meeting is urgent, login to the portal and send the report immediately"))
        self.assertGreater(res4.risk_score, 0.0)
        self.assertIn("nlp_urgency", res4.flags)
        self.assertIn("nlp_credential_request", res4.flags)

    async def test_sender_engine_analysis(self):
        engine = SenderEngine()
        import uuid
        test_sender = f"test_actor_{uuid.uuid4()}@example.com"
        # Provide sender_id and a link
        res = await engine.analyze(ScanInput(sender_id=test_sender, url="http://link.com"))
        self.assertEqual(res.status, "success")
        self.assertGreater(res.risk_score, 0)
        # It should trigger first_time_sender on first run
        self.assertTrue(len(res.flags) > 0)
        
    async def test_sender_engine_skipped(self):
        engine = SenderEngine()
        res = await engine.analyze(ScanInput(text="No sender attached"))
        self.assertEqual(res.status, "skipped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
