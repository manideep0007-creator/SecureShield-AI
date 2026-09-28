import sys
import os
import unittest
import asyncio

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.models.scan_input import ScanInput
from app.engines.url_engine import URLEngine
from app.engines.malware_engine import MalwareEngine
from app.engines.nlp_engine import NLPEngine
from app.engines.sender_engine import SenderEngine

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
        
    async def test_nlp_engine_skipped(self):
        engine = NLPEngine()
        res = await engine.analyze(ScanInput(url="https://example.com"))
        self.assertEqual(res.status, "skipped")

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
