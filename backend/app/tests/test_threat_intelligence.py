import asyncio
import hashlib
import os
import sys
import unittest
from unittest.mock import patch, AsyncMock

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi.testclient import TestClient
from main import app
from app.models.scan_input import ScanInput
from app.engines.url_engine import URLEngine
from app.engines.malware_engine import MalwareEngine
from app.intelligence.threat_feeds import ThreatFeedStore, threat_store


class TestThreatIntelligence(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Ensure threat store is initialized
        threat_store.init_db()

    def test_preseeded_malware_hashes(self):
        """Test that real-world baseline malware hashes are detected immediately."""
        # 1. EICAR Standard Antivirus Test String
        eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        match = threat_store.lookup_hash(eicar_sha256)
        self.assertIsNotNone(match)
        self.assertEqual(match["signature"], "EICAR-Standard-AV-Test")

        # 2. WannaCry Ransomware SHA-256
        wannacry_sha256 = "ed01845f04478418121a9e8048b518f7004f5dd309e5445427370ac1b0f83f1b"
        match_wc = threat_store.lookup_hash(wannacry_sha256)
        self.assertIsNotNone(match_wc)
        self.assertEqual(match_wc["signature"], "WannaCry.Ransomware")
        self.assertEqual(match_wc["file_type"], "exe")

        # 3. Emotet Banking Trojan SHA-256
        emotet_sha256 = "4f76239bc7a61d76fb5a0f6bf3b6ff8fb6f28448e894c770c8041c2c01824987"
        match_em = threat_store.lookup_hash(emotet_sha256)
        self.assertIsNotNone(match_em)
        self.assertEqual(match_em["signature"], "Emotet.BankingTrojan")

    def test_whitelisted_domains(self):
        """Test legitimate top domain recognition to eliminate false alarms."""
        self.assertTrue(threat_store.is_whitelisted_domain("google.com"))
        self.assertTrue(threat_store.is_whitelisted_domain("accounts.google.com"))
        self.assertTrue(threat_store.is_whitelisted_domain("https://github.com/torvalds/linux"))
        self.assertTrue(threat_store.is_whitelisted_domain("microsoft.com"))
        self.assertTrue(threat_store.is_whitelisted_domain("apple.com"))

        # Random suspicious domains should NOT be whitelisted
        self.assertFalse(threat_store.is_whitelisted_domain("secure-login-verify-account.xyz"))
        self.assertFalse(threat_store.is_whitelisted_domain("phishing-bank-update.top"))

    async def test_url_engine_threat_feed_match(self):
        """Test that URLEngine flags confirmed threat feed URLs with 100.0 score."""
        engine = URLEngine()
        mal_url = "http://malicious-distribution-node.ru/payload.exe"
        threat_store.add_malicious_url(mal_url, threat_type="malware_download", source="URLhaus", tags="trojan,elf")

        res = await engine.analyze(ScanInput(url=mal_url))
        self.assertEqual(res.status, "success")
        self.assertEqual(res.risk_score, 100.0)
        self.assertIn("known_malicious_url", res.flags)
        self.assertIn("urlhaus_malicious", res.flags)

        ev_match = next((e for e in res.evidence if e.key == "THREAT_FEED_MATCH"), None)
        self.assertIsNotNone(ev_match)
        self.assertEqual(ev_match.value["source"], "URLhaus")

    async def test_url_engine_whitelist_attenuation(self):
        """Test that whitelisted destinations are recognized and prevent false alarms."""
        engine = URLEngine()
        res = await engine.analyze(ScanInput(url="https://accounts.google.com/signin/v2/identifier"))
        self.assertIn(res.status, ("success", "partial"))
        self.assertIn("whitelisted_trusted_domain", res.flags)
        self.assertLess(res.risk_score, 20.0)

    async def test_malware_engine_threat_feed_match(self):
        """Test that MalwareEngine detects real malware hashes and identifies family signatures."""
        engine = MalwareEngine()
        # EICAR standard test payload
        eicar_payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
        res = await engine.analyze(ScanInput(file_bytes=eicar_payload, file_name="eicar.com"))
        self.assertEqual(res.status, "success")
        self.assertEqual(res.risk_score, 100.0)
        self.assertEqual(res.confidence, 1.0)
        self.assertIn("MALWARE", res.flags)
        self.assertIn("malware_detected", res.flags)
        self.assertIn("malwarebazaar_verified", res.flags)
        self.assertIn("threat_family:EICAR-Standard-AV-Test", res.flags)

        ev_sig = next((e for e in res.evidence if e.key == "MALWARE_SIGNATURE"), None)
        self.assertIsNotNone(ev_sig)
        self.assertEqual(ev_sig.value["signature"], "EICAR-Standard-AV-Test")

    def test_api_threat_intelligence_status(self):
        """Test the REST API endpoint exposing live threat feed counts and status."""
        client = TestClient(app)
        res = client.get("/api/threat-intelligence/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("malware_hashes_count", data)
        self.assertIn("threat_urls_count", data)
        self.assertIn("whitelisted_domains_count", data)
        self.assertGreater(data["malware_hashes_count"], 0)
        self.assertGreater(data["whitelisted_domains_count"], 0)


if __name__ == "__main__":
    unittest.main()
