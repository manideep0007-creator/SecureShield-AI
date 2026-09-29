import sys
import os
import unittest
from unittest.mock import patch, AsyncMock

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.models.scan_input import ScanInput
from app.engines.pipeline import UnifiedScanPipeline
from app.engines.url_engine import URLEngine
from app.engines.malware_engine import MalwareEngine
from app.engines.nlp_engine import NLPEngine
from app.engines.sender_engine import SenderEngine


class TestUnifiedPipeline(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.pipeline = UnifiedScanPipeline()

    async def test_empty_invalid_input(self):
        """Test that submitting an entirely empty ScanInput raises a ValueError."""
        with self.assertRaises(ValueError):
            await self.pipeline.run(ScanInput())

    async def test_text_scan(self):
        """Test that providing text triggers the NLP engine and skips others."""
        input_data = ScanInput(text="URGENT! Please verify your password immediately.")
        results = await self.pipeline.run(input_data)
        
        nlp_result = next(r for r in results if r.engine_name == "nlp_engine")
        url_result = next(r for r in results if r.engine_name == "url_engine")
        
        self.assertEqual(nlp_result.status, "success")
        self.assertGreater(nlp_result.risk_score, 0)
        self.assertIn("nlp_urgency", nlp_result.flags)
        
        # Verify evidence generation in pipeline output
        self.assertGreater(len(nlp_result.evidence), 0)
        urgency_evidence = next((e for e in nlp_result.evidence if e.key == "urgency"), None)
        self.assertIsNotNone(urgency_evidence)
        self.assertEqual(urgency_evidence.description, "urgency language was detected.")
        
        self.assertEqual(url_result.status, "skipped")

    @patch("app.engines.url_engine.check_google_safe_browsing", new_callable=AsyncMock)
    async def test_url_scan(self, mock_gsb):
        """Test URL preprocessing and corresponding engine triggering."""
        mock_gsb.return_value = {"gsb_score": 1.0, "gsb_threats": ["MALWARE"]}
        
        # We test both the pipeline preprocessing (which redirects/resolves) 
        # and the underlying engine triggering
        input_data = ScanInput(url="http://192.168.1.1@phishing.xyz")
        results = await self.pipeline.run(input_data)
        
        url_result = next(r for r in results if r.engine_name == "url_engine")
        malware_result = next(r for r in results if r.engine_name == "malware_engine")
        
        self.assertEqual(url_result.status, "success")
        self.assertGreater(url_result.risk_score, 0)
        self.assertIn("MALWARE", url_result.flags)
        self.assertIn("ip_based_host", url_result.flags)
        
        self.assertEqual(malware_result.status, "skipped")

    @patch("app.engines.malware_engine.check_virustotal", new_callable=AsyncMock)
    async def test_file_scan_with_mismatch(self, mock_vt):
        """Test generic file parsing, Magic Bytes preprocessing, and malware engine."""
        mock_vt.return_value = {"score": 0.5, "flags": ["vt_suspicious"]}
        
        # A file explicitly lying about its extension: says "txt", actually "pdf"
        dummy_pdf_bytes = b"%PDF-1.4\n%Fake PDF Content"
        
        input_data = ScanInput(file_name="safe_document.txt", file_bytes=dummy_pdf_bytes)
        results = await self.pipeline.run(input_data)
        
        malware_result = next(r for r in results if r.engine_name == "malware_engine")
        nlp_result = next(r for r in results if r.engine_name == "nlp_engine")
        
        # Verify execution and preprocessing flag augmentation
        self.assertEqual(malware_result.status, "success")
        self.assertIn("vt_suspicious", malware_result.flags)
        self.assertIn("extension_mismatch", malware_result.flags) # from preprocessing!
        self.assertGreater(malware_result.risk_score, 50.0) # Boosted by +30
        
        self.assertEqual(nlp_result.status, "skipped")

if __name__ == "__main__":
    unittest.main(verbosity=2)
