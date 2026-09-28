import sys
import os
import unittest
import base64
from unittest.mock import patch, AsyncMock

# Add backend directory to path so we can import the FastAPI app naturally
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

class TestAPIUnifiedScan(unittest.TestCase):
    def test_invalid_empty_input(self):
        """Test sending an empty JSON payload yields a 400 Validation Error from the pipeline bounds."""
        res = client.post("/api/scan", json={})
        self.assertEqual(res.status_code, 400)
        self.assertIn("at least one piece of scannable data", res.json()["detail"])

    @patch("app.engines.url_engine.check_google_safe_browsing", new_callable=AsyncMock)
    def test_valid_url_scan(self, mock_gsb):
        """Test API parsing of a URL, successful URL engine execution, and other engine skips."""
        mock_gsb.return_value = {"gsb_score": 1.0, "gsb_threats": ["MALWARE"]}
        
        res = client.post("/api/scan", json={"url": "http://192.168.1.1@suspicious.xyz"})
        self.assertEqual(res.status_code, 200)
        response_data = res.json()
        results = response_data["results"]
        
        url_engine = next((r for r in results if r["engine_name"] == "url_engine"), None)
        self.assertIsNotNone(url_engine)
        self.assertEqual(url_engine["status"], "success")
        self.assertIn("MALWARE", url_engine["flags"])
        self.assertGreater(url_engine["risk_score"], 0)
        
        nlp_engine = next((r for r in results if r["engine_name"] == "nlp_engine"), None)
        self.assertIsNotNone(nlp_engine)
        self.assertEqual(nlp_engine["status"], "skipped")

    def test_valid_text_scan(self):
        """Test API parsing text accurately trips NLP engine while skipping File/URL mechanics."""
        res = client.post("/api/scan", json={"text": "URGENT act now to retrieve your password"})
        self.assertEqual(res.status_code, 200)
        response_data = res.json()
        results = response_data["results"]
        
        nlp_engine = next((r for r in results if r["engine_name"] == "nlp_engine"), None)
        self.assertIsNotNone(nlp_engine)
        self.assertEqual(nlp_engine["status"], "success")
        self.assertIn("nlp_urgency", nlp_engine["flags"])
        self.assertIn("nlp_credential_request", nlp_engine["flags"])
        
        malware_engine = next((r for r in results if r["engine_name"] == "malware_engine"), None)
        self.assertIsNotNone(malware_engine)
        self.assertEqual(malware_engine["status"], "skipped")

    @patch("app.engines.malware_engine.check_virustotal", new_callable=AsyncMock)
    def test_file_scan_with_mismatch(self, mock_vt):
        """Test base64 ingestion and accurate decoding mapping straight into the Malware engine."""
        mock_vt.return_value = {"score": 0.9, "flags": ["vt_malicious"]}
        
        # A file explicitly lying about its extension: says "txt", actually "pdf"
        dummy_pdf_bytes = b"%PDF-1.4\n%Fake PDF Content"
        encoded_bytes = base64.b64encode(dummy_pdf_bytes).decode("utf-8")
        
        payload = {
            "file_bytes": encoded_bytes,
            "file_name": "image_spoof.jpeg",
            "source_channel": "manual_upload"
        }
        
        res = client.post("/api/scan", json=payload)
        self.assertEqual(res.status_code, 200)
        response_data = res.json()
        results = response_data["results"]
        
        malware_engine = next((r for r in results if r["engine_name"] == "malware_engine"), None)
        self.assertIsNotNone(malware_engine)
        self.assertEqual(malware_engine["status"], "success")
        self.assertIn("vt_malicious", malware_engine["flags"])

    def test_response_structure_completeness(self):
        """Test that the API always returns the standardized wrapper object correctly."""
        res = client.post("/api/scan", json={"text": "Looking strictly at the wrapper object structure here."})
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("scan_id", data)
        self.assertIsInstance(data["scan_id"], str)
        self.assertEqual(data["status"], "completed")
        self.assertIn("results", data)
        self.assertIsInstance(data["results"], list)
        
        self.assertIn("total_engines", data)
        self.assertIn("completed_engines", data)
        self.assertIn("skipped_engines", data)
        
        self.assertEqual(data["total_engines"], data["completed_engines"] + data["skipped_engines"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
