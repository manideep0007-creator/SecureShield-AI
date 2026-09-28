import json
import sys
import os
from unittest.mock import patch, AsyncMock

# Set dummy environment variables to allow pydantic-settings to validate successfully during testing
os.environ["GOOGLE_SAFE_BROWSING_API_KEY"] = "testsuite_dummy_gsb_key"
os.environ["VIRUSTOTAL_API_KEY"] = "testsuite_dummy_vt_key"

# Add parent directory to path so we can import the FastAPI app naturally
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

TEST_CASES = [
    {
        "name": "Known Safe Message",
        "endpoint": "/api/analyze/message",
        "payload": {"message_text": "Hi there, are we still meeting for lunch at 12?"},
        "expected_category_in": ["Safe"]
    },
    {
        "name": "Known Safe URL",
        "endpoint": "/api/analyze/message",
        "payload": {"url": "https://www.google.com"},
        "expected_category_in": ["Safe"]
    },
    {
        "name": "Obvious Phishing Scam",
        "endpoint": "/api/analyze/message",
        "payload": {
            "message_text": "URGENT! Your account is locked! Please verify your password and send a gift card immediately."
        },
        "expected_category_in": ["Phishing"]
    },
    {
        "name": "Suspicious / IP-Based URL",
        "endpoint": "/api/analyze/message",
        "payload": {"url": "http://192.168.1.1@secure-login-verify.xyz/login"},
        "expected_category_in": ["Suspicious", "Deceptive", "Phishing", "Malware"]
    }
]

def run_tests():
    print("========================================")
    print(" SecureShield AI - Pipeline Test Suite")
    print("========================================\n")
    
    passed = 0
    total = len(TEST_CASES) + 1 
    
    with patch("app.engines.url_engine.check_google_safe_browsing", new_callable=AsyncMock) as mock_gsb, \
         patch("app.engines.malware_engine.check_virustotal", new_callable=AsyncMock) as mock_vt:
        
        def gsb_side_effect(url):
            if "secure-login-verify" in url:
                return {"gsb_score": 1.0, "gsb_threats": ["MALWARE"]}
            return {"gsb_score": 0.0, "gsb_threats": []}
        mock_gsb.side_effect = gsb_side_effect
        
        mock_vt.return_value = {"score": 0.3, "flags": ["vt_not_found"]}
        
        for case in TEST_CASES:
            print(f"[*] Testing: {case['name']}")
            res = client.post(case["endpoint"], json=case["payload"])
            
            if res.status_code != 200:
                print(f"  [X] FAILED: HTTP {res.status_code}")
                continue
                
            data = res.json()
            actual = data.get("category", "UNKNOWN")
            
            if actual in case["expected_category_in"]:
                print(f"  [+] PASSED (Classified as {actual})")
                passed += 1
            else:
                print(f"  [X] FAILED! Expected {case['expected_category_in']}, got {actual}")
                print(f"      Score:   {data.get('final_score')}")
                print(f"      Reasons: {data.get('reasons')}")
            print()
            
        print("[*] Testing: Malware / Misleading Extension Upload")
        file_path = "test_spoofed_invoice.exe"
        with open(file_path, "wb") as f:
            f.write(b"%PDF-1.4\n%Fake PDF Content to trigger mismatch rule")
            
        try:
            with open(file_path, "rb") as f:
                file_res = client.post("/api/analyze/file", files={"file": (file_path, f)})
                
            if file_res.status_code == 200:
                data = file_res.json()
                cat = data.get("category", "UNKNOWN")
                if cat in ["Suspicious", "Deceptive", "Phishing", "Malware"]:
                    print(f"  [+] PASSED (Classified as {cat})")
                    passed += 1
                else:
                    print(f"  [X] FAILED! Expected elevated risk, got {cat}")
                    print(f"      Reasons: {data.get('reasons')}")
            else:
                print(f"  [X] FAILED: Upload HTTP {file_res.status_code}")
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        print("\n----------------------------------------")
        print(f"Summary: {passed} / {total} tests passed.")

if __name__ == "__main__":
    run_tests()