import sys
import os
import unittest

# Add backend directory to path so we can import the models naturally
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.models.scan_input import ScanInput


class TestScanInput(unittest.TestCase):
    def test_empty_initialization(self):
        """Test that all fields default to expected empty representations."""
        data = ScanInput()
        self.assertIsNone(data.text)
        self.assertIsNone(data.url)
        self.assertIsNone(data.sender_id)
        self.assertIsNone(data.source_channel)
        self.assertIsNone(data.file_name)
        self.assertIsNone(data.file_bytes)
        self.assertIsNone(data.image_bytes)
        self.assertEqual(data.metadata, {})
        self.assertIsNone(data.client_id)

    def test_partial_initialization(self):
        """Test that partial assignment correctly reflects in the model."""
        data = ScanInput(text="Suspicious text here", url="http://malicious.example.com", client_id="device-uuid-1234")
        self.assertEqual(data.text, "Suspicious text here")
        self.assertEqual(data.url, "http://malicious.example.com")
        self.assertEqual(data.client_id, "device-uuid-1234")
        self.assertIsNone(data.sender_id)
        self.assertEqual(data.metadata, {})

    def test_full_initialization(self):
        """Test exhaustive property assignment across all channels."""
        data = ScanInput(
            text="Please see the attached invoice",
            url="https://phishing.example.com/invoice",
            sender_id="bad_actor@scam.com",
            source_channel="gmail",
            file_name="fake_invoice.pdf",
            file_bytes=b"dummy file bytes",
            image_bytes=b"dummy image representation",
            metadata={"origin_ip": "192.168.1.1", "urgency": "high"},
            client_id="custom-client-uuid-999"
        )
        self.assertEqual(data.text, "Please see the attached invoice")
        self.assertEqual(data.source_channel, "gmail")
        self.assertEqual(data.file_bytes, b"dummy file bytes")
        self.assertEqual(data.metadata["origin_ip"], "192.168.1.1")
        self.assertEqual(data.client_id, "custom-client-uuid-999")


if __name__ == "__main__":
    unittest.main(verbosity=2)

