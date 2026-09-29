import unittest
import asyncio
import cv2
import numpy as np
from app.models.scan_input import ScanInput
from app.engines.visual_engine import VisualEngine

class TestVisualEngine(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.engine = VisualEngine()

    async def test_skip_no_image(self):
        res = await self.engine.analyze(ScanInput(text="hello"))
        self.assertEqual(res.status, "skipped")

    async def test_ocr_extraction(self):
        # Create a simple image with text
        img = np.zeros((100, 400, 3), dtype=np.uint8)
        cv2.putText(img, 'URGENT', (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
        _, buffer = cv2.imencode('.png', img)
        
        res = await self.engine.analyze(ScanInput(image_bytes=buffer.tobytes()))
        self.assertEqual(res.status, "success")
        self.assertIn("ocr_text_extracted", res.flags)
        
        ext_text = res.metadata.get("extracted_text", "")
        self.assertIn("URGENT", ext_text)

    async def test_invalid_image(self):
        res = await self.engine.analyze(ScanInput(image_bytes=b"notanimage"))
        self.assertEqual(res.status, "error")

    async def test_qr_decoding(self):
        # Generate a real QR Code using OpenCV
        encoder = cv2.QRCodeEncoder.create()
        qr_img = encoder.encode('https://malicious-scam.com/login')
        
        # Scale up and pad so the detector works robustly across CV2 versions
        qr_img = cv2.resize(qr_img, (0, 0), fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
        qr_img = cv2.copyMakeBorder(qr_img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=[255])
        
        qr_img_bgr = cv2.cvtColor(qr_img, cv2.COLOR_GRAY2BGR)
        _, buffer = cv2.imencode('.png', qr_img_bgr)
        
        res = await self.engine.analyze(ScanInput(image_bytes=buffer.tobytes()))
        self.assertEqual(res.status, "success")
        self.assertIn("qr_code_detected", res.flags)
        
        qr_ev = next((e for e in res.evidence if e.key == "qr_data"), None)
        self.assertIsNotNone(qr_ev)
        self.assertEqual(qr_ev.value, "https://malicious-scam.com/login")
        
        self.assertEqual(res.metadata.get("extracted_url"), "https://malicious-scam.com/login")

if __name__ == '__main__':
    unittest.main()
