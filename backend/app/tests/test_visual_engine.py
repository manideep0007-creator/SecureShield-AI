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

if __name__ == '__main__':
    unittest.main()
