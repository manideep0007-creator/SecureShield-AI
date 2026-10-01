    async def test_image_scan_propagation(self):
        # Create an image that effectively says "urgent password"
        import cv2
        import numpy as np
        img = np.zeros((100, 500, 3), dtype=np.uint8)
        cv2.putText(img, 'URGENT password', (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
        _, buffer = cv2.imencode('.png', img)

        input_data = ScanInput(image_bytes=buffer.tobytes())
        results = await self.pipeline.run(input_data)

        vis_result = next((r for r in results if r.engine_name == "visual_engine"), None)
        nlp_result = next((r for r in results if r.engine_name == "nlp_engine"), None)

        self.assertIsNotNone(vis_result)
        self.assertEqual(vis_result.status, "success")

        # Confirm NLP successfully digested the Vision extractions
        self.assertIsNotNone(nlp_result)
        self.assertEqual(nlp_result.status, "success")
        self.assertIn("nlp_urgency", nlp_result.flags)
        
