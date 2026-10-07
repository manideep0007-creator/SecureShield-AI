import cv2
import easyocr
import numpy as np
import re
from app.engines.base_engine import BaseEngine
from app.engines.registry import engine_registry
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.scan_input import ScanInput

_reader = None

def get_ocr_reader():
    global _reader
    if _reader is None:
        _reader = easyocr.Reader(['en'], gpu=False)
    return _reader

def extract_urls(text: str) -> list[str]:
    url_pattern = re.compile(
        r'(?:http[s]?://|www\.)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)

class VisualEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "visual_engine"

    async def analyze(self, input_data: ScanInput) -> EngineResult:
        if not input_data.image_bytes:
            return EngineResult.skipped(self.name, "No image provided")

        try:
            nparr = np.frombuffer(input_data.image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            if img is None:
                return EngineResult.error(self.name, "Failed to decode image bytes")

            extracted_text = ""
            extracted_url = ""
            flags = []
            evidence = []
            score = 0.0

            qr_decoder = cv2.QRCodeDetector()
            data, bbox, _ = qr_decoder.detectAndDecode(img)
            
            if data:
                flags.append("qr_code_detected")
                evidence.append(EvidenceItem(
                    key="qr_data",
                    value=data,
                    description="Successfully decoded QR code payload."
                ))
                score += 20.0
                
                urls = extract_urls(data)
                if urls:
                    extracted_url = urls[0]
                else:
                    extracted_text += data + "\n"

            ocr_reader = get_ocr_reader()
            ocr_results = ocr_reader.readtext(img)
            ocr_texts = [res[1] for res in ocr_results if res[2] > 0.3]
            
            if ocr_texts:
                flags.append("ocr_text_extracted")
                joined_text = " ".join(ocr_texts)
                evidence.append(EvidenceItem(
                    key="ocr_data",
                    value=joined_text,
                    description=f"Extracted {len(ocr_texts)} lines of text via OCR."
                ))
                extracted_text += joined_text + " "
                
                if not extracted_url:
                    urls = extract_urls(joined_text)
                    if urls:
                        extracted_url = urls[0]

                # Phase 5: Visual Phishing / Fake Login Detection
                # 1. OCR pattern analysis
                text_lower = joined_text.lower()
                cred_keywords = ["login", "sign in", "password", "username", "verify account", "enter credentials"]
                has_cred_text = any(kw in text_lower for kw in cred_keywords)

                # 2. Structural pattern analysis (detect input boxes)
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                blur = cv2.GaussianBlur(gray, (5, 5), 0)
                edges = cv2.Canny(blur, 50, 150)
                contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                
                input_field_count = 0
                for cnt in contours:
                    approx = cv2.approxPolyDP(cnt, 0.02 * cv2.arcLength(cnt, True), True)
                    if len(approx) == 4:
                        x, y, w, h = cv2.boundingRect(approx)
                        aspect_ratio = float(w)/h
                        if 2.0 <= aspect_ratio <= 20.0 and w > 40 and h > 10:
                            input_field_count += 1

                # 3. Assess Visual Phishing Risk
                if has_cred_text and input_field_count > 0:
                    flags.append("visual_phishing_detected")
                    score = min(score + 60.0, 100.0)
                    evidence.append(EvidenceItem(
                        key="visual_fake_login",
                        value={"input_fields_detected": input_field_count},
                        description="Image structurally resembles a credential-harvesting or fake login form."
                    ))
                elif has_cred_text:
                    flags.append("visual_credential_prompt")
                    score = min(score + 30.0, 100.0)
                    evidence.append(EvidenceItem(
                        key="visual_credential_prompt",
                        value=True,
                        description="Credential request language visually embedded in image payload."
                    ))

            if not flags:
                return self._build_result(
                    risk_score=0.0,
                    confidence=0.9,
                    flags=[],
                    evidence=[],
                    status=EngineStatus.SUCCESS,
                    metadata={"note": "No text or QR found in image"}
                )

            metadata = {
                "extracted_text": extracted_text.strip() if extracted_text else None,
                "extracted_url": extracted_url if extracted_url else None
            }

            return self._build_result(
                risk_score=score,
                confidence=0.85,
                flags=flags,
                evidence=evidence,
                status=EngineStatus.SUCCESS,
                metadata=metadata
            )

        except Exception as e:
            return EngineResult.error(self.name, f"Vision processing error: {str(e)}")

engine_registry.register(VisualEngine())
