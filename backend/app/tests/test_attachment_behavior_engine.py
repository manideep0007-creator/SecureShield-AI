import asyncio
import io
import os
import sys
import unittest
import zipfile
from unittest.mock import patch

# Ensure backend directory is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.engines.attachment_behavior_engine import (
    AttachmentBehaviorEngine,
    sanitize_filename,
    detect_double_extension,
    detect_suspicious_filename,
    detect_magic_type,
    detect_type_mismatch,
    detect_macro_presence,
    detect_embedded_scripts,
    inspect_archive,
    FLAG_WEIGHTS,
    MAX_ATTACHMENT_RISK_SCORE,
)
from app.engines.pipeline import UnifiedScanPipeline
from app.engines.registry import engine_registry
from app.models.engine_result import EngineStatus
from app.models.scan_input import ScanInput


# -------------------------------------------------------------------------
# Synthetic In-Memory Fixture Helpers (Safe & Non-executable)
# -------------------------------------------------------------------------

def create_safe_pdf_bytes() -> bytes:
    return b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF"


def create_pdf_with_script_bytes() -> bytes:
    return b"%PDF-1.5\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('hello');) >>\nendobj\n%%EOF"


def create_mock_pe_bytes() -> bytes:
    # Safe static DOS/PE header signature without executable machine code
    return b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"


def create_safe_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", "This is a benign text file inside an archive.")
    return buf.getvalue()


def create_nested_zip_bytes() -> bytes:
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as inner_z:
        inner_z.writestr("inner_doc.txt", "Inner text document.")

    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w", zipfile.ZIP_DEFLATED) as outer_z:
        outer_z.writestr("inner.zip", inner_buf.getvalue())
    return outer_buf.getvalue()


def create_deep_nested_archive_bytes() -> bytes:
    # Level 3 archive inside Level 2 inside Level 1
    lvl3 = io.BytesIO()
    with zipfile.ZipFile(lvl3, "w") as z3:
        z3.writestr("deep.txt", "deep payload")

    lvl2 = io.BytesIO()
    with zipfile.ZipFile(lvl2, "w") as z2:
        z2.writestr("level3.zip", lvl3.getvalue())

    lvl1 = io.BytesIO()
    with zipfile.ZipFile(lvl1, "w") as z1:
        z1.writestr("level2.zip", lvl2.getvalue())

    return lvl1.getvalue()


def create_path_traversal_archive_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
    return buf.getvalue()


def create_dropper_archive_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("invoice.exe", b"MZ\x90\x00test")
    return buf.getvalue()


def create_expansion_anomaly_archive_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Repeated zeros compress to ~2KB while uncompressed is 2MB (> 1,000,000 bytes with > 50:1 ratio)
        z.writestr("huge_text_payload.txt", b"0" * 2_000_000)
    return buf.getvalue()



def create_ooxml_macro_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        z.writestr("word/document.xml", "<w:document></w:document>")
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1VBA_PROJECT")
    return buf.getvalue()


# -------------------------------------------------------------------------
# Test Cases
# -------------------------------------------------------------------------

class TestAttachmentBehaviorEngine(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.engine = AttachmentBehaviorEngine()

    # 1. No attachment -> SKIPPED
    async def test_no_attachment_skipped(self):
        input_data = ScanInput(text="Just message text without attachment", url="https://example.com")
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SKIPPED)
        self.assertEqual(result.risk_score, 0.0)
        self.assertEqual(len(result.flags), 0)

    # 2. Normal safe document -> low/zero risk
    async def test_normal_safe_document(self):
        safe_bytes = create_safe_pdf_bytes()
        input_data = ScanInput(file_name="quarterly_report.pdf", file_bytes=safe_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertEqual(result.risk_score, 0.0)
        self.assertEqual(len(result.flags), 0)
        self.assertGreaterEqual(result.confidence, 0.9)

    # 3. Extension / type mismatch
    async def test_extension_type_mismatch(self):
        # Says jpg image, but contains PDF magic bytes
        fake_jpg_bytes = create_safe_pdf_bytes()
        input_data = ScanInput(file_name="vacation_photo.jpg", file_bytes=fake_jpg_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("ATTACHMENT_TYPE_MISMATCH", result.flags)
        self.assertGreater(result.risk_score, 0.0)

    # 4. Double extension
    async def test_double_extension_detection(self):
        pe_bytes = create_mock_pe_bytes()
        input_data = ScanInput(file_name="important_invoice.pdf.exe", file_bytes=pe_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("DOUBLE_EXTENSION", result.flags)
        self.assertIn("EXECUTABLE_ATTACHMENT", result.flags)
        self.assertGreaterEqual(result.risk_score, 50.0)

    # 5. Executable attachment
    async def test_executable_attachment(self):
        pe_bytes = create_mock_pe_bytes()
        input_data = ScanInput(file_name="setup.exe", file_bytes=pe_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("EXECUTABLE_ATTACHMENT", result.flags)
        self.assertGreaterEqual(result.risk_score, 50.0)

    # 6. Script attachment
    async def test_script_attachment(self):
        script_bytes = b"param([string]$target)\nWrite-Output 'Executing test task'\n"
        input_data = ScanInput(file_name="deploy.ps1", file_bytes=script_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("SCRIPT_ATTACHMENT", result.flags)
        self.assertIn("SUSPICIOUS_EXTENSION", result.flags)
        self.assertGreaterEqual(result.risk_score, 45.0)

    # 7. Office document with detectable macro indicator
    async def test_office_document_macro_presence(self):
        macro_bytes = create_ooxml_macro_bytes()
        input_data = ScanInput(file_name="financial_model.docm", file_bytes=macro_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("MACRO_PRESENT", result.flags)
        self.assertGreaterEqual(result.risk_score, 40.0)

    # 8. Embedded-script indicator
    async def test_embedded_script_indicator(self):
        pdf_js_bytes = create_pdf_with_script_bytes()
        input_data = ScanInput(file_name="interactive_form.pdf", file_bytes=pdf_js_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("EMBEDDED_SCRIPT", result.flags)
        self.assertGreaterEqual(result.risk_score, 35.0)

    # 9. ZIP / archive inspection (clean archive)
    async def test_clean_zip_archive_inspection(self):
        zip_bytes = create_safe_zip_bytes()
        input_data = ScanInput(file_name="project_documents.zip", file_bytes=zip_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertEqual(result.risk_score, 0.0)
        self.assertEqual(len(result.flags), 0)

    # 10. Nested archive
    async def test_nested_archive_detection(self):
        nested_bytes = create_nested_zip_bytes()
        input_data = ScanInput(file_name="archive_bundle.zip", file_bytes=nested_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("NESTED_ARCHIVE", result.flags)
        self.assertGreaterEqual(result.risk_score, 20.0)

    # 11. Excessive archive depth
    async def test_archive_depth_anomaly(self):
        deep_bytes = create_deep_nested_archive_bytes()
        input_data = ScanInput(file_name="deep_container.zip", file_bytes=deep_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("ARCHIVE_DEPTH_ANOMALY", result.flags)
        self.assertGreaterEqual(result.risk_score, 35.0)

    # 12. Suspicious archive structure (dropper and path traversal)
    async def test_suspicious_archive_structure(self):
        dropper_bytes = create_dropper_archive_bytes()
        input_data = ScanInput(file_name="urgent_notice.zip", file_bytes=dropper_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("SUSPICIOUS_ARCHIVE", result.flags)
        self.assertIn("EXECUTABLE_ATTACHMENT", result.flags)

        # Path traversal check
        traversal_bytes = create_path_traversal_archive_bytes()
        input_data2 = ScanInput(file_name="traversal_test.zip", file_bytes=traversal_bytes)
        result2 = await self.engine.analyze(input_data2)
        self.assertIn("SUSPICIOUS_ARCHIVE", result2.flags)

    # 13. Large / compression-expansion safety boundary
    async def test_archive_expansion_anomaly(self):
        expansion_bytes = create_expansion_anomaly_archive_bytes()
        input_data = ScanInput(file_name="suspicious_expansion.zip", file_bytes=expansion_bytes)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.SUCCESS)
        self.assertIn("ARCHIVE_EXPANSION_ANOMALY", result.flags)
        self.assertGreaterEqual(result.risk_score, 40.0)

    # 14. Sanitized evidence generation (privacy preservation)
    async def test_sanitized_evidence_generation(self):
        sensitive_path = "C:\\Users\\VictimUser\\Documents\\Financials\\invoice_2026.pdf.exe"
        pe_bytes = create_mock_pe_bytes()
        input_data = ScanInput(file_name=sensitive_path, file_bytes=pe_bytes)
        result = await self.engine.analyze(input_data)

        # Check metadata
        sanitized = result.metadata.get("sanitized_filename")
        self.assertEqual(sanitized, "invoice_2026.pdf.exe")
        self.assertNotIn("VictimUser", sanitized)
        self.assertNotIn("C:", sanitized)

        # Ensure no raw bytes leak into evidence values
        for ev in result.evidence:
            self.assertIsInstance(ev.key, str)
            self.assertIsInstance(ev.description, str)
            self.assertNotIsInstance(ev.value, bytes)
            self.assertNotIn("VictimUser", str(ev.value))

    # 15. Deterministic scoring
    async def test_deterministic_scoring(self):
        pe_bytes = create_mock_pe_bytes()
        input_data = ScanInput(file_name="invoice_march.pdf.exe", file_bytes=pe_bytes)

        scores = []
        flags_set = []
        for _ in range(5):
            res = await self.engine.analyze(input_data)
            scores.append(res.risk_score)
            flags_set.append(tuple(res.flags))

        # All runs must produce identical score and flags
        self.assertTrue(all(s == scores[0] for s in scores))
        self.assertTrue(all(f == flags_set[0] for f in flags_set))
        # Ensure capped score
        self.assertLessEqual(scores[0], MAX_ATTACHMENT_RISK_SCORE)

    # 16. Deterministic evidence ordering
    async def test_deterministic_evidence_ordering(self):
        pe_bytes = create_mock_pe_bytes()
        input_data = ScanInput(file_name="payment_statement.pdf.exe", file_bytes=pe_bytes)
        res = await self.engine.analyze(input_data)

        keys = [item.key for item in res.evidence]
        self.assertEqual(keys, sorted(keys))

    # 17. Engine failure isolation
    async def test_engine_failure_isolation(self):
        input_data = ScanInput(file_name="crash_test.pdf", file_bytes=b"dummy")
        with patch.object(AttachmentBehaviorEngine, "analyze", side_effect=RuntimeError("Simulated static analysis crash")):
            result = await self.engine.safe_analyze(input_data)
            self.assertEqual(result.status, EngineStatus.ERROR)
            self.assertIn("Simulated static analysis crash", result.error_message)

    # 18. Registry integration
    def test_registry_integration(self):
        engine = engine_registry.get("attachment_behavior_engine")
        self.assertIsNotNone(engine)
        self.assertIsInstance(engine, AttachmentBehaviorEngine)
        self.assertIn("attachment_behavior_engine", engine_registry.engine_names)

    # 19. Existing pipeline regression tests
    async def test_pipeline_integration_with_attachment(self):
        pipeline = UnifiedScanPipeline()
        safe_pdf = create_safe_pdf_bytes()
        input_data = ScanInput(
            file_name="quarterly_report.pdf",
            file_bytes=safe_pdf,
            text="Please review the attached quarterly report."
        )
        results = await pipeline.run(input_data)

        # Both NLP and Attachment engines should complete
        attachment_res = next((r for r in results if r.engine_name == "attachment_behavior_engine"), None)
        nlp_res = next((r for r in results if r.engine_name == "nlp_engine"), None)

        self.assertIsNotNone(attachment_res)
        self.assertEqual(attachment_res.status, EngineStatus.SUCCESS)
        self.assertIsNotNone(nlp_res)

    async def test_partial_status_on_malformed_archive(self):
        # Corrupted ZIP header that cannot be parsed
        corrupted_zip = b"PK\x03\x04\x00\x00\x00\x00corrupted_bytes_here"
        input_data = ScanInput(file_name="broken.zip", file_bytes=corrupted_zip)
        result = await self.engine.analyze(input_data)
        self.assertEqual(result.status, EngineStatus.PARTIAL)
        self.assertIn("SUSPICIOUS_ARCHIVE", result.flags)


if __name__ == "__main__":
    unittest.main()
