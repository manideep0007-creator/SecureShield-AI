"""
V2 Attachment Behavior Engine — Static Attachment Behavior Intelligence.

Performs safe static analysis of attachments to detect behavioral threats:
- File-type magic bytes analysis
- Extension / type mismatch detection
- Suspicious executable / script characteristics
- Office document macro presence detection
- Embedded script indicators (PDF / Office / RTF / HTML)
- Archive inspection (ZIP / TAR):
    - Contained dangerous file types
    - Nested archives
    - Excessive archive nesting depth
    - Suspicious archive structure (path traversal, encrypted entries, dropper structure)
    - Archive expansion / compression anomalies (zip bombs)
- Double extensions and Right-to-Left Override (RTLO)
- Suspicious attachment names / lure patterns

SAFETY & PRIVACY:
- SAFE STATIC ANALYSIS ONLY.
- NEVER executes attachments, macros, or scripts.
- NEVER launches executables or invokes shell commands.
- NEVER opens network connections or downloads external payloads.
- NEVER modifies original attachments.
- NEVER persists raw attachment bytes, contents, passwords, or credentials.
- Evidence contains only safe, sanitized metadata.
"""

from __future__ import annotations

import io
import os
import re
import tarfile
import zipfile
from typing import Any

from app.engines.base_engine import BaseEngine
from app.engines.registry import engine_registry
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.scan_input import ScanInput


# -------------------------------------------------------------------------
# Constants & Configuration
# -------------------------------------------------------------------------

SAFE_DOC_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif",
    "txt", "csv", "rtf", "mp3", "mp4", "wav"
})

DANGEROUS_EXTENSIONS = frozenset({
    "exe", "dll", "scr", "bat", "cmd", "msi", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "psm1", "psd1", "pif", "com", "hta", "cpl", "jar",
    "apk", "dmg", "iso", "img", "bin", "reg", "inf", "diagcab", "iqy", "slk",
    "sh", "bash", "py", "pyw", "rb", "pl"
})

EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "dll", "scr", "bat", "cmd", "msi", "com", "pif", "cpl",
    "hta", "apk", "dmg", "iso", "img", "bin"
})

SCRIPT_EXTENSIONS = frozenset({
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "psd1",
    "sh", "bash", "py", "pyw", "rb", "pl"
})

SUSPICIOUS_EVASION_EXTENSIONS = frozenset({
    "scr", "pif", "hta", "cpl", "wsf", "vbs", "vbe", "jse", "cmd", "ps1",
    "iso", "img", "iqy", "slk", "diagcab", "reg", "inf", "lnk"
})

ARCHIVE_EXTENSIONS = frozenset({
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "tgz", "tbz2", "iso", "img", "cab"
})

LURE_KEYWORDS = (
    "payment", "remittance", "invoice", "receipt", "statement", "swift",
    "wire", "ach", "fedex", "dhl", "usps", "payroll", "overdue", "salary"
)

# Scoring weights per detected condition
FLAG_WEIGHTS: dict[str, float] = {
    "EXECUTABLE_ATTACHMENT": 50.0,
    "SCRIPT_ATTACHMENT": 45.0,
    "DOUBLE_EXTENSION": 40.0,
    "MACRO_PRESENT": 40.0,
    "ARCHIVE_EXPANSION_ANOMALY": 40.0,
    "EMBEDDED_SCRIPT": 35.0,
    "ATTACHMENT_TYPE_MISMATCH": 35.0,
    "ARCHIVE_DEPTH_ANOMALY": 35.0,
    "SUSPICIOUS_ARCHIVE": 30.0,
    "SUSPICIOUS_EXTENSION": 25.0,
    "NESTED_ARCHIVE": 20.0,
    "SUSPICIOUS_FILENAME": 15.0,
}

# Maximum score cap so Attachment Behavior alone does not automatically cross 90.0 Malware
MAX_ATTACHMENT_RISK_SCORE = 85.0

# Resource safety limits
MAX_ARCHIVE_ENTRIES = 200
MAX_UNCOMPRESSED_ARCHIVE_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_EXPANSION_RATIO = 50.0  # 50:1 ratio


# -------------------------------------------------------------------------
# Static Analysis Helpers
# -------------------------------------------------------------------------

def sanitize_filename(name: str | None) -> str:
    """Safely extract and sanitize base filename, stripping path traversal and control characters."""
    if not name:
        return ""
    # Normalize slashes and take basename
    clean = name.replace("\\", "/").split("/")[-1].strip()
    # Strip null bytes and non-printable control characters
    clean = "".join(c for c in clean if c.isprintable() or c == " ")
    return clean.strip()


def detect_double_extension(filename: str) -> bool:
    """Detect deceptive double extensions (e.g. invoice.pdf.exe) and RTLO manipulation."""
    if not filename:
        return False
    # Right-to-Left Override character
    if "\u202e" in filename:
        return True
    
    # Strip multiple consecutive spaces/dots to reveal real extension structure
    parts = [p.strip() for p in filename.split(".") if p.strip()]
    if len(parts) >= 3:
        penultimate = parts[-2].lower()
        ultimate = parts[-1].lower()
        if penultimate in SAFE_DOC_EXTENSIONS and ultimate in DANGEROUS_EXTENSIONS:
            return True
        if penultimate in SAFE_DOC_EXTENSIONS and ultimate in ARCHIVE_EXTENSIONS:
            return True
    return False


def detect_suspicious_filename(filename: str) -> bool:
    """Detect suspicious filename patterns, lure words combined with dangerous extensions, and evasion padding."""
    if not filename:
        return False
    lower = filename.lower()
    # RTLO character or null byte
    if "\u202e" in filename or "\x00" in filename:
        return True
    # Excessive whitespace or underscores designed to hide extension in email clients
    if ("   " in filename or "___" in filename) and any(lower.endswith("." + ext) for ext in DANGEROUS_EXTENSIONS | ARCHIVE_EXTENSIONS):
        return True
    # Phishing lure keyword combined with dangerous executable/script extension
    has_lure = any(kw in lower for kw in LURE_KEYWORDS)
    if has_lure:
        ext = lower.split(".")[-1]
        if ext in DANGEROUS_EXTENSIONS:
            return True
    return False



def detect_magic_type(file_bytes: bytes) -> str:
    """Inspect safe magic-byte signatures for file type identification."""
    if not file_bytes:
        return "empty"

    # 1. Executables
    if file_bytes.startswith(b"MZ"):
        return "executable/pe"
    if file_bytes.startswith(b"\x7fELF"):
        return "executable/elf"
    if file_bytes[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "executable/macho"
    if file_bytes.startswith(b"\xca\xfe\xba\xbe"):
        return "executable/java_class"

    # 2. PDF
    if file_bytes.startswith(b"%PDF-") or b"%PDF-" in file_bytes[:1024]:
        return "document/pdf"

    # 3. OLE2 Compound Document (Legacy Office: doc, xls, ppt, msi)
    if file_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "document/ole2"

    # 4. RTF
    if file_bytes.startswith(b"{\\rtf"):
        return "document/rtf"

    # 5. ZIP and OOXML
    if file_bytes.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        header_sample = file_bytes[:2048]
        if b"[Content_Types].xml" in header_sample or b"word/" in header_sample or b"xl/" in header_sample or b"ppt/" in header_sample:
            return "document/ooxml"
        return "archive/zip"

    # 6. Other Archives
    if file_bytes.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "archive/rar"
    if file_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "archive/7z"
    if file_bytes.startswith(b"\x1f\x8b"):
        return "archive/gzip"
    if file_bytes.startswith(b"BZh"):
        return "archive/bzip2"
    if len(file_bytes) >= 512 and file_bytes[257:262] == b"ustar":
        return "archive/tar"

    # 7. HTML
    start_chunk = file_bytes[:512].lower().strip()
    if start_chunk.startswith((b"<!doctype html", b"<html", b"<?xml")):
        return "document/html"

    # 8. Script shebang
    if file_bytes.startswith(b"#!"):
        return "script/shebang"

    # 9. filetype library fallback
    try:
        import filetype
        kind = filetype.guess(file_bytes)
        if kind:
            return kind.mime
    except Exception:
        pass

    return "unknown"


def detect_type_mismatch(declared_ext: str, detected_type: str) -> bool:
    """Compare declared extension against detected magic type, respecting valid aliases."""
    if not declared_ext or detected_type in ("unknown", "empty"):
        return False
    declared = declared_ext.lower().strip(".")

    # Valid format matches
    if declared in ("jpg", "jpeg") and (detected_type == "image/jpeg" or "jpeg" in detected_type):
        return False
    if declared == "png" and (detected_type == "image/png" or "png" in detected_type):
        return False
    if declared == "gif" and (detected_type == "image/gif" or "gif" in detected_type):
        return False
    if declared == "pdf" and detected_type == "document/pdf":
        return False
    if declared in ("doc", "xls", "ppt") and detected_type == "document/ole2":
        return False
    if declared in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm") and detected_type in ("document/ooxml", "archive/zip"):
        return False
    if declared == "rtf" and detected_type == "document/rtf":
        return False
    if declared in ("zip", "jar", "apk") and detected_type in ("archive/zip", "document/ooxml"):
        return False
    if declared in ("html", "htm") and detected_type == "document/html":
        return False
    if declared == "txt" and not detected_type.startswith("executable/") and not detected_type.startswith("archive/"):
        return False

    # Genuine Mismatches
    # 1. Declared benign document/image, but detected is executable
    if declared in SAFE_DOC_EXTENSIONS and detected_type.startswith("executable/"):
        return True
    # 2. Declared benign document/image, but detected is generic archive
    if declared in ("pdf", "jpg", "jpeg", "png", "txt", "csv") and detected_type == "archive/zip":
        return True
    # 3. Declared pdf but detected is not pdf
    if declared == "pdf" and detected_type != "document/pdf":
        return True
    # 4. Declared image but detected is not image
    if declared in ("jpg", "jpeg", "png", "gif", "bmp") and not detected_type.startswith("image/"):
        return True
    # 5. Declared OOXML office doc but detected is executable
    if declared in ("docx", "xlsx", "pptx") and detected_type.startswith("executable/"):
        return True

    return False


def detect_macro_presence(file_bytes: bytes, declared_ext: str, detected_type: str) -> tuple[bool, str]:
    """Safely detect embedded VBA macros in modern OOXML and legacy OLE2 Office documents."""
    ext = declared_ext.lower().strip(".")
    # Explicit macro extensions
    if ext in ("docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam"):
        return True, f"macro_enabled_extension (.{ext})"

    # Modern OOXML check (inspect ZIP directory table without executing)
    if detected_type in ("document/ooxml", "archive/zip") or file_bytes.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                for name in z.namelist()[:MAX_ARCHIVE_ENTRIES]:
                    low = name.lower()
                    if "vbaproject.bin" in low or "vbadata.xml" in low or "vba/" in low:
                        return True, f"ooxml_vba_part ({sanitize_filename(name)})"
        except Exception:
            pass

    # Legacy OLE2 check (inspect byte signatures for VBA project streams)
    if detected_type == "document/ole2" or file_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        vba_markers = (b"_VBA_PROJECT", b"VBA\x00", b"dir\x00", b"AutoOpen", b"Auto_Open", b"Document_Open", b"Workbook_Open")
        for marker in vba_markers:
            if marker in file_bytes:
                return True, f"ole2_vba_marker ({marker.decode('latin1', errors='ignore')})"

    return False, ""


def detect_embedded_scripts(file_bytes: bytes, detected_type: str) -> tuple[bool, str]:
    """Safely detect embedded scripts and launch actions in PDF, OOXML, RTF, and HTML."""
    if not file_bytes:
        return False, ""

    # PDF embedded JavaScript / Launch actions
    if detected_type == "document/pdf" or file_bytes.startswith(b"%PDF-") or b"%PDF-" in file_bytes[:1024]:
        if re.search(rb'/(?:JavaScript|JS)\b', file_bytes):
            return True, "pdf_javascript"
        if re.search(rb'/Launch\b', file_bytes):
            return True, "pdf_launch_action"
        if re.search(rb'/EmbeddedFiles\b', file_bytes):
            return True, "pdf_embedded_files"

    # OOXML embedded OLE scripts or executables
    if detected_type == "document/ooxml" or file_bytes.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                for name in z.namelist()[:MAX_ARCHIVE_ENTRIES]:
                    low = name.lower()
                    if "embeddings/oleobject" in low or low.endswith((".js", ".vbs", ".ps1", ".bat", ".cmd", ".exe")):
                        return True, f"ooxml_embedded_object ({sanitize_filename(name)})"
        except Exception:
            pass

    # RTF embedded OLE objects
    if detected_type == "document/rtf" or file_bytes.startswith(b"{\\rtf"):
        if re.search(rb'\\(?:objdata|objocx|object)\b', file_bytes):
            return True, "rtf_embedded_object"

    # HTML script tags
    if detected_type == "document/html":
        if re.search(rb'<script[\s>]|javascript:|onerror=|onload=', file_bytes[:16384], re.IGNORECASE):
            return True, "html_script_tags"

    return False, ""


def inspect_archive(file_bytes: bytes, declared_ext: str, detected_type: str) -> dict[str, Any]:
    """Safely inspect archive structures (ZIP / TAR) applying strict resource bounds."""
    results: dict[str, Any] = {
        "is_archive": False,
        "is_partial": False,
        "flags": [],
        "evidence": [],
    }

    if not file_bytes:
        return results

    is_zip = detected_type == "archive/zip" or file_bytes.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    # Don't treat Office documents (OOXML) as generic archives
    office_exts = ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam")
    if detected_type == "document/ooxml" or declared_ext.lower().strip(".") in office_exts:
        return results


    if is_zip:
        results["is_archive"] = True
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                infolist = z.infolist()
                if not infolist:
                    return results

                total_uncompressed = 0
                total_compressed = 0
                non_dir_entries: list[tuple[str, zipfile.ZipInfo]] = []
                nested_archives: list[tuple[str, zipfile.ZipInfo]] = []

                entries_to_check = infolist[:MAX_ARCHIVE_ENTRIES]

                for info in entries_to_check:
                    total_uncompressed += info.file_size
                    total_compressed += info.compress_size

                    filename = info.filename
                    clean_name = sanitize_filename(filename)

                    if not info.is_dir() and clean_name:
                        non_dir_entries.append((clean_name, info))

                    # 1. Path traversal check
                    norm_parts = filename.replace("\\", "/").split("/")
                    if ".." in norm_parts:
                        results["flags"].append("SUSPICIOUS_ARCHIVE")
                        results["evidence"].append(EvidenceItem(
                            key="archive_path_traversal",
                            value=clean_name,
                            description="Archive contains suspicious directory traversal entries."
                        ))

                    # 2. Encrypted / password-protected entries
                    if bool(info.flag_bits & 0x1):
                        results["flags"].append("SUSPICIOUS_ARCHIVE")
                        results["evidence"].append(EvidenceItem(
                            key="archive_encrypted_entry",
                            value=clean_name,
                            description="Archive contains password-protected or encrypted entries."
                        ))

                    # 3. Path depth anomaly
                    if len(norm_parts) > 5:
                        results["flags"].append("ARCHIVE_DEPTH_ANOMALY")
                        results["evidence"].append(EvidenceItem(
                            key="archive_depth_anomaly",
                            value=f"depth={len(norm_parts)}",
                            description=f"Archive directory structure exceeds safe nesting depth limit ({len(norm_parts)})."
                        ))

                    if clean_name:
                        # 4. Double extension inside archive
                        if detect_double_extension(clean_name):
                            results["flags"].append("DOUBLE_EXTENSION")
                            results["flags"].append("SUSPICIOUS_ARCHIVE")
                            results["evidence"].append(EvidenceItem(
                                key="archive_contained_double_extension",
                                value=clean_name,
                                description=f"Archive contains deceptive double extension: '{clean_name}'."
                            ))

                        # 5. Executable or script payload inside archive
                        ext = clean_name.lower().split(".")[-1]
                        if ext in DANGEROUS_EXTENSIONS and ext not in ARCHIVE_EXTENSIONS:
                            if ext in EXECUTABLE_EXTENSIONS:
                                results["flags"].append("EXECUTABLE_ATTACHMENT")
                            else:
                                results["flags"].append("SCRIPT_ATTACHMENT")
                            results["flags"].append("SUSPICIOUS_ARCHIVE")
                            results["evidence"].append(EvidenceItem(
                                key="archive_contained_payload",
                                value=f"{clean_name} (.{ext})",
                                description=f"Archive contains executable or script payload: '{clean_name}'."
                            ))

                        # 6. Nested archive
                        if ext in ARCHIVE_EXTENSIONS:
                            nested_archives.append((clean_name, info))
                            results["flags"].append("NESTED_ARCHIVE")
                            results["evidence"].append(EvidenceItem(
                                key="nested_archive",
                                value=clean_name,
                                description=f"Archive contains nested archive file: '{clean_name}'."
                            ))

                # Compression expansion ratio check
                ratio = (total_uncompressed / max(total_compressed, 1)) if total_uncompressed > 0 else 1.0
                if (total_uncompressed > MAX_UNCOMPRESSED_ARCHIVE_SIZE) or (total_uncompressed > 1_000_000 and ratio > MAX_EXPANSION_RATIO):
                    results["flags"].append("ARCHIVE_EXPANSION_ANOMALY")
                    results["evidence"].append(EvidenceItem(
                        key="archive_expansion_anomaly",
                        value=f"ratio={ratio:.1f}:1, uncompressed={total_uncompressed}B",
                        description=f"Archive exhibits suspicious compression expansion ratio ({ratio:.1f}:1)."
                    ))

                # Single executable dropper check
                if len(non_dir_entries) == 1:
                    single_name, _ = non_dir_entries[0]
                    single_ext = single_name.lower().split(".")[-1]
                    if single_ext in DANGEROUS_EXTENSIONS:
                        results["flags"].append("SUSPICIOUS_ARCHIVE")
                        results["evidence"].append(EvidenceItem(
                            key="archive_single_payload_dropper",
                            value=single_name,
                            description="Archive contains a solitary executable/script payload (classic dropper format)."
                        ))

                # Safely inspect nested zip archives (depth >= 2) within strict bounds
                for nest_name, nest_info in nested_archives[:3]:
                    if nest_info.compress_size < 1_000_000 and nest_name.lower().endswith(".zip"):
                        try:
                            inner_bytes = z.read(nest_info)
                            with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner_z:
                                for inner_info in inner_z.infolist()[:50]:
                                    inner_clean = sanitize_filename(inner_info.filename)
                                    inner_ext = inner_clean.lower().split(".")[-1]
                                    if inner_ext in ARCHIVE_EXTENSIONS:
                                        results["flags"].append("ARCHIVE_DEPTH_ANOMALY")
                                        results["evidence"].append(EvidenceItem(
                                            key="archive_depth_anomaly",
                                            value=f"nested_level_2 ({inner_clean})",
                                            description="Archive contains multiple nested archive layers exceeding depth limits."
                                        ))
                                        break
                                    if inner_ext in DANGEROUS_EXTENSIONS:
                                        results["flags"].append("SUSPICIOUS_ARCHIVE")
                                        if inner_ext in EXECUTABLE_EXTENSIONS:
                                            results["flags"].append("EXECUTABLE_ATTACHMENT")
                                        else:
                                            results["flags"].append("SCRIPT_ATTACHMENT")
                                        results["evidence"].append(EvidenceItem(
                                            key="nested_archive_payload",
                                            value=inner_clean,
                                            description=f"Nested archive contains payload: '{inner_clean}'."
                                        ))
                        except Exception:
                            pass

        except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            results["is_partial"] = True
            results["flags"].append("SUSPICIOUS_ARCHIVE")
            results["evidence"].append(EvidenceItem(
                key="archive_malformed",
                value=f"malformed_header ({type(exc).__name__})",
                description="Archive header is corrupted, malformed, or invalid."
            ))
        except Exception as exc:
            results["is_partial"] = True
            results["flags"].append("SUSPICIOUS_ARCHIVE")
            results["evidence"].append(EvidenceItem(
                key="archive_read_error",
                value=str(exc)[:100],
                description="Unable to safely parse full archive structure."
            ))

    return results


# -------------------------------------------------------------------------
# V2 Attachment Behavior Engine Class
# -------------------------------------------------------------------------

class AttachmentBehaviorEngine(BaseEngine):
    """
    V2 Attachment Behavior Engine.

    Performs safe, bounded static analysis on attachment metadata and byte headers.
    """

    @property
    def name(self) -> str:
        return "attachment_behavior_engine"

    async def analyze(self, input_data: ScanInput) -> EngineResult:
        file_bytes = input_data.file_bytes
        file_name = input_data.file_name
        metadata = input_data.metadata or {}

        # Support optional metadata-based attachments for email/message pipelines
        if not file_bytes and not file_name:
            attachments = metadata.get("attachments") or metadata.get("files")
            if isinstance(attachments, list) and attachments:
                first = attachments[0]
                if isinstance(first, dict):
                    file_name = first.get("file_name") or first.get("filename") or first.get("name")
                    file_bytes = first.get("file_bytes") or first.get("content") or first.get("bytes")
            elif isinstance(attachments, dict):
                file_name = attachments.get("file_name") or attachments.get("filename")
                file_bytes = attachments.get("file_bytes") or attachments.get("content")

        # When no attachment data is present at all, return SKIPPED
        if not file_bytes and not file_name:
            return EngineResult.skipped(self.name, "No attachment data to analyze")

        flags: list[str] = []
        evidence: list[EvidenceItem] = []
        clean_name = sanitize_filename(file_name)
        declared_ext = clean_name.lower().split(".")[-1] if "." in clean_name else ""
        detected_type = detect_magic_type(file_bytes) if file_bytes else "unknown"
        is_partial = False

        # -----------------------------------------------------------------
        # 1. Filename & Extension Rules
        # -----------------------------------------------------------------
        if clean_name:
            # Double Extension check
            if detect_double_extension(clean_name):
                flags.append("DOUBLE_EXTENSION")
                evidence.append(EvidenceItem(
                    key="double_extension",
                    value=clean_name,
                    description=f"Attachment uses a deceptive double file extension: '{clean_name}'."
                ))

            # Suspicious Filename / Lure check
            if detect_suspicious_filename(clean_name):
                flags.append("SUSPICIOUS_FILENAME")
                evidence.append(EvidenceItem(
                    key="suspicious_filename",
                    value=clean_name,
                    description=f"Attachment filename matches deceptive lure pattern: '{clean_name}'."
                ))

            # Suspicious Extension check
            if declared_ext in SUSPICIOUS_EVASION_EXTENSIONS:
                flags.append("SUSPICIOUS_EXTENSION")
                evidence.append(EvidenceItem(
                    key="suspicious_extension",
                    value=f".{declared_ext}",
                    description=f"Attachment uses a high-risk or suspicious file extension: '.{declared_ext}'."
                ))

            # Executable by extension
            if declared_ext in EXECUTABLE_EXTENSIONS:
                flags.append("EXECUTABLE_ATTACHMENT")
                evidence.append(EvidenceItem(
                    key="executable_extension",
                    value=f".{declared_ext}",
                    description=f"Attachment declared as executable file type: '.{declared_ext}'."
                ))

            # Script by extension
            if declared_ext in SCRIPT_EXTENSIONS:
                flags.append("SCRIPT_ATTACHMENT")
                evidence.append(EvidenceItem(
                    key="script_extension",
                    value=f".{declared_ext}",
                    description=f"Attachment declared as script file type: '.{declared_ext}'."
                ))

        # -----------------------------------------------------------------
        # 2. Magic Bytes & Type Mismatch
        # -----------------------------------------------------------------
        if file_bytes:
            # Executable by magic bytes
            if detected_type.startswith("executable/"):
                if "EXECUTABLE_ATTACHMENT" not in flags:
                    flags.append("EXECUTABLE_ATTACHMENT")
                    evidence.append(EvidenceItem(
                        key="executable_magic_bytes",
                        value=detected_type,
                        description=f"Attachment binary header matches executable format: '{detected_type}'."
                    ))

            # Script by magic bytes / shebang
            if detected_type == "script/shebang":
                if "SCRIPT_ATTACHMENT" not in flags:
                    flags.append("SCRIPT_ATTACHMENT")
                    evidence.append(EvidenceItem(
                        key="script_shebang",
                        value="script/shebang",
                        description="Attachment content begins with executable script shebang."
                    ))

            # Extension / Type Mismatch
            if clean_name and declared_ext:
                if detect_type_mismatch(declared_ext, detected_type):
                    flags.append("ATTACHMENT_TYPE_MISMATCH")
                    evidence.append(EvidenceItem(
                        key="attachment_type_mismatch",
                        value=f"declared=.{declared_ext}, detected={detected_type}",
                        description=f"Declared extension '.{declared_ext}' does not match detected type '{detected_type}'."
                    ))

            # -------------------------------------------------------------
            # 3. Macro Presence in Office Documents
            # -------------------------------------------------------------
            has_macro, macro_detail = detect_macro_presence(file_bytes, declared_ext, detected_type)
            if has_macro:
                flags.append("MACRO_PRESENT")
                evidence.append(EvidenceItem(
                    key="macro_present",
                    value=macro_detail,
                    description="Office document attachment contains embedded VBA macros."
                ))

            # -------------------------------------------------------------
            # 4. Embedded Scripts (PDF / OOXML / RTF / HTML)
            # -------------------------------------------------------------
            has_script, script_detail = detect_embedded_scripts(file_bytes, detected_type)
            if has_script:
                flags.append("EMBEDDED_SCRIPT")
                evidence.append(EvidenceItem(
                    key="embedded_script",
                    value=script_detail,
                    description=f"Attachment contains embedded script or launch action: {script_detail}."
                ))

            # -------------------------------------------------------------
            # 5. Archive Inspection (ZIP / TAR)
            # -------------------------------------------------------------
            archive_res = inspect_archive(file_bytes, declared_ext, detected_type)
            if archive_res["is_archive"]:
                flags.extend(archive_res["flags"])
                evidence.extend(archive_res["evidence"])
                if archive_res["is_partial"]:
                    is_partial = True

        # -----------------------------------------------------------------
        # Deterministic Scoring & Deduplication
        # -----------------------------------------------------------------
        unique_flags = sorted(list(dict.fromkeys(flags)))
        raw_score = sum(FLAG_WEIGHTS.get(f, 20.0) for f in unique_flags)
        risk_score = min(raw_score, MAX_ATTACHMENT_RISK_SCORE)

        # Confidence calculation
        if not unique_flags:
            confidence = 1.0 if file_bytes else 0.70
        else:
            high_confidence_indicators = {
                "EXECUTABLE_ATTACHMENT", "MACRO_PRESENT", "DOUBLE_EXTENSION",
                "ATTACHMENT_TYPE_MISMATCH", "ARCHIVE_EXPANSION_ANOMALY"
            }
            if any(f in high_confidence_indicators for f in unique_flags):
                confidence = 0.95 if file_bytes else 0.75
            else:
                confidence = 0.85 if file_bytes else 0.70

        # Deterministic evidence ordering
        evidence.sort(key=lambda item: (item.key, str(item.value)))

        status = EngineStatus.PARTIAL if is_partial else EngineStatus.SUCCESS

        return self._build_result(
            risk_score=risk_score,
            confidence=confidence,
            flags=unique_flags,
            evidence=evidence,
            status=status,
            metadata={
                "sanitized_filename": clean_name or "unknown",
                "detected_type": detected_type,
                "anomalies_detected": len(unique_flags)
            }
        )


# Register the engine exactly once
engine_registry.register(AttachmentBehaviorEngine())
