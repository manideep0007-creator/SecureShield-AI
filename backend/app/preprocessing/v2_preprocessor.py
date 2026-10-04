"""
V2 Preprocessing Layer — Centralized Input Normalization & Sanitization.

Performs safe, deterministic preprocessing of all ScanInput channels:
- Text/Message normalization: Unicode NFKC, control-char stripping, whitespace collapsing, length bounding.
- URL normalization: Scheme/host lowercasing, default port stripping, bracket trimming, malformed scheme rejection.
- File/Attachment normalization: 10 MB limit enforcement, basename extraction, path traversal removal, type validation.
- Email/Header metadata normalization: Sender extraction, case-folded header mapping, Received-chain bounding, auth preservation.

SAFETY & PRIVACY:
- NO shell or code execution.
- NO network requests or external uploads during preprocessing.
- NO persistence of raw attachment bytes, email bodies, passwords, or credentials.
- Bounded memory and deterministic execution.
"""

from __future__ import annotations

import re
import unicodedata
from enum import Enum
from typing import Any
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel, Field

from app.models.scan_input import ScanInput


# -------------------------------------------------------------------------
# Resource Limits & Safety Boundaries
# -------------------------------------------------------------------------

MAX_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB strict limit
MAX_TEXT_LENGTH: int = 50_000           # 50,000 characters
MAX_URL_LENGTH: int = 4096              # 4,096 characters
MAX_FILENAME_LENGTH: int = 255          # 255 characters
MAX_METADATA_ITEMS: int = 100           # 100 entries
MAX_LIST_ITEMS: int = 50                # 50 items
MAX_RECEIVED_HOPS: int = 30             # 30 received hops


# -------------------------------------------------------------------------
# Models
# -------------------------------------------------------------------------

class PreprocessingStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    REJECTED = "rejected"


class PreprocessingResult(BaseModel):
    status: PreprocessingStatus
    normalized_input: ScanInput
    warnings: list[str] = Field(default_factory=list)
    error_message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


# -------------------------------------------------------------------------
# Normalization Helpers
# -------------------------------------------------------------------------

def normalize_text(text: str | None) -> tuple[str | None, list[str]]:
    """
    Safely normalize text input:
    - Bounded length (MAX_TEXT_LENGTH)
    - Unicode NFKC normalization
    - Strip non-printable ASCII control characters (preserving \\n, \\r, \\t)
    - Collapse excessive spaces and consecutive blank lines
    """
    if text is None:
        return None, []
    if not isinstance(text, str):
        text = str(text)

    warnings: list[str] = []

    # 1. Bounded text length
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH]
        warnings.append("text_truncated_to_max_length")

    # Check for control characters
    has_ctrl = any((ord(c) < 32 and c not in ("\n", "\r", "\t")) or ord(c) == 127 for c in text)
    if has_ctrl:
        warnings.append("control_characters_stripped")

    # 2. Unicode normalization (NFKC decomposes compatibility chars to standard forms)
    text = unicodedata.normalize("NFKC", text)

    # 3. Strip control characters (except \n, \r, \t)
    text = "".join(c for c in text if c in ("\n", "\r", "\t") or (ord(c) >= 32 and ord(c) != 127))

    # 4. Normalize line endings to \n
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # 5. Whitespace normalization:
    lines = [re.sub(r"[^\S\n]+", " ", line).strip() for line in text.split("\n")]
    text = "\n".join(lines)

    # Collapse more than 2 consecutive newlines into 2
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    return text if text else None, warnings


def normalize_url(url: str | None) -> tuple[str | None, list[str], bool]:
    """
    Safely normalize URL input:
    - Strip surrounding whitespace and angle brackets / quotes (<...>, "...", '...')
    - Lowercase scheme and host
    - Strip default ports (80 for http, 443 for https)
    - Reject unsupported or dangerous schemes (javascript:, file:, data:, etc.)
    - Return (normalized_url, warnings, is_valid)
    """
    if url is None:
        return None, [], True
    if not isinstance(url, str):
        url = str(url)

    warnings: list[str] = []
    clean_url = url.strip()

    # 1. Bounded URL length
    if len(clean_url) > MAX_URL_LENGTH:
        return None, ["url_exceeds_max_length"], False

    # 2. Strip common enclosing wrapper characters
    for open_ch, close_ch in [("<", ">"), ("(", ")"), ("[", "]"), ('"', '"'), ("'", "'")]:
        if clean_url.startswith(open_ch) and clean_url.endswith(close_ch):
            clean_url = clean_url[1:-1].strip()

    if not clean_url:
        return None, ["empty_url_after_stripping"], False

    # Reject control characters in URLs
    if any((ord(c) < 32 and c not in ("\t",)) or ord(c) == 127 for c in clean_url):
        return None, ["url_contains_control_characters"], False

    # 3. Scheme check
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url))
    if not has_scheme:
        if ":" in clean_url and not clean_url.startswith(("/", "\\")):
            pseudo_scheme = clean_url.split(":", 1)[0].lower()
            if pseudo_scheme in ("javascript", "data", "file", "vbscript", "about"):
                return None, [f"unsupported_scheme_{pseudo_scheme}"], False
        clean_url = "http://" + clean_url
        warnings.append("url_scheme_defaulted_to_http")

    try:
        parsed = urlparse(clean_url)
    except Exception:
        return None, ["malformed_url_syntax"], False

    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        return None, [f"unsupported_scheme_{scheme}"], False

    if not parsed.hostname:
        return None, ["missing_url_host"], False

    if parsed.username or parsed.password:
        warnings.append("url_embedded_credentials_present")

    # Lowercase hostname and strip standard default ports
    netloc = parsed.netloc
    host = parsed.hostname
    port = parsed.port
    if host:
        host_lower = host.lower()
        userinfo = ""
        if parsed.username:
            userinfo += parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            userinfo += "@"

        port_str = ""
        if port:
            if not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                port_str = f":{port}"

        netloc = f"{userinfo}{host_lower}{port_str}"

    normalized = urlunparse((
        scheme,
        netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    return normalized, warnings, True


def normalize_file(
    file_name: str | None, file_bytes: bytes | None
) -> tuple[str | None, bytes | None, dict[str, Any], list[str], bool]:
    """
    Safely normalize file/attachment input:
    - Enforces strict 10 MB file boundary
    - Extracts clean basename, stripping directory traversals and path prefixes
    - Strips control characters and normalizes Unicode
    - Performs magic-byte file type checking via existing utilities
    - Returns (clean_filename, file_bytes, details, warnings, is_valid)
    """
    warnings: list[str] = []
    details: dict[str, Any] = {}

    # Strict 10 MB enforcement
    if file_bytes is not None:
        if len(file_bytes) > MAX_FILE_BYTES:
            return None, None, {}, ["file_exceeds_10mb_limit"], False

    clean_name = None
    if file_name:
        if not isinstance(file_name, str):
            file_name = str(file_name)
        # Normalize slashes and take basename to eliminate path traversals
        base = file_name.replace("\\", "/").split("/")[-1].strip()
        # Strip non-printable ASCII control characters
        has_ctrl = any((ord(c) < 32 and c not in ("\t",)) or ord(c) == 127 for c in base)
        if has_ctrl:
            warnings.append("filename_control_characters_stripped")
        base = "".join(c for c in base if ord(c) >= 32 and ord(c) != 127)
        # NFKC normalize
        base = unicodedata.normalize("NFKC", base).strip()
        if len(base) > MAX_FILENAME_LENGTH:
            base = base[:MAX_FILENAME_LENGTH]
            warnings.append("filename_truncated_to_max_length")
        clean_name = base if base else None

    # Determine file type metadata if both bytes and filename are available
    if file_bytes and clean_name:
        try:
            from app.preprocessing.data_prep import check_file_type
            type_check = check_file_type(file_bytes, clean_name)
            details["actual_mime"] = type_check.get("actual_mime")
            details["actual_ext"] = type_check.get("actual_ext")
            details["extension_mismatch"] = type_check.get("extension_mismatch", False)
        except Exception:
            pass

    return clean_name, file_bytes, details, warnings, True


def normalize_email_metadata(
    sender_id: str | None, metadata: dict[str, Any] | None
) -> tuple[str | None, dict[str, Any], list[str]]:
    """
    Safely normalize sender and header metadata:
    - Extracts clean email address from sender display name (<...>)
    - Bounds metadata entries and nested lists
    - Standardizes header keys and values
    - Bounds Received chain hops to MAX_RECEIVED_HOPS
    - Preserves Authentication-Results / SPF / DKIM / DMARC integrity
    """
    warnings: list[str] = []
    clean_sender = None

    if sender_id is not None:
        s = str(sender_id).strip()
        match = re.search(r"<([^>]+)>", s)
        if match:
            clean_sender = match.group(1).strip().lower()
        else:
            clean_sender = s.lower() if "@" in s else s

    if metadata is None:
        return clean_sender, {}, warnings

    meta_copy: dict[str, Any] = {}
    items_count = 0
    for k, v in metadata.items():
        items_count += 1
        if items_count > MAX_METADATA_ITEMS:
            warnings.append("metadata_items_limit_exceeded")
            break
        meta_copy[k] = v

    # Normalize headers dictionary if present
    headers = meta_copy.get("headers")
    if isinstance(headers, dict):
        norm_headers: dict[str, Any] = {}
        for hk, hv in list(headers.items())[:MAX_METADATA_ITEMS]:
            clean_hk = str(hk).strip()
            # Bounded Received chain
            if clean_hk.lower() == "received":
                if isinstance(hv, list):
                    if len(hv) > MAX_RECEIVED_HOPS:
                        hv = hv[:MAX_RECEIVED_HOPS]
                        warnings.append("received_chain_hops_truncated")
                    hv = [str(hop).strip() for hop in hv]
                elif isinstance(hv, str):
                    hv = hv.strip()
            elif isinstance(hv, str):
                hv = "".join(c for c in hv if ord(c) >= 32 or c in ("\n", "\r", "\t")).strip()
            norm_headers[clean_hk] = hv
        meta_copy["headers"] = norm_headers

    return clean_sender, meta_copy, warnings


# -------------------------------------------------------------------------
# V2 Preprocessor Class
# -------------------------------------------------------------------------

class V2Preprocessor:
    """
    V2 Centralized Preprocessor.
    
    Provides deterministic input normalization and sanitization prior to
    engine execution in the Unified Scan Pipeline.
    """

    def preprocess(self, input_data: ScanInput) -> PreprocessingResult:
        warnings: list[str] = []
        details: dict[str, Any] = {}

        try:
            # 1. Text normalization
            norm_text, text_warnings = normalize_text(input_data.text)
            warnings.extend(text_warnings)

            # 2. URL normalization
            norm_url, url_warnings, url_valid = normalize_url(input_data.url)
            warnings.extend(url_warnings)
            if not url_valid:
                return PreprocessingResult(
                    status=PreprocessingStatus.REJECTED,
                    normalized_input=input_data,
                    warnings=warnings,
                    error_message=f"Invalid or rejected URL: {url_warnings[0] if url_warnings else 'malformed URL'}",
                    details=details,
                )

            # 3. File normalization & 10 MB limit enforcement
            clean_file_name, norm_file_bytes, file_details, file_warnings, file_valid = normalize_file(
                input_data.file_name, input_data.file_bytes
            )
            warnings.extend(file_warnings)
            details.update(file_details)
            if not file_valid:
                return PreprocessingResult(
                    status=PreprocessingStatus.REJECTED,
                    normalized_input=input_data,
                    warnings=warnings,
                    error_message="File exceeds maximum allowed size of 10MB",
                    details=details,
                )

            # 4. Email metadata normalization
            clean_sender, norm_meta, meta_warnings = normalize_email_metadata(
                input_data.sender_id, input_data.metadata
            )
            warnings.extend(meta_warnings)

            normalized_input = ScanInput(
                text=norm_text,
                url=norm_url,
                sender_id=clean_sender,
                source_channel=input_data.source_channel,
                file_name=clean_file_name,
                file_bytes=norm_file_bytes,
                image_bytes=input_data.image_bytes,
                metadata=norm_meta,
                classification_profile=input_data.classification_profile,
            )

            # 5. Check if normalized_input contains scannable data
            has_content = any([
                normalized_input.text,
                normalized_input.url,
                normalized_input.file_bytes,
                normalized_input.image_bytes,
                normalized_input.sender_id,
                normalized_input.file_name,
            ])
            if not has_content:
                return PreprocessingResult(
                    status=PreprocessingStatus.REJECTED,
                    normalized_input=normalized_input,
                    warnings=warnings,
                    error_message="ScanInput contains no valid scannable content after normalization.",
                    details=details,
                )

            status = PreprocessingStatus.PARTIAL if warnings else PreprocessingStatus.SUCCESS

            return PreprocessingResult(
                status=status,
                normalized_input=normalized_input,
                warnings=warnings,
                details=details,
            )

        except Exception as exc:
            return PreprocessingResult(
                status=PreprocessingStatus.REJECTED,
                normalized_input=input_data,
                warnings=[f"preprocessing_error: {str(exc)}"],
                error_message=f"Preprocessing failed: {str(exc)}",
                details={"exception": str(exc)},
            )
