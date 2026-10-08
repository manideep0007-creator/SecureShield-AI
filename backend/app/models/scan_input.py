from __future__ import annotations

import base64
import binascii
from typing import Any

from pydantic import BaseModel, Field, field_validator

MAX_BINARY_PAYLOAD_BYTES: int = 10 * 1024 * 1024
MAX_ENCODED_PAYLOAD_CHARS: int = ((MAX_BINARY_PAYLOAD_BYTES + 2) // 3) * 4 + 64

_BASE64_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)


def decode_binary_payload(value: Any, field_name: str) -> Any:
    """
    Resolve a binary payload arriving through JSON transport.

    JSON cannot carry raw bytes, so clients transmit an encoded string. Accepted forms:
      - None                -> None
      - bytes / bytearray   -> used verbatim (direct in-process construction)
      - str                 -> MUST be base64 of the raw payload

    Base64 is mandatory for strings so binary payloads (PE, PDF, ZIP, images) stay
    byte-exact. Interpreting a string as UTF-8 would silently corrupt every non-text
    file and invalidate SHA-256 based malware lookups. Both standard and URL-safe
    alphabets are accepted, with or without padding.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be bytes or a base64-encoded string.")

    candidate = "".join(value.split())
    if not candidate:
        return None
    if len(candidate) > MAX_ENCODED_PAYLOAD_CHARS:
        raise ValueError(f"{field_name} exceeds the maximum supported encoded size.")
    if not set(candidate) <= _BASE64_ALPHABET:
        raise ValueError(f"{field_name} must be base64-encoded when sent as a string.")

    normalized = candidate.replace("-", "+").replace("_", "/")
    padding = (-len(normalized)) % 4
    if padding:
        normalized += "=" * padding

    try:
        return base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(
            f"{field_name} must be valid base64 when sent as a string."
        ) from error


class ScanInput(BaseModel):
    """
    Universal data model representing all possible input channels 
    for Secure Shield AI processing.

    Binary channels (file_bytes, image_bytes) accept raw bytes in-process and
    base64-encoded strings over JSON. See decode_binary_payload().
    """
    text: str | None = Field(default=None, description="Raw message text or body")
    url: str | None = Field(default=None, description="Extracted or direct URL to scan")
    sender_id: str | None = Field(default=None, description="Identifier for the sender (email, phone, etc.)")
    source_channel: str | None = Field(default=None, description="Source of the input (e.g., 'gmail', 'sms', 'system')")
    file_name: str | None = Field(default=None, description="Original name of the uploaded file")
    file_bytes: bytes | None = Field(default=None, description="Raw file payload representing documents or executables (base64 over JSON)")
    image_bytes: bytes | None = Field(default=None, description="Raw image payload for OCR/vision analysis (base64 over JSON)")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional arbitrary context or metadata")
    classification_profile: str | None = Field(default=None, description="Optional classification profile ('default', 'strict', 'enterprise')")
    client_id: str | None = Field(default=None, description="Client/tenant identifier (random UUID generated on device)")

    @field_validator("file_bytes", "image_bytes", mode="before")
    @classmethod
    def _decode_binary(cls, value: Any, info) -> Any:
        return decode_binary_payload(value, info.field_name)
