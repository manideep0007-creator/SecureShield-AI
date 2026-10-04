from pydantic import BaseModel, Field
from typing import Any


class ScanInput(BaseModel):
    """
    Universal data model representing all possible input channels 
    for Secure Shield AI processing.
    """
    text: str | None = Field(default=None, description="Raw message text or body")
    url: str | None = Field(default=None, description="Extracted or direct URL to scan")
    sender_id: str | None = Field(default=None, description="Identifier for the sender (email, phone, etc.)")
    source_channel: str | None = Field(default=None, description="Source of the input (e.g., 'gmail', 'sms', 'system')")
    file_name: str | None = Field(default=None, description="Original name of the uploaded file")
    file_bytes: bytes | None = Field(default=None, description="Raw file payload representing documents or executables")
    image_bytes: bytes | None = Field(default=None, description="Raw image payload for OCR/vision analysis")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional arbitrary context or metadata")
    classification_profile: str | None = Field(default=None, description="Optional classification profile ('default', 'strict', 'enterprise')")
