"""
V2 Engine Models — Standardized data structures for all detection engines.

Every V2 engine must return an EngineResult. This replaces the ad-hoc dicts
used in V1 (where each engine returned different keys) with a single contract.

V1 engines (backend/engines/) are NOT modified. These models apply to V2 only.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EngineStatus(str, Enum):
    """Outcome status of an engine execution."""
    SUCCESS = "success"           # Engine ran and produced a definitive result
    PARTIAL = "partial"           # Engine ran but some sub-checks failed (e.g. API key missing)
    ERROR = "error"               # Engine failed entirely — result should not be trusted
    SKIPPED = "skipped"           # Engine was not applicable to this input type


class EvidenceItem(BaseModel):
    """A single piece of evidence supporting a flag or score."""
    key: str = Field(..., description="Machine-readable evidence identifier (e.g. 'gsb_threat_type', 'sha256_hash')")
    value: Any = Field(..., description="The evidence value")
    description: str = Field(default="", description="Optional human-readable explanation of this evidence")


class EngineResult(BaseModel):
    """
    Universal return type for all V2 detection engines.

    Every engine — URL, malware, NLP, sender, or any future engine — must
    produce an EngineResult so the fusion layer can process them uniformly.

    Fields
    ------
    engine_name : str
        Unique identifier for the engine (e.g. "url_engine", "malware_engine").
    risk_score : float
        Threat score from 0.0 (safe) to 1.0 (maximum threat).
    confidence : float
        Self-reported confidence in the result, 0.0 to 1.0.
        In V1 this was hardcoded in fusion.py; V2 engines report it themselves.
    flags : list[str]
        Machine-readable threat indicators (e.g. "ip_based_host", "vt_malicious").
    evidence : list[EvidenceItem]
        Supporting data points that justify the score and flags.
    status : EngineStatus
        Whether the engine succeeded, partially succeeded, errored, or was skipped.
    error_message : str | None
        Human-readable error description when status is ERROR or PARTIAL.
    metadata : dict[str, Any]
        Arbitrary engine-specific data (sub-scores, API responses, timing, etc.).
    """
    engine_name: str = Field(..., description="Unique engine identifier")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Threat score 0–100")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Self-reported confidence 0.0–1.0")
    flags: list[str] = Field(default_factory=list, description="Machine-readable threat flags")
    evidence: list[EvidenceItem] = Field(default_factory=list, description="Evidence supporting the verdict")
    status: EngineStatus = Field(default=EngineStatus.SUCCESS, description="Execution outcome")
    error_message: str | None = Field(default=None, description="Error details when status is ERROR or PARTIAL")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Engine-specific auxiliary data")

    @staticmethod
    def skipped(engine_name: str, reason: str = "Not applicable to input type") -> EngineResult:
        """Factory for quickly creating a SKIPPED result."""
        return EngineResult(
            engine_name=engine_name,
            risk_score=0.0,
            confidence=0.0,
            status=EngineStatus.SKIPPED,
            error_message=reason,
        )

    @staticmethod
    def error(engine_name: str, message: str) -> EngineResult:
        """Factory for quickly creating an ERROR result."""
        return EngineResult(
            engine_name=engine_name,
            risk_score=0.0,
            confidence=0.0,
            status=EngineStatus.ERROR,
            error_message=message,
        )
