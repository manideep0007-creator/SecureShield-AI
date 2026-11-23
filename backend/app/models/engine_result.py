"""
V2 Engine Models — Standardized data structures for all detection engines.

Every V2 engine must return an EngineResult. This replaces the ad-hoc dicts
used in V1 with a single contract.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class EngineStatus(str, Enum):
    """Outcome status of an engine execution."""
    SUCCESS = "success"           # Engine ran and produced a definitive result
    PARTIAL = "partial"           # Engine ran but some sub-checks failed (e.g. API key missing)
    ERROR = "error"               # Engine failed entirely — result should not be trusted
    SKIPPED = "skipped"           # Engine was not applicable to this input type


class EvidenceItem(BaseModel):
    """A single piece of evidence supporting a flag or score."""
    key: str = Field(..., description="Machine-readable evidence identifier")
    value: Any = Field(..., description="The evidence value")
    description: str = Field(default="", description="Optional human-readable explanation")


class EngineResult(BaseModel):
    """Universal return type for all V2 detection engines."""
    engine_name: str = Field(..., description="Unique engine identifier")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Threat score 0–100")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Self-reported confidence 0.0–1.0")
    flags: list[str] = Field(default_factory=list, description="Machine-readable threat flags")
    evidence: list[EvidenceItem] = Field(default_factory=list, description="Evidence supporting the verdict")
    status: EngineStatus = Field(default=EngineStatus.SUCCESS, description="Execution outcome")
    error_message: str | None = Field(default=None, description="Error details when status is ERROR or PARTIAL")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Engine-specific auxiliary data")

    @field_validator("risk_score", mode="before")
    @classmethod
    def clamp_risk_score(cls, v: Any) -> float:
        try:
            val = float(v)
            return max(0.0, min(100.0, val))
        except (ValueError, TypeError):
            return 0.0

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: Any) -> float:
        try:
            val = float(v)
            return max(0.0, min(1.0, val))
        except (ValueError, TypeError):
            return 0.0

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
