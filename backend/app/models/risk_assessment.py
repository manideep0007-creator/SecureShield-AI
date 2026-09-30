"""Unified risk assessment produced from V2 engine results."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from app.models.engine_result import EvidenceItem


class RiskClassification(str, Enum):
    """The complete set of user-facing risk classifications."""

    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    DECEPTIVE = "Deceptive"
    PHISHING = "Phishing"
    MALWARE = "Malware"


class RiskAssessment(BaseModel):
    """Deterministic aggregate assessment for a unified scan."""

    risk_score: float = Field(..., ge=0.0, le=100.0)
    classification: RiskClassification
    confidence: float = Field(..., ge=0.0, le=1.0)
    contributing_engines: list[str] = Field(default_factory=list)
    ignored_engines: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)