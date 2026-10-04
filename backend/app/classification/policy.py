"""
V2 Dynamic Risk Classification Policy & Context Profiles (Phase 19).

Provides validated, deterministic classification policies that map unified 0–100
risk scores into discrete RiskClassification categories without replacing Phase 7
Risk Fusion.

Architecture:
- Phase 7 Risk Fusion computes the unified confidence-weighted risk score (0–100).
- Phase 19 Classification Policy governs how that score and malware signals map to
  Safe, Suspicious, Deceptive, Phishing, or Malware categories.
- Profiles (default, strict, enterprise) configure thresholds declaratively.
- Malware safeguard: score alone never produces Malware without a verified malware signal.
- Feedback boundary: user feedback cannot automatically retune security thresholds.
- Privacy boundary: operates strictly on scores, flags, and metadata; never accesses raw content.
"""

from __future__ import annotations

from typing import Any, Iterable
from pydantic import BaseModel, Field, model_validator

from app.models.risk_assessment import RiskAssessment, RiskClassification


MALWARE_FLAGS = frozenset({
    "MALWARE",
    "malware_detected",
    "vt_malicious",
    "vt_suspicious",
})


class ClassificationPolicy(BaseModel):
    """
    Validated configuration governing score-to-category mapping.
    
    Threshold ordering rule:
        0.0 <= safe_upper < suspicious_upper < deceptive_upper < phishing_upper <= 100.0
    """
    name: str = Field(default="custom", description="Profile/policy identifier")
    safe_upper: float = Field(default=20.0, description="Exclusive upper boundary for Safe (< safe_upper)")
    suspicious_upper: float = Field(default=45.0, description="Exclusive upper boundary for Suspicious (< suspicious_upper)")
    deceptive_upper: float = Field(default=70.0, description="Exclusive upper boundary for Deceptive (< deceptive_upper)")
    phishing_upper: float = Field(default=90.0, description="Exclusive upper boundary for Phishing (< phishing_upper)")
    malware_requires_signal: bool = Field(default=True, description="Strictly require malware signal for Malware classification")
    description: str = Field(default="", description="Human-readable policy description")

    @model_validator(mode="after")
    def validate_thresholds(self) -> ClassificationPolicy:
        # 1. Bounds check (0.0 to 100.0)
        thresholds = [
            ("safe_upper", self.safe_upper),
            ("suspicious_upper", self.suspicious_upper),
            ("deceptive_upper", self.deceptive_upper),
            ("phishing_upper", self.phishing_upper),
        ]
        for name, val in thresholds:
            if val < 0.0 or val > 100.0:
                raise ValueError(
                    f"Threshold '{name}' must be between 0.0 and 100.0, got {val}"
                )

        # 2. Strict ordering check
        if not (self.safe_upper < self.suspicious_upper):
            raise ValueError(
                f"Invalid threshold ordering: safe_upper ({self.safe_upper}) must be strictly less than "
                f"suspicious_upper ({self.suspicious_upper})"
            )
        if not (self.suspicious_upper < self.deceptive_upper):
            raise ValueError(
                f"Invalid threshold ordering: suspicious_upper ({self.suspicious_upper}) must be strictly less than "
                f"deceptive_upper ({self.deceptive_upper})"
            )
        if not (self.deceptive_upper < self.phishing_upper):
            raise ValueError(
                f"Invalid threshold ordering: deceptive_upper ({self.deceptive_upper}) must be strictly less than "
                f"phishing_upper ({self.phishing_upper})"
            )

        return self

    def classify(
        self,
        score: float,
        malware_signal: bool = False,
        flags: Iterable[str] | None = None,
    ) -> RiskClassification:
        """
        Deterministically map a risk score and malware signal to a RiskClassification.
        
        Boundary semantics:
        - score < safe_upper -> Safe
        - score < suspicious_upper -> Suspicious
        - score < deceptive_upper -> Deceptive
        - score < phishing_upper -> Phishing
        - score >= phishing_upper:
          - If malware_signal is True (or malware flag present) -> Malware
          - Else -> Phishing
        """
        score_val = max(0.0, min(100.0, float(score)))

        has_malware = malware_signal
        if not has_malware and flags:
            has_malware = bool(MALWARE_FLAGS.intersection(flags))

        if score_val < self.safe_upper:
            return RiskClassification.SAFE
        if score_val < self.suspicious_upper:
            return RiskClassification.SUSPICIOUS
        if score_val < self.deceptive_upper:
            return RiskClassification.DECEPTIVE
        if score_val < self.phishing_upper:
            return RiskClassification.PHISHING

        # At or above phishing_upper (e.g. >= 90.0 in default):
        if self.malware_requires_signal:
            return RiskClassification.MALWARE if has_malware else RiskClassification.PHISHING
        return RiskClassification.MALWARE

    def classify_assessment(
        self,
        assessment: RiskAssessment,
        malware_signal: bool | None = None,
    ) -> RiskAssessment:
        """
        Apply this policy to update an existing RiskAssessment's classification.
        Returns a new or updated RiskAssessment instance.
        """
        signal = malware_signal if malware_signal is not None else bool(MALWARE_FLAGS.intersection(assessment.flags))
        new_classification = self.classify(assessment.risk_score, malware_signal=signal, flags=assessment.flags)
        assessment.classification = new_classification
        return assessment


# -----------------------------------------------------------------------------
# Predefined Context Profiles
# -----------------------------------------------------------------------------

DEFAULT_PROFILE = ClassificationPolicy(
    name="default",
    safe_upper=20.0,
    suspicious_upper=45.0,
    deceptive_upper=70.0,
    phishing_upper=90.0,
    malware_requires_signal=True,
    description="Standard SecureShield AI default 5-tier classification policy matching Phase 7 Risk Fusion.",
)

STRICT_PROFILE = ClassificationPolicy(
    name="strict",
    safe_upper=15.0,
    suspicious_upper=35.0,
    deceptive_upper=55.0,
    phishing_upper=80.0,
    malware_requires_signal=True,
    description="Strict classification policy with heightened threat sensitivity for elevated-risk environments.",
)

ENTERPRISE_PROFILE = ClassificationPolicy(
    name="enterprise",
    safe_upper=10.0,
    suspicious_upper=30.0,
    deceptive_upper=50.0,
    phishing_upper=75.0,
    malware_requires_signal=True,
    description="Enterprise zero-trust classification policy with aggressive suspicion thresholds.",
)

PROFILES: dict[str, ClassificationPolicy] = {
    "default": DEFAULT_PROFILE,
    "strict": STRICT_PROFILE,
    "enterprise": ENTERPRISE_PROFILE,
}


def get_classification_profile(
    name: str | None = None,
    *,
    fallback_to_default: bool = True,
) -> ClassificationPolicy:
    """
    Retrieve a validated classification profile by name.
    
    If name is None or empty, returns the default profile.
    If name is unknown and fallback_to_default is True, safely returns the default profile.
    If name is unknown and fallback_to_default is False, raises ValueError.
    """
    if not name:
        return PROFILES["default"]

    key = str(name).strip().lower()
    if key in PROFILES:
        return PROFILES[key]

    if fallback_to_default:
        return PROFILES["default"]

    raise ValueError(
        f"Unknown classification profile: '{name}'. Supported profiles: {list(PROFILES.keys())}"
    )


# -----------------------------------------------------------------------------
# Feedback Safety & Immutability Boundary
# -----------------------------------------------------------------------------

def is_feedback_tuning_allowed() -> bool:
    """
    Explicit architectural boundary: Feedback data is advisory only and
    cannot automatically retune policy thresholds.
    """
    return False


def apply_feedback_tuning(policy: ClassificationPolicy, feedback_data: dict[str, Any]) -> ClassificationPolicy:
    """
    Explicitly refuses runtime policy modification via user feedback.
    Feedback cannot dynamically change classification decisions.
    """
    raise PermissionError(
        "Security policy violation: Automatic modification of classification thresholds from user feedback "
        "is forbidden by architectural design."
    )
