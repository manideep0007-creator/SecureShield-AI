from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FeedbackValue = Literal["positive", "negative"]
FeedbackClassification = Literal["Safe", "Suspicious", "Deceptive", "Phishing", "Malware"]
FeedbackSource = Literal["url", "file", "share", "gmail", "unknown"]

_SCAN_ID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(pattern=_SCAN_ID_PATTERN)
    user_feedback: FeedbackValue
    classification_at_scan_time: FeedbackClassification
    risk_score_at_scan_time: float = Field(ge=0, le=100, allow_inf_nan=False)
    confidence_at_scan_time: float = Field(ge=0, le=1, allow_inf_nan=False, default=0)
    source_type: FeedbackSource = "unknown"

    @model_validator(mode="before")
    @classmethod
    def adapt_phase9_request(cls, values):
        if not isinstance(values, dict):
            return values
        uf = values.get("user_feedback")
        if uf in ("correct", "accurate"):
            values["user_feedback"] = "positive"
        elif uf in ("incorrect", "inaccurate"):
            values["user_feedback"] = "negative"

        if "scan_id" in values:
            return values
        legacy_target = values.get("analyzed_target")
        if legacy_target is None:
            return values
        old_feedback = values.get("feedback_value")
        normalized_feedback = {"up": "positive", "down": "negative"}.get(old_feedback, old_feedback)
        adapted = dict(values)
        adapted.update(
            scan_id=legacy_target,
            user_feedback=normalized_feedback,
            classification_at_scan_time=values.get("category"),
            risk_score_at_scan_time=values.get("score"),
            confidence_at_scan_time=values.get("confidence_at_scan_time", 0),
            source_type=values.get("source_type", "unknown"),
        )
        for legacy_field in ("analyzed_target", "feedback_value", "category", "score"):
            adapted.pop(legacy_field, None)
        return adapted


class FeedbackSubmissionResponse(BaseModel):
    status: Literal["success"]
    scan_id: str
    timestamp: str


class FeedbackCounts(BaseModel):
    total_count: int
    positive_count: int
    negative_count: int
    positive_rate: float
    negative_rate: float


class EvaluationMetrics(BaseModel):
    total_feedback_count: int
    positive_feedback_count: int
    negative_feedback_count: int
    positive_feedback_rate: float
    negative_feedback_rate: float
    feedback_count_by_classification: dict[str, int]
    feedback_count_by_source_type: dict[str, int]
    average_risk_score_positive: float | None
    average_risk_score_negative: float | None
    classification_feedback_summary: dict[str, FeedbackCounts]