from __future__ import annotations

from app.database.feedback import read_feedback_records
from app.models.feedback import EvaluationMetrics, FeedbackCounts

CLASSIFICATIONS = ("Safe", "Suspicious", "Deceptive", "Phishing", "Malware")
SOURCE_TYPES = ("url", "file", "share", "gmail", "unknown")


def calculate_feedback_metrics(records: list[dict]) -> EvaluationMetrics:
    by_classification = {
        classification: {"positive": 0, "negative": 0}
        for classification in CLASSIFICATIONS
    }
    by_source = {source: 0 for source in SOURCE_TYPES}
    positive_scores: list[float] = []
    negative_scores: list[float] = []
    positive_count = 0
    negative_count = 0

    for record in records:
        feedback = record.get("user_feedback")
        if feedback not in ("positive", "negative"):
            continue
        classification = record.get("classification_at_scan_time")
        if classification not in by_classification:
            continue
        source = record.get("source_type")
        if source not in by_source:
            source = "unknown"
        by_source[source] += 1
        by_classification[classification][feedback] += 1
        risk_score = record.get("risk_score_at_scan_time")
        if risk_score is not None:
            (positive_scores if feedback == "positive" else negative_scores).append(float(risk_score))
        if feedback == "positive":
            positive_count += 1
        else:
            negative_count += 1

    total = positive_count + negative_count
    summaries = {}
    for classification, counts in by_classification.items():
        class_total = counts["positive"] + counts["negative"]
        summaries[classification] = FeedbackCounts(
            total_count=class_total,
            positive_count=counts["positive"],
            negative_count=counts["negative"],
            positive_rate=counts["positive"] / class_total if class_total else 0.0,
            negative_rate=counts["negative"] / class_total if class_total else 0.0,
        )

    return EvaluationMetrics(
        total_feedback_count=total,
        positive_feedback_count=positive_count,
        negative_feedback_count=negative_count,
        positive_feedback_rate=positive_count / total if total else 0.0,
        negative_feedback_rate=negative_count / total if total else 0.0,
        feedback_count_by_classification={
            classification: counts["positive"] + counts["negative"]
            for classification, counts in by_classification.items()
        },
        feedback_count_by_source_type=by_source,
        average_risk_score_positive=sum(positive_scores) / len(positive_scores) if positive_scores else None,
        average_risk_score_negative=sum(negative_scores) / len(negative_scores) if negative_scores else None,
        classification_feedback_summary=summaries,
    )


def get_feedback_metrics(db_path: str | None = None) -> EvaluationMetrics:
    return calculate_feedback_metrics(read_feedback_records(db_path))