"""Confidence-weighted fusion for V2 ``EngineResult`` values."""

from __future__ import annotations

from collections.abc import Iterable

from app.classification.policy import ClassificationPolicy, get_classification_profile
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.risk_assessment import RiskAssessment, RiskClassification


ENGINE_RELIABILITY = {
    "url_engine": 0.90,
    "malware_engine": 1.00,
    "nlp_engine": 0.80,
    "visual_engine": 0.90,
    "sender_engine": 0.60,
}

MALWARE_FLAGS = frozenset({"MALWARE", "malware_detected", "vt_malicious", "vt_suspicious"})


def _classification(
    score: float,
    malware_signal: bool,
    policy: ClassificationPolicy | str | None = None,
) -> RiskClassification:
    active_policy = policy if isinstance(policy, ClassificationPolicy) else get_classification_profile(policy)
    return active_policy.classify(score, malware_signal)


def _has_malware_signal(result: EngineResult) -> bool:
    if result.confidence < 0.5:
        return False
    return (
        result.engine_name == "malware_engine" and result.risk_score >= 90.0
    ) or bool(MALWARE_FLAGS.intersection(result.flags))


def fuse_engine_results(
    results: Iterable[EngineResult],
    policy: ClassificationPolicy | str | None = None,
) -> RiskAssessment:
    """Combine usable engine results without penalizing unavailable engines.

    Successful results use ``confidence * engine reliability`` as their weight.
    Partial results contribute at half weight because they contain incomplete
    analysis. Skipped and error results are recorded as ignored and contribute
    neither risk nor confidence.
    
    Classification is determined by the provided or default ``ClassificationPolicy``.
    """
    ordered_results = sorted(results, key=lambda result: result.engine_name)
    usable = [
        result
        for result in ordered_results
        if result.status in {EngineStatus.SUCCESS, EngineStatus.PARTIAL}
        and result.confidence > 0.0
    ]
    ignored = [
        result.engine_name
        for result in ordered_results
        if result.status in {EngineStatus.SKIPPED, EngineStatus.ERROR}
        or result.confidence <= 0.0
    ]

    weighted_score = 0.0
    total_weight = 0.0
    total_reliability = 0.0
    flags: set[str] = set()
    evidence: list[EvidenceItem] = []
    malware_signal = False

    for result in usable:
        reliability = ENGINE_RELIABILITY.get(result.engine_name, 0.75)
        status_factor = 0.5 if result.status == EngineStatus.PARTIAL else 1.0
        weight = result.confidence * reliability * status_factor
        weighted_score += result.risk_score * weight
        total_weight += weight
        total_reliability += reliability * status_factor
        flags.update(result.flags)
        evidence.extend(result.evidence)
        malware_signal = malware_signal or _has_malware_signal(result)

    score = round(weighted_score / total_weight, 2) if total_weight else 0.0
    aggregate_confidence = (
        min(1.0, total_weight / total_reliability)
        if total_reliability
        else 0.0
    )

    return RiskAssessment(
        risk_score=score,
        classification=_classification(score, malware_signal, policy=policy),
        confidence=round(aggregate_confidence, 4),
        contributing_engines=[result.engine_name for result in usable],
        ignored_engines=sorted(set(ignored)),
        flags=sorted(flags),
        evidence=evidence,
    )