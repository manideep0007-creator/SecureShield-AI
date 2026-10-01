import pytest
from app.models.risk_assessment import RiskAssessment, RiskClassification
from app.models.engine_result import EvidenceItem
from app.explainability.explainability_engine import ExplainabilityEngine

def test_explain_safe():
    assessment = RiskAssessment(
        risk_score=0.0,
        classification=RiskClassification.SAFE,
        confidence=1.0,
        contributing_engines=["url_engine", "nlp_engine"],
        flags=[],
        evidence=[]
    )
    explained = ExplainabilityEngine.explain(assessment)
    assert explained.reasons == ["No suspicious indicators were found."]
    assert explained.recommended_action == "Proceed with normal caution."

def test_explain_suspicious_with_flags():
    assessment = RiskAssessment(
        risk_score=40.0,
        classification=RiskClassification.SUSPICIOUS,
        confidence=0.8,
        contributing_engines=["url_engine"],
        flags=["url_length_anomaly", "suspicious_tld"],
        evidence=[]
    )
    explained = ExplainabilityEngine.explain(assessment)
    assert "The URL is unusually long." in explained.reasons
    assert "The URL uses a Top-Level Domain (TLD) commonly associated with spam or malicious activity." in explained.reasons
    assert "Exercise caution" in explained.recommended_action

def test_explain_deceptive():
    assessment = RiskAssessment(
        risk_score=65.0,
        classification=RiskClassification.DECEPTIVE,
        confidence=0.9,
        contributing_engines=["sender_engine"],
        flags=["first_time_sender", "brand_impersonation"],
        evidence=[]
    )
    explained = ExplainabilityEngine.explain(assessment)
    assert "This is the first time receiving a message from this sender." in explained.reasons
    # Unmapped flag shouldn't crash, and other flags should be retained
    assert "Do not trust this content" in explained.recommended_action

def test_explain_phishing():
    assessment = RiskAssessment(
        risk_score=85.0,
        classification=RiskClassification.PHISHING,
        confidence=0.85,
        contributing_engines=["nlp_engine"],
        flags=["nlp_financial_urgency", "qr_code_detected"],
        evidence=[]
    )
    explained = ExplainabilityEngine.explain(assessment)
    print(explained.reasons)
    assert "Natural language processing found signs of financial urgency." in explained.reasons
    assert "A QR code was detected in the attached image." in explained.reasons
    assert "Report and delete this message." in explained.recommended_action

def test_explain_malware():
    assessment = RiskAssessment(
        risk_score=100.0,
        classification=RiskClassification.MALWARE,
        confidence=0.99,
        contributing_engines=["malware_engine"],
        flags=["vt_malicious", "extension_mismatch"],
        evidence=[]
    )
    explained = ExplainabilityEngine.explain(assessment)
    assert "VirusTotal identified this content as malicious." in explained.reasons
    assert "The file extension does not match its true type." in explained.reasons
    assert "Isolate and permanently delete the content immediately." in explained.recommended_action

def test_explain_low_confidence():
    assessment = RiskAssessment(
        risk_score=50.0,
        classification=RiskClassification.SUSPICIOUS,
        confidence=0.3,
        contributing_engines=["url_engine"],
        flags=["ip_based_host"],
        evidence=[]
    )
    explained = ExplainabilityEngine.explain(assessment)
    assert "The URL uses an IP address instead of a standard domain name, which is often used in evasion tactics." in explained.reasons
    assert "Note: The confidence of this scan is low due to missing or failed engine analyses." in explained.reasons

def test_explain_no_contributing_engines():
    assessment = RiskAssessment(
        risk_score=0.0,
        classification=RiskClassification.SAFE,
        confidence=0.0,
        contributing_engines=[],
        flags=[],
        evidence=[]
    )
    explained = ExplainabilityEngine.explain(assessment)
    assert "No detection engines successfully analyzed this input." in explained.reasons

def test_explain_no_flags_not_safe():
    assessment = RiskAssessment(
        risk_score=60.0,
        classification=RiskClassification.DECEPTIVE,
        confidence=0.7,
        contributing_engines=["url_engine"],
        flags=[],
        evidence=[]
    )
    explained = ExplainabilityEngine.explain(assessment)
    assert explained.reasons == ["Assessed based on aggregate engine analysis without specific discrete flags."]
