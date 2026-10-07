import re
from app.engines.base_engine import BaseEngine
from app.engines.registry import engine_registry
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.scan_input import ScanInput

CATEGORIES = {
    "urgency": [
        r"\b(act(?:ing)?\s+now|action\s+required|urgent(?:ly)?|urgency|immediate(?:ly)?|asap|time\s+is\s+running\s+out|(?:within\s+)?24\s+hours)\b"
    ],
    "credential_request": [
        r"\b(password(?:s)?|passcode(?:s)?|log[\s-]?in(?:s)?|logging[\s-]?in|verif(?:y|ying|ication(?:\s+of)?)\s+(?:your\s+)?(?:account|identity|credentials?)|ssn|social\s+security(?:\s+number)?)\b",
        r"\b((?:share|enter|send|provide|give|submit|reply\s+with|input|type|forward)\s+(?:your\s+|the\s+)?(?:otp|one[\s-]?time\s+(?:code|password|passcode)))\b",
    ],
    "account_suspension": [
        r"\b(suspend(?:ed|ing)?|suspension(?:s)?|lock(?:ed|ing)?|block(?:ed|ing)?|unauthori[zs]ed\s+access|clos(?:e|ed|ing|ure(?:\s+of)?)\s+(?:your\s+)?account|deactivat(?:e|ed|ing|ion)|restrict(?:ed|ing|ion)?)\b"
    ],
    "prize_lottery": [
        r"\b(giveaway(?:s)?|lotter(?:y|ies)|win(?:ner|ners|ning)?|claim\s+(?:your\s+)?prize|free\s+gift(?:s)?|selected\s+to\s+win)\b"
    ],
    "unusual_payment": [
        r"\b(gift\s+card(?:s)?|wire\s+transfer(?:s)?|western\s+union|bitcoin|crypto|usdt|apple\s+pay|cash\s*app)\b"
    ]
}

# Negative pattern to identify legitimate 2FA warning disclaimers (e.g. "Do not share with anyone")
OTP_DISCLAIMER_PATTERN = re.compile(
    r"\b(?:do\s*n['o]?t|never|should\s+not|not\s+to)\s+(?:share|disclose|give|reveal|tell|forward)\b",
    re.IGNORECASE
)

def _analyze_text_internal(text: str) -> dict:
    """Analyze message text for social engineering / phishing keywords."""
    if not text or not text.strip():
        return {}
    
    text_lower = text.lower()
    has_otp_disclaimer = bool(OTP_DISCLAIMER_PATTERN.search(text_lower))
    triggered = []
    flags = []
    evidence_dicts = []
    score = 0.0
    
    for category, patterns in CATEGORIES.items():
        category_matches = []
        for pattern in patterns:
            raw_matches = re.findall(pattern, text_lower)
            if not raw_matches:
                continue
            
            for match in raw_matches:
                match_str = match if isinstance(match, str) else match[0]
                # If message contains an explicit OTP disclaimer (e.g. "do not share", "never share"),
                # suppress matches that are parts of the safety warning (e.g. "share your otp")
                if category == "credential_request" and has_otp_disclaimer:
                    if any(otp_kw in match_str for otp_kw in ["otp", "one-time", "one time"]):
                        if any(neg_verb in match_str for neg_verb in ["share", "disclose", "give", "tell", "forward"]):
                            continue
                category_matches.append(match_str)
                
        if category_matches:
            flags.append(f"nlp_{category}")
            triggered.extend(category_matches)
            score += 0.35 # Increase score per category hit
            
            unique_matches = sorted(list(set(category_matches)))
            evidence_dicts.append({
                "key": category,
                "value": unique_matches,
                "description": f"{category.replace('_', '-')} language was detected."
            })
                
    if not flags:
        return {}
        
    return {
        "score": min(score, 1.0),
        "flags": list(set(flags)),
        "evidence": evidence_dicts,
        "triggered_phrases": list(set(triggered))
    }

class NLPEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "nlp_engine"

    async def analyze(self, input_data: ScanInput) -> EngineResult:
        text = input_data.text
        if not text:
            return EngineResult.skipped(self.name, "No text provided")
            
        nlp_res = _analyze_text_internal(text)
        if not nlp_res:
            return self._build_result(risk_score=0.0, confidence=0.65, flags=[])
            
        evidence_items = [
            EvidenceItem(
                key=e["key"],
                value=e["value"],
                description=e["description"]
            )
            for e in nlp_res.get("evidence", [])
        ]
            
        return self._build_result(
            risk_score=nlp_res.get("score", 0.0) * 100.0,
            confidence=0.65,
            flags=nlp_res.get("flags", []),
            evidence=evidence_items,
            status=EngineStatus.SUCCESS,
            metadata={"triggered_phrases": nlp_res.get("triggered_phrases", [])}
        )

# Register engine
engine_registry.register(NLPEngine())
