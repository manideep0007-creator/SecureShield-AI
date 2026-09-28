import re
from app.engines.base_engine import BaseEngine
from app.engines.registry import engine_registry
from app.models.engine_result import EngineResult, EngineStatus

CATEGORIES = {
    "urgency": [r"\b(act now|urgent|immediately|asap|time is running out|24 hours)\b"],
    "credential_request": [r"\b(password|login|verify your account|ssn|social security|one time code|otp)\b"],
    "account_suspension": [r"\b(suspend|locked|blocked|unauthorized access|closing your account)\b"],
    "prize_lottery": [r"\b(giveaway|lottery|winner|claim your prize|free gift|selected to win)\b"],
    "unusual_payment": [r"\b(gift card|wire transfer|western union|bitcoin|crypto|usdt|apple pay|cashapp)\b"]
}

def _analyze_text_internal(text: str) -> dict:
    """Analyze message text for social engineering / phishing keywords."""
    if not text or not text.strip():
        return {}
    
    text_lower = text.lower()
    triggered = []
    flags = []
    score = 0.0
    
    for category, patterns in CATEGORIES.items():
        for pattern in patterns:
            matches = re.findall(pattern, text_lower)
            if matches:
                flags.append(f"nlp_{category}")
                triggered.extend(matches)
                score += 0.35 # Increase score per category hit
                
    if not flags:
        return {}
        
    return {
        "score": min(score, 1.0),
        "flags": list(set(flags)),
        "triggered_phrases": list(set(triggered))
    }

class NLPEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "nlp_engine"

    async def analyze(self, input_data: dict) -> EngineResult:
        text = input_data.get("text")
        if not text:
            return EngineResult.skipped(self.name, "No text provided")
            
        nlp_res = _analyze_text_internal(text)
        if not nlp_res:
            return self._build_result(risk_score=0.0, confidence=0.65, flags=[])
            
        return self._build_result(
            risk_score=nlp_res.get("score", 0.0) * 100.0,
            confidence=0.65,
            flags=nlp_res.get("flags", []),
            evidence=[],
            status=EngineStatus.SUCCESS,
            metadata={"triggered_phrases": nlp_res.get("triggered_phrases", [])}
        )

# Register engine
engine_registry.register(NLPEngine())

# Legacy function for V1 pipeline
def analyze_text(text: str) -> dict:
    # Notice this is synchronous in V1
    import asyncio
    engine = NLPEngine()
    # But wait, python's async def analyze can't be called directly synchronously.
    # To not change behavior, we'll just bypass and use the internal one for V1.
    res = _analyze_text_internal(text)
    if res:
        res["type"] = "nlp"
    return res
