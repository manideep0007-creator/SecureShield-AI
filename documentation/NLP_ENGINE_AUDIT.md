# NLP Engine Audit (Phase 3)

## 1. Current NLP / Social Engineering Detection Categories
The NLP engine currently implements the following 5 categories:
- **urgency**
- **credential_request**
- **account_suspension**
- **prize_lottery**
- **unusual_payment**

## 2. Rules, Keywords, Regex, and Patterns
The engine uses regex extraction with the following patterns (case-insensitive):
- **urgency**: `\b(act now|urgent|immediately|asap|time is running out|24 hours)\b`
- **credential_request**: `\b(password|login|verify your account|ssn|social security|one time code|otp)\b`
- **account_suspension**: `\b(suspend|locked|blocked|unauthorized access|closing your account)\b`
- **prize_lottery**: `\b(giveaway|lottery|winner|claim your prize|free gift|selected to win)\b`
- **unusual_payment**: `\b(gift card|wire transfer|western union|bitcoin|crypto|usdt|apple pay|cashapp)\b`

## 3. Risk Score Calculation
- For each category matched, the internal score is increased by `0.35` per *category* hit.
- The internal score is capped at a maximum of `1.0`: `min(score, 1.0)`.
- The final returned `risk_score` transforms this to a standard integer/float scale by multiplying the internal score by `100.0` (max `100.0`).
- The self-reported `confidence` score is hardcoded to `0.65`.

## 4. Current Flags Generated
The engine dynamically generates a flag for each triggered category by prepending `nlp_`:
- `nlp_urgency`
- `nlp_credential_request`
- `nlp_account_suspension`
- `nlp_prize_lottery`
- `nlp_unusual_payment`

## 5. Current Evidence Generated
Currently, **no explicit `EvidenceItem` objects are generated**. The `evidence` field on the `EngineResult` is returned as an empty list (`[]`). Note: matched phrases are included in the `metadata` dictionary, but not as structured evidence.

## 6. EngineResult Structure
The NLP engine returns a standard `EngineResult` object conforming to the architecture:
- `engine_name`: `"nlp_engine"`
- `risk_score`: Float between `0.0` and `100.0`
- `confidence`: `0.65`
- `flags`: List of strings (e.g., `["nlp_urgency", "nlp_credential_request"]`)
- `evidence`: `[]` (empty list)
- `status`: `EngineStatus.SUCCESS` (or `EngineStatus.SKIPPED`)
- `metadata`: A standard dictionary containing `"triggered_phrases"`, which is a list of unique matched keywords.

## 7. Existing NLP Tests and Coverage
The engine is currently covered by 4 specific tests:
- `backend/app/tests/test_engines.py`:
  - `test_nlp_engine_analysis`: Tests scoring and generation of flags (e.g., `nlp_urgency`).
  - `test_nlp_engine_skipped`: Tests skipped status when the input text is missing.
- `backend/app/tests/test_unified_pipeline.py`:
  - `test_text_scan`: Checks that submitting text successfully triggers the NLP engine (asserts status is `success`, `risk_score` > 0, and `nlp_urgency` flag counts).
- `backend/app/tests/test_api_scan.py`:
  - `test_valid_text_scan`: Tests the API router endpoint to confirm the NLP engine executes successfully and flags `nlp_urgency` and `nlp_credential_request`.

All existing unittests pass successfully with no errors or changes required.

## 8. Missing Capabilities 
The architectural specification defines a requirement for **8 social-engineering manipulation categories** (`documentation/ARCHITECTURE_V2.md`). 
Currently, only **5** are implemented. 
This leaves **3 missing categories** required for compliance. Furthermore, the engine is missing proper `evidence` field population (it relies on `metadata` passing unstructured tokens instead of yielding proper `EvidenceItem` records).