# NLP Scoring Audit (Phase 3)

## Findings

### A. Range required by the architecture
According to `documentation/ARCHITECTURE_V2.md` (Section 3.1), the architecture specifies:
- `risk_score`: `float` from 0.0 to 1.0
- `confidence`: `float` from 0.0 to 1.0

### B. Range the NLP engine currently returns
The NLP engine computes an internal score from 0.0 to 1.0, but when mapping to the V2 `EngineResult` object, it explicitly multiplies that internal score by `100.0`. Therefore, it currently returns a `risk_score` spanning **0.0 to 100.0**. The `confidence` remains compliant, hardcoded to `0.65`.

### C. Range other engines return
All other engines (URL, Malware, and Sender) follow the identical behavior pattern as the NLP engine. They multiply their internally computed bounds by `100.0` before pushing them to the V2 `EngineResult`'s `risk_score` field. Therefore, all engines yield a **0.0 to 100.0** score.

### D. Impact of changing NLP risk_score to 0.0–1.0
Changing the NLP engine to emit a rigid `0.0-1.0` `risk_score` would actively break the ecosystem:
1. **Model Validation Constraints:** It would become fundamentally inconsistent with the other engines which routinely supply `100.0`. If bounds were universally tightened, it would require rewriting every engine.
2. **Logic Skew:** Under a 0-100 system, returning `1.0` maximum would represent a negligible 1% threat relative to other engines.
3. **Legacy API Breakdown:** V1 wrappers interface with V2 structures by dividing the `EngineResult`'s `risk_score` by `100.0` to restore logic to a `0-1` range. Outputting `1.0` initially would cause the legacy wrapper to yield `0.01` (1%), crippling V1 risk fusion scoring.

### E. Range Risk Fusion currently expects
- **V1 Risk Fusion** expects its inputs (internal dictionary components) to map to a **0.0 to 1.0** scale. To facilitate this, current V1 API wrappers manually divide the `EngineResult.risk_score` by `100.0` before it touches `fusion.py`.
- **V2 unified mechanics (`EngineResult`)** explicitly mandate a **0.0 to 100.0** scale via Pydantic model constraints in `app/models/engine_result.py`: 
  `risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Threat score 0–100")`.

### F. Recommended Architecture-Compliant Solution
The inconsistency stems from an oversight/typo in the static `.md` documentation, not an architectural code bug. The ultimate source-of-truth—the foundational V2 Pydantic definitions and universal engine behaviors—have effectively standardized on a `0.0-100.0` float logic.

**Recommendation and Action:** Do not modify the Python codebase. We amended `documentation/ARCHITECTURE_V2.md` so that the `risk_score` parameter reflects a `float` bounded between `0.0–100.0`, realigning it with the true V2 schemas.

### Confirmation of Reconciliation
- **Original documented range:** `risk_score` 0.0–1.0
- **Actual implementation range:** `risk_score` 0.0–100.0
- **Affected sections updated:** Section 3.1 "V2 Engine Interface" in `ARCHITECTURE_V2.md`.
- **Final agreed convention:** 
  - `risk_score`: 0.0–100.0
  - `confidence`: 0.0–1.0
- **Source code impact:** No source code was modified. The test suite results confirm standard operation behavior remains identical.