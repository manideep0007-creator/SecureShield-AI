import uuid
from pydantic import BaseModel, Field
from app.models.engine_result import EngineResult, EngineStatus
from app.models.risk_assessment import RiskAssessment, RiskClassification

class UnifiedScanResponse(BaseModel):
    """
    Standardized response wrapper containing metadata for a unified scan request.
    """
    scan_id: str = Field(..., description="Unique identifier for the scan transaction")
    status: str = Field(..., description="Overall pipeline execution status (e.g., 'completed')")
    results: list[EngineResult] = Field(..., description="List of individual detection engine outputs")
    total_engines: int = Field(..., description="Total number of active engines inside the registry")
    completed_engines: int = Field(..., description="Number of engines that executed safely (excluding skipped)")
    skipped_engines: int = Field(..., description="Number of engines that skipped execution based on input bounds")
    risk_assessment: RiskAssessment = Field(..., description="Unified confidence-weighted risk assessment")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Unified final risk score")
    classification: RiskClassification = Field(..., description="Unified final risk classification")
    
    @classmethod
    def from_results(cls, results: list[EngineResult]) -> "UnifiedScanResponse":
        from app.fusion.risk_fusion import fuse_engine_results

        total = len(results)
        skipped = sum(1 for r in results if r.status == EngineStatus.SKIPPED)
        completed = total - skipped
        
        assessment = fuse_engine_results(results)
        
        from app.explainability.explainability_engine import ExplainabilityEngine
        assessment = ExplainabilityEngine.explain(assessment)

        return cls(
            scan_id=str(uuid.uuid4()),
            status="completed",
            results=results,
            total_engines=total,
            completed_engines=completed,
            skipped_engines=skipped,
            risk_assessment=assessment,
            risk_score=assessment.risk_score,
            classification=assessment.classification,
        )