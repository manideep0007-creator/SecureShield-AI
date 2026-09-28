import uuid
from pydantic import BaseModel, Field
from app.models.engine_result import EngineResult, EngineStatus

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
    
    @classmethod
    def from_results(cls, results: list[EngineResult]) -> "UnifiedScanResponse":
        total = len(results)
        skipped = sum(1 for r in results if r.status == EngineStatus.SKIPPED)
        completed = total - skipped
        
        return cls(
            scan_id=str(uuid.uuid4()),
            status="completed",
            results=results,
            total_engines=total,
            completed_engines=completed,
            skipped_engines=skipped
        )