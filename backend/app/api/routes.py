from fastapi import APIRouter, HTTPException
import sqlite3

from app.database.feedback import save_feedback
from app.evaluation.feedback_metrics import get_feedback_metrics
from app.engines.pipeline import UnifiedScanPipeline
from app.models.feedback import EvaluationMetrics, FeedbackRequest, FeedbackSubmissionResponse
from app.models.scan_input import ScanInput
from app.models.scan_response import UnifiedScanResponse

from app.config.config import settings

router = APIRouter()
unified_pipeline = UnifiedScanPipeline()


@router.get("/health")
def api_health():
    """Lightweight availability health check endpoint."""
    return {"status": "running", "project": settings.PROJECT_NAME}


@router.post("/feedback", response_model=FeedbackSubmissionResponse)
def api_feedback(payload: FeedbackRequest):
    try:
        inserted, timestamp = save_feedback(payload)
    except (sqlite3.Error, OSError) as error:
        raise HTTPException(
            status_code=503,
            detail={"code": "feedback_storage_unavailable", "message": "Feedback could not be stored."},
        ) from error
    if not inserted:
        raise HTTPException(
            status_code=409,
            detail={"code": "duplicate_feedback", "message": "Feedback has already been recorded for this scan."},
        )
    return FeedbackSubmissionResponse(status="success", scan_id=payload.scan_id, timestamp=timestamp)


@router.get("/evaluation/metrics", response_model=EvaluationMetrics)
def api_evaluation_metrics():
    try:
        return get_feedback_metrics()
    except (sqlite3.Error, OSError) as error:
        raise HTTPException(
            status_code=503,
            detail={"code": "feedback_storage_unavailable", "message": "Evaluation metrics are unavailable."},
        ) from error


@router.post("/scan", response_model=UnifiedScanResponse)
async def api_scan(payload: ScanInput):
    """V2 Unified Scan Endpoint: Parses ScanInput and returns all EngineResults."""
    try:
        results = await unified_pipeline.run(payload)
        profile = (
            payload.classification_profile
            or (payload.metadata.get("classification_profile") if isinstance(payload.metadata, dict) else None)
            or (payload.metadata.get("profile") if isinstance(payload.metadata, dict) else None)
        )
        return UnifiedScanResponse.from_results(results, profile=profile)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scanning error: {str(e)}")
