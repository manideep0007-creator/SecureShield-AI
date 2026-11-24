import logging
from fastapi import APIRouter, HTTPException, Request
import sqlite3

from app.database.feedback import save_feedback
from app.evaluation.feedback_metrics import get_feedback_metrics
from app.engines.pipeline import UnifiedScanPipeline
from app.models.feedback import EvaluationMetrics, FeedbackRequest, FeedbackSubmissionResponse
from app.models.scan_input import ScanInput
from app.models.scan_response import UnifiedScanResponse

from app.config.config import settings

logger = logging.getLogger(__name__)
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


@router.get("/threat-intelligence/status")
def api_threat_intelligence_status():
    """Returns real-world threat intelligence feed counts and synchronization timestamps."""
    from app.intelligence.threat_feeds import threat_store
    return threat_store.get_statistics()


@router.post("/threat-intelligence/sync")
async def api_threat_intelligence_sync():
    """Trigger an on-demand live community feed sync (URLhaus, MalwareBazaar, OpenPhish)."""
    from app.intelligence.threat_feeds import threat_store
    result = await threat_store.sync_live_feeds()
    return result


@router.post("/scan", response_model=UnifiedScanResponse)
async def api_scan(payload: ScanInput, request: Request):
    """V2 Unified Scan Endpoint: Parses ScanInput and returns all EngineResults."""
    try:
        # Enforce user authorization and data isolation:
        # Never trust a client-supplied user_id or tenant ID without session ownership verification.
        authenticated_user = getattr(request.state, "user", None)
        if authenticated_user:
            user_id = authenticated_user["user_id"]
            if isinstance(payload.metadata, dict):
                # Bind scan strictly to authenticated session identity
                payload.metadata["user_id"] = user_id
                payload.metadata["authenticated"] = True
        else:
            # If request is authenticated only via system API key without a user session,
            # strictly sanitize and remove any client-supplied user_id to prevent identity spoofing
            if isinstance(payload.metadata, dict):
                payload.metadata.pop("user_id", None)
                payload.metadata["authenticated"] = False

        results = await unified_pipeline.run(payload)
        profile = (
            payload.classification_profile
            or (payload.metadata.get("classification_profile") if isinstance(payload.metadata, dict) else None)
            or (payload.metadata.get("profile") if isinstance(payload.metadata, dict) else None)
        )
        scan_response = UnifiedScanResponse.from_results(results, profile=profile)

        # Store scan record in user's isolated database if authenticated
        if authenticated_user:
            try:
                from app.database.auth_db import save_user_scan
                target = payload.url or payload.file_name or (payload.text[:100] if payload.text else "unknown")
                scan_type = "url" if payload.url else ("file" if payload.file_bytes else "message")
                save_user_scan(
                    user_id=authenticated_user["user_id"],
                    scan_id=scan_response.scan_id,
                    scan_type=scan_type,
                    target=target,
                    threat_level=scan_response.classification,
                    threat_score=scan_response.risk_score,
                    details_json=scan_response.model_dump_json() if hasattr(scan_response, "model_dump_json") else "{}"
                )
            except Exception as storage_exc:
                logger.warning("Could not persist scan to user-isolated database: %s", storage_exc)

        return scan_response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scanning error: {str(e)}")
