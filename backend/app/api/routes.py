from fastapi import APIRouter, File, UploadFile, Body, HTTPException, Form
from pydantic import BaseModel, HttpUrl
from typing import Optional
from app.preprocessing.data_prep import resolve_url, check_file_type
from app.engines.url_engine import analyze_url
from app.engines.malware_engine import analyze_file
from app.engines.nlp_engine import analyze_text
from app.engines.sender_engine import analyze_sender
from app.fusion.fusion import generate_fusion_score
from app.database.feedback import save_feedback
from app.models.scan_input import ScanInput
from app.models.engine_result import EngineResult
from app.models.scan_response import UnifiedScanResponse
from app.models.feedback import EvaluationMetrics, FeedbackRequest, FeedbackSubmissionResponse
from app.evaluation.feedback_metrics import get_feedback_metrics
from app.engines.pipeline import UnifiedScanPipeline
import sqlite3

router = APIRouter()
unified_pipeline = UnifiedScanPipeline()

class MessageScanRequest(BaseModel):
    message_text: Optional[str] = None
    url: Optional[HttpUrl] = None
    sender_id: Optional[str] = None

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

@router.post("/analyze/message")
async def api_analyze_message(payload: MessageScanRequest):
    if not payload.message_text and not payload.url:
        raise HTTPException(status_code=400, detail="Must provide either message_text or url")

    results = []
    has_link = bool(payload.url)
    
    # 1. NLP Engine
    if payload.message_text:
        nlp_res = analyze_text(payload.message_text)
        if nlp_res:
            results.append(nlp_res)
            
    # 2. URL Engine
    if payload.url:
        final_url = await resolve_url(str(payload.url))
        url_res = await analyze_url(final_url)
        results.append(url_res)
        
    # 3. Sender Engine
    if payload.sender_id:
        sender_res = analyze_sender(payload.sender_id, has_link=has_link, has_file=False)
        if sender_res:
            results.append(sender_res)
            
    # 4. Fusion Engine
    fusion = generate_fusion_score(results)
    
    if payload.url:
        fusion["analyzed_target"] = final_url
    elif payload.message_text:
        fusion["analyzed_target"] = payload.message_text[:50]
    
    # Bubble up details
    fusion["details"] = {res["type"]: res.get("details", {}) for res in results}
    
    # Bubble up errors if any engine failed
    errors = [res.get("error") for res in results if "error" in res]
    if errors:
        fusion["errors"] = errors
        
    return fusion

@router.post("/analyze/file")
async def api_analyze_file(file: UploadFile = File(...), sender_id: Optional[str] = Form(None)):
    MAX_FILE_SIZE = 10 * 1024 * 1024 # 10 MB limit
    
    # 1. Read file bytes
    file_bytes = await file.read()
    
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="File is empty")
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds maximum allowed size of 10MB")
    
    results = []
    
    # Preprocess: File magic bytes check
    file_type_check = check_file_type(file_bytes, file.filename)
    
    # Malware Engine
    file_result = await analyze_file(file_bytes)
    if file_type_check["extension_mismatch"]:
        file_result.setdefault("flags", []).append("extension_mismatch")
        file_result["score"] = min(file_result.get("score", 0) + 0.3, 1.0)
    
    results.append(file_result)
    
    # Sender Engine
    if sender_id:
        sender_res = analyze_sender(sender_id, has_link=False, has_file=True)
        if sender_res:
            results.append(sender_res)
            
    # Fusion
    fusion = generate_fusion_score(results)
    fusion["analyzed_target"] = file.filename
    fusion["details"] = {res["type"]: res.get("details", {}) for res in results if "type" in res}
    
    errors = [res.get("error") for res in results if "error" in res]
    if errors:
        fusion["errors"] = errors
    
    return fusion

@router.post("/scan", response_model=UnifiedScanResponse)
async def api_scan(payload: ScanInput):
    """V2 Unified Scan Endpoint: Parses ScanInput and returns all EngineResults."""
    try:
        results = await unified_pipeline.run(payload)
        return UnifiedScanResponse.from_results(results)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scanning error: {str(e)}")
