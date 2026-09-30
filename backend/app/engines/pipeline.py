from app.models.scan_input import ScanInput
from app.models.engine_result import EngineResult
from app.engines.registry import engine_registry
from app.preprocessing.data_prep import resolve_url, check_file_type

class UnifiedScanPipeline:
    """
    V2 Unified Scan Pipeline
    Coordinates preprocessing, engine selection, sequential execution, and result collection.
    """
    
    def __init__(self, registry=engine_registry):
        self.registry = registry

    async def run(self, input_data: ScanInput) -> list[EngineResult]:
        # 1. Validate input
        # Ensure at least one scannable field is present
        if not any([input_data.text, input_data.url, input_data.file_bytes, input_data.image_bytes, input_data.sender_id]):
            raise ValueError("ScanInput must contain at least one piece of scannable data.")

        results = []

        # 2. Extract Visual Context (QR/OCR)
        import app.engines.visual_engine # Ensure it's imported
        from app.engines.registry import engine_registry
        vis_engine = engine_registry.get("visual_engine")
        
        if vis_engine:
            vis_res = await vis_engine.safe_analyze(input_data)
            results.append(vis_res)
            
            # Feed extracted text/urls downstream in sequence before parallel branch
            if vis_res.status == "success":
                ext_text = vis_res.metadata.get("extracted_text")
                ext_url = vis_res.metadata.get("extracted_url")
                
                if ext_text and not input_data.text:
                    input_data.text = ext_text
                if ext_url and not input_data.url:
                    input_data.url = ext_url

        # 3. Preprocess available data
        if input_data.url:
            input_data.url = await resolve_url(input_data.url)
            
        extension_mismatch = False
        if input_data.file_bytes and input_data.file_name:
            type_check = check_file_type(input_data.file_bytes, input_data.file_name)
            extension_mismatch = type_check.get("extension_mismatch", False)

        # 4. Determine applicable detection engines & 5. Run concurrently
        # Engines receiving irrelevant data return a 'skipped' EngineResult seamlessly.
        # visual_engine is excluded from the parallel execution to prevent duplicate runs.
        registry_results = await self.registry.run_all(input_data, exclude=["visual_engine"])
        
        # Post-process results based on global preprocessing flags (which handles parallelized results)
        if extension_mismatch:
            for res in registry_results:
                if res.engine_name == "malware_engine" and res.status != "skipped":
                    if "extension_mismatch" not in res.flags:
                        res.flags.append("extension_mismatch")
                        # Boost the threat score for mismatched file extensions just like V1
                        res.risk_score = min(res.risk_score + 30.0, 100.0)

        # 6. Collect & Return all engine results
        results.extend(registry_results)
                
        return results
