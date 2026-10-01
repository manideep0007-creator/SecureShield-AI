import asyncio
from app.models.scan_input import ScanInput
from app.engines.pipeline import UnifiedScanPipeline
from app.models.scan_response import UnifiedScanResponse

async def main():
    pipeline = UnifiedScanPipeline()
    results = await pipeline.run(ScanInput(text='hello world'))
    resp = UnifiedScanResponse.from_results(results)
    print(resp.risk_assessment)

asyncio.run(main())
