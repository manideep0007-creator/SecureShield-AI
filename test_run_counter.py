import asyncio
from app.models.scan_input import ScanInput
from app.engines.pipeline import UnifiedScanPipeline

async def test_run():
    pipeline = UnifiedScanPipeline()
    res = await pipeline.run(ScanInput(text="test"))
    vis_count = sum(1 for r in res if r.engine_name == 'visual_engine')
    print('VisualEngine count in results:', vis_count)

asyncio.run(test_run())
