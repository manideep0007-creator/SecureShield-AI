import unittest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from app.engines.registry import EngineRegistry
from app.engines.base_engine import BaseEngine
from app.models.engine_result import EngineResult, EngineStatus
from app.models.scan_input import ScanInput

class SlowEngine(BaseEngine):
    @property
    def name(self): return "slow_engine"
    async def analyze(self, input_data):
        await asyncio.sleep(5.0)  # Intentionally slow, but we'll test timeout manipulation
        return self._build_result(risk_score=10.0)

class CrashingEngine(BaseEngine):
    @property
    def name(self): return "crashing_engine"
    async def analyze(self, input_data):
        raise ValueError("Simulated crash")

class FastEngine(BaseEngine):
    @property
    def name(self): return "fast_engine"
    async def analyze(self, input_data):
        return self._build_result(risk_score=50.0, status=EngineStatus.SUCCESS)

class TestEngineRegistryParallel(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.registry = EngineRegistry()
        self.registry.register(FastEngine())
        self.registry.register(CrashingEngine())
        self.registry.register(SlowEngine())
        
    async def test_run_all_parallel_and_isolation(self):
        # We temporarily mock the timeout so we don't literally wait 30 seconds for SlowEngine
        # or we can mock SlowEngine.analyze to run just past a short timeout
        import app.engines.registry as reg_module
        
        input_data = ScanInput(text="test")
        
        # Override the timeout manually via mocking wait_for 
        # But wait, run_all hardcodes 30.0. Let's patch it.
        original_wait_for = asyncio.wait_for
        async def fast_wait_for(aw, timeout):
            return await original_wait_for(aw, timeout=0.1)
            
        with unittest.mock.patch('asyncio.wait_for', new=fast_wait_for):
            results = await self.registry.run_all(input_data)
            
        # FastEngine should succeed
        fast_res = next(r for r in results if r.engine_name == "fast_engine")
        self.assertEqual(fast_res.status, EngineStatus.SUCCESS)
        
        # CrashingEngine should surface as ERROR
        crash_res = next(r for r in results if r.engine_name == "crashing_engine")
        self.assertEqual(crash_res.status, EngineStatus.ERROR)
        self.assertIn("Simulated crash", crash_res.error_message)
        
        # SlowEngine should timeout and return ERROR
        slow_res = next(r for r in results if r.engine_name == "slow_engine")
        self.assertEqual(slow_res.status, EngineStatus.ERROR)
        self.assertIn("timed out", slow_res.error_message)
        
        # Deterministic sorting: c, f, s 
        self.assertEqual(results[0].engine_name, "crashing_engine")
        self.assertEqual(results[1].engine_name, "fast_engine")
        self.assertEqual(results[2].engine_name, "slow_engine")
        
    async def test_run_all_exclude(self):
        input_data = ScanInput(text="exclude_test")
        results = await self.registry.run_all(input_data, exclude=["crashing_engine", "slow_engine"])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].engine_name, "fast_engine")

if __name__ == '__main__':
    unittest.main()
