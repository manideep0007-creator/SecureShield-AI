"""
V2 Engine Registry — Central catalog of all registered detection engines.

The registry lets the pipeline discover and invoke engines dynamically
without hardcoding imports. Engines register themselves at startup;
the fusion layer iterates the registry to run all active engines.

Usage
-----
    from app.engines.registry import engine_registry

    # Register an engine (typically done inside each engine module)
    engine_registry.register(MyURLEngine())

    # Pipeline runs all registered engines
    results = await engine_registry.run_all(input_data)
"""

from __future__ import annotations

from typing import Any

from app.engines.base_engine import BaseEngine
from app.models.engine_result import EngineResult
from app.models.scan_input import ScanInput


class EngineRegistry:
    """Thread-safe registry of detection engine instances."""

    def __init__(self) -> None:
        self._engines: dict[str, BaseEngine] = {}

    def register(self, engine: BaseEngine) -> None:
        """Add an engine to the registry. Raises on duplicate names."""
        if engine.name in self._engines:
            raise ValueError(f"Engine '{engine.name}' is already registered")
        self._engines[engine.name] = engine

    def unregister(self, engine_name: str) -> None:
        """Remove an engine by name. No-op if not found."""
        self._engines.pop(engine_name, None)

    def get(self, engine_name: str) -> BaseEngine | None:
        """Retrieve a single engine by name."""
        return self._engines.get(engine_name)

    @property
    def engine_names(self) -> list[str]:
        """List all registered engine names."""
        return list(self._engines.keys())

    @property
    def engines(self) -> list[BaseEngine]:
        """List all registered engine instances."""
        return list(self._engines.values())

    async def run_all(self, input_data: ScanInput, exclude: list[str] | None = None) -> list[EngineResult]:
        """
        Execute registered engines concurrently against the input and collect results
        in parallel.

        Each engine runs through `safe_analyze` so failures are isolated. A timeout
        further prevents a hanging engine from blocking the entire pipeline.
        """
        import asyncio
        if exclude is None:
            exclude = []
            
        async def run_with_timeout(engine: BaseEngine) -> EngineResult:
            try:
                # 30-second bounded execution safety limit per engine
                return await asyncio.wait_for(engine.safe_analyze(input_data), timeout=30.0)
            except asyncio.TimeoutError:
                return EngineResult.error(engine.name, "Engine timed out after 30 seconds")
            except Exception as e:
                return EngineResult.error(engine.name, f"Unexpected fatal error: {str(e)}")

        tasks = [
            run_with_timeout(engine)
            for name, engine in self._engines.items()
            if name not in exclude
        ]
        
        if not tasks:
            return []
            
        results = await asyncio.gather(*tasks)
        
        # Ensure deterministic result aggregation regardless of asynchronous return order
        return sorted(list(results), key=lambda x: x.engine_name)

    def __len__(self) -> int:
        return len(self._engines)

    def __repr__(self) -> str:
        names = ", ".join(self._engines.keys()) or "(empty)"
        return f"EngineRegistry([{names}])"


# Global singleton — import this to register or query engines
engine_registry = EngineRegistry()
