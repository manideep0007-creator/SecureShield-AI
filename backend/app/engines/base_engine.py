"""
V2 Base Engine — Abstract interface that all detection engines must implement.

This defines the contract every V2 engine follows. The pipeline calls `analyze()`
and receives a standardized EngineResult regardless of which engine produced it.

V1 engines (backend/engines/) are NOT modified. This interface applies to V2 only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.models.engine_result import EngineResult, EngineStatus


class BaseEngine(ABC):
    """
    Abstract base class for all V2 detection engines.

    Subclasses must implement:
        - `name`     (property)  → unique engine identifier string
        - `analyze`  (method)    → run detection and return an EngineResult

    The base class provides:
        - `safe_analyze` → wraps `analyze` in error handling so one engine
                           can never crash the entire pipeline
        - `_build_result` → convenience helper to construct an EngineResult
                            with the engine name pre-filled
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique engine identifier (e.g. 'url_engine', 'malware_engine')."""
        ...

    @abstractmethod
    async def analyze(self, input_data: dict[str, Any]) -> EngineResult:
        """
        Run the detection analysis.

        Parameters
        ----------
        input_data : dict
            Flexible input payload. Each engine decides which keys it needs:
            - URL engine expects:    {"url": str}
            - Malware engine expects: {"file_bytes": bytes, "filename": str}
            - NLP engine expects:    {"text": str}
            - Sender engine expects: {"sender_id": str, "has_link": bool, "has_file": bool}

        Returns
        -------
        EngineResult
            Standardized result with risk_score, confidence, flags, evidence, and status.
        """
        ...

    async def safe_analyze(self, input_data: dict[str, Any]) -> EngineResult:
        """
        Fault-tolerant wrapper around `analyze`.

        Catches any unhandled exception and returns an ERROR result instead of
        propagating the crash. This ensures one broken engine never takes down
        the entire pipeline.
        """
        try:
            return await self.analyze(input_data)
        except Exception as exc:
            return EngineResult.error(
                engine_name=self.name,
                message=f"Unhandled exception: {type(exc).__name__}: {exc}",
            )

    def _build_result(self, **kwargs) -> EngineResult:
        """Convenience: create an EngineResult with engine_name pre-filled."""
        return EngineResult(engine_name=self.name, **kwargs)
