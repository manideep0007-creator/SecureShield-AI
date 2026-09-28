# V2 Detection Engines
# Upgraded and new analysis engines (URL, malware, NLP, sender, etc.).
# V1 engines remain at backend/engines/ (unchanged).

from app.engines.base_engine import BaseEngine
from app.engines.registry import EngineRegistry, engine_registry

__all__ = ["BaseEngine", "EngineRegistry", "engine_registry"]
