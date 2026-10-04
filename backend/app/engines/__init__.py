# V2 Detection Engines
# Upgraded and new analysis engines (URL, malware, NLP, sender, etc.).
# V1 engines remain at backend/engines/ (unchanged).

from app.engines.base_engine import BaseEngine
from app.engines.registry import EngineRegistry, engine_registry
from app.engines.attachment_behavior_engine import AttachmentBehaviorEngine

__all__ = ["BaseEngine", "EngineRegistry", "engine_registry", "AttachmentBehaviorEngine"]

