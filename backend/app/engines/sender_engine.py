import sqlite3
import os
from app.engines.base_engine import BaseEngine
from app.engines.registry import engine_registry
from app.models.engine_result import EngineResult, EngineStatus
from app.models.scan_input import ScanInput

# Create data directory if it doesn't exist
DB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "sender_behavior.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS senders (
                        sender_id TEXT PRIMARY KEY,
                        message_count INTEGER DEFAULT 0,
                        link_count INTEGER DEFAULT 0,
                        file_count INTEGER DEFAULT 0
                      )''')
init_db()

def _analyze_sender_internal(sender_id: str, has_link: bool = False, has_file: bool = False) -> dict:
    """Track sender behavior and flag out-of-character messages."""
    if not sender_id:
        return {}
        
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT message_count, link_count, file_count FROM senders WHERE sender_id=?", (sender_id,))
        row = cursor.fetchone()
        
        flags = []
        score = 0.0
        
        if row is None:
            # They have never messaged us before
            flags.append("first_time_sender")
            score = 0.4
            
            # Record their first interaction
            cursor.execute("INSERT INTO senders (sender_id, message_count, link_count, file_count) VALUES (?, 1, ?, ?)",
                           (sender_id, 1 if has_link else 0, 1 if has_file else 0))
        else:
            msg_count, link_count, file_count = row
            
            # Flag if this is a known sender but they've NEVER sent a link before
            if has_link and link_count == 0:
                flags.append("out_of_character_link")
                score += 0.6
            
            # Flag if they've NEVER sent a file before
            if has_file and file_count == 0:
                flags.append("out_of_character_file")
                score += 0.6
                
            score = min(score, 1.0)
                
            # Update their stats moving forward
            new_links = link_count + (1 if has_link else 0)
            new_files = file_count + (1 if has_file else 0)
            cursor.execute("UPDATE senders SET message_count=message_count+1, link_count=?, file_count=? WHERE sender_id=?",
                           (new_links, new_files, sender_id))
        
        conn.commit()
        
    return {
        "score": score,
        "flags": flags,
        "details": {"previous_history_found": bool(row)}
    }

class SenderEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "sender_engine"

    async def analyze(self, input_data: ScanInput) -> EngineResult:
        sender_id = input_data.sender_id
        if not sender_id:
            return EngineResult.skipped(self.name, "No sender_id provided")
            
        has_link = bool(input_data.url)
        has_file = bool(input_data.file_bytes) or bool(input_data.file_name)
        
        # Run synchronously as it was in V1
        res = _analyze_sender_internal(sender_id, has_link, has_file)
        
        return self._build_result(
            risk_score=res.get("score", 0.0) * 100.0,
            confidence=0.5,
            flags=res.get("flags", []),
            evidence=[],
            status=EngineStatus.SUCCESS,
            metadata=res.get("details", {})
        )

# Register engine
engine_registry.register(SenderEngine())

# Legacy function for V1 pipeline
def analyze_sender(sender_id: str, has_link: bool = False, has_file: bool = False) -> dict:
    res = _analyze_sender_internal(sender_id, has_link, has_file)
    if res:
        res["type"] = "sender"
    return res
