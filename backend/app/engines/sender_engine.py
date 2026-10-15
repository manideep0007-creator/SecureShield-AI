import sqlite3
import os
import time
import json
import re
from app.engines.base_engine import BaseEngine
from app.engines.registry import engine_registry
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.scan_input import ScanInput

from app.config.config import settings

_DEFAULT_SENDER_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "sender_behavior.db"))
DB_PATH = _DEFAULT_SENDER_DB_PATH

def get_sender_db_path(custom_path: str | None = None) -> str:
    if custom_path:
        return custom_path
    if DB_PATH != _DEFAULT_SENDER_DB_PATH and DB_PATH != os.path.join(settings.resolved_data_dir, "sender_behavior.db"):
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        return DB_PATH
    data_dir = settings.resolved_data_dir
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "sender_behavior.db")

def init_db(db_path: str | None = None):
    path = get_sender_db_path(db_path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with sqlite3.connect(path, timeout=5.0) as conn:
        cursor = conn.cursor()
        
        # Check senders table and migrate to compound primary key (client_id, sender_id)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='senders'")
        senders_exists = cursor.fetchone() is not None
        if not senders_exists:
            cursor.execute('''CREATE TABLE senders (
                            client_id TEXT NOT NULL DEFAULT 'anonymous',
                            sender_id TEXT NOT NULL,
                            message_count INTEGER DEFAULT 0,
                            link_count INTEGER DEFAULT 0,
                            file_count INTEGER DEFAULT 0,
                            first_seen REAL DEFAULT 0.0,
                            last_seen REAL DEFAULT 0.0,
                            time_buckets TEXT DEFAULT '{}',
                            last_domain TEXT DEFAULT '',
                            recent_count INTEGER DEFAULT 0,
                            recent_window_start REAL DEFAULT 0.0,
                            PRIMARY KEY (client_id, sender_id)
                          )''')
        else:
            cursor.execute("PRAGMA table_info(senders)")
            columns = [col[1] for col in cursor.fetchall()]
            if "client_id" not in columns:
                cursor.execute('''CREATE TABLE senders_v2 (
                                client_id TEXT NOT NULL DEFAULT 'anonymous',
                                sender_id TEXT NOT NULL,
                                message_count INTEGER DEFAULT 0,
                                link_count INTEGER DEFAULT 0,
                                file_count INTEGER DEFAULT 0,
                                first_seen REAL DEFAULT 0.0,
                                last_seen REAL DEFAULT 0.0,
                                time_buckets TEXT DEFAULT '{}',
                                last_domain TEXT DEFAULT '',
                                recent_count INTEGER DEFAULT 0,
                                recent_window_start REAL DEFAULT 0.0,
                                PRIMARY KEY (client_id, sender_id)
                              )''')
                cursor.execute('''INSERT INTO senders_v2 (
                                client_id, sender_id, message_count, link_count, file_count,
                                first_seen, last_seen, time_buckets, last_domain, recent_count, recent_window_start
                              ) SELECT 'anonymous', sender_id, message_count, link_count, file_count,
                                       first_seen, last_seen, time_buckets, last_domain, recent_count, recent_window_start
                                FROM senders''')
                cursor.execute("DROP TABLE senders")
                cursor.execute("ALTER TABLE senders_v2 RENAME TO senders")
            else:
                if "first_seen" not in columns:
                    cursor.execute("ALTER TABLE senders ADD COLUMN first_seen REAL DEFAULT 0.0")
                if "last_seen" not in columns:
                    cursor.execute("ALTER TABLE senders ADD COLUMN last_seen REAL DEFAULT 0.0")
                if "time_buckets" not in columns:
                    cursor.execute("ALTER TABLE senders ADD COLUMN time_buckets TEXT DEFAULT '{}'")
                if "last_domain" not in columns:
                    cursor.execute("ALTER TABLE senders ADD COLUMN last_domain TEXT DEFAULT ''")
                if "recent_count" not in columns:
                    cursor.execute("ALTER TABLE senders ADD COLUMN recent_count INTEGER DEFAULT 0")
                if "recent_window_start" not in columns:
                    cursor.execute("ALTER TABLE senders ADD COLUMN recent_window_start REAL DEFAULT 0.0")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON senders(client_id, last_seen)")

        # Check sender_name_history table and migrate to compound primary key (client_id, display_name)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sender_name_history'")
        name_exists = cursor.fetchone() is not None
        if not name_exists:
            cursor.execute('''CREATE TABLE sender_name_history (
                            client_id TEXT NOT NULL DEFAULT 'anonymous',
                            display_name TEXT NOT NULL,
                            last_domain TEXT DEFAULT '',
                            last_email TEXT DEFAULT '',
                            last_seen REAL DEFAULT 0.0,
                            count INTEGER DEFAULT 0,
                            PRIMARY KEY (client_id, display_name)
                          )''')
        else:
            cursor.execute("PRAGMA table_info(sender_name_history)")
            name_columns = [col[1] for col in cursor.fetchall()]
            if "client_id" not in name_columns:
                cursor.execute('''CREATE TABLE sender_name_history_v2 (
                                client_id TEXT NOT NULL DEFAULT 'anonymous',
                                display_name TEXT NOT NULL,
                                last_domain TEXT DEFAULT '',
                                last_email TEXT DEFAULT '',
                                last_seen REAL DEFAULT 0.0,
                                count INTEGER DEFAULT 0,
                                PRIMARY KEY (client_id, display_name)
                              )''')
                cursor.execute('''INSERT INTO sender_name_history_v2 (
                                client_id, display_name, last_domain, last_email, last_seen, count
                              ) SELECT 'anonymous', display_name, last_domain, last_email, last_seen, count
                                FROM sender_name_history''')
                cursor.execute("DROP TABLE sender_name_history")
                cursor.execute("ALTER TABLE sender_name_history_v2 RENAME TO sender_name_history")
            else:
                if "last_domain" not in name_columns:
                    cursor.execute("ALTER TABLE sender_name_history ADD COLUMN last_domain TEXT DEFAULT ''")
                if "last_email" not in name_columns:
                    cursor.execute("ALTER TABLE sender_name_history ADD COLUMN last_email TEXT DEFAULT ''")
                if "last_seen" not in name_columns:
                    cursor.execute("ALTER TABLE sender_name_history ADD COLUMN last_seen REAL DEFAULT 0.0")
                if "count" not in name_columns:
                    cursor.execute("ALTER TABLE sender_name_history ADD COLUMN count INTEGER DEFAULT 0")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_name_last_seen ON sender_name_history(client_id, last_seen)")
    conn.close()

init_db()

MAX_RECORDS = 5000

def _prune_tables(cursor):
    cursor.execute("SELECT count(*) FROM senders")
    count = cursor.fetchone()[0] or 0
    if count > MAX_RECORDS:
        cursor.execute("DELETE FROM senders WHERE (client_id, sender_id) IN (SELECT client_id, sender_id FROM senders ORDER BY last_seen ASC LIMIT 500)")
        
    cursor.execute("SELECT count(*) FROM sender_name_history")
    name_count = cursor.fetchone()[0] or 0
    if name_count > MAX_RECORDS:
        cursor.execute("DELETE FROM sender_name_history WHERE (client_id, display_name) IN (SELECT client_id, display_name FROM sender_name_history ORDER BY last_seen ASC LIMIT 500)")

def _normalize_sender(raw_sender: str, metadata: dict):
    if not raw_sender:
        return "", "", "", ""
    match = re.search(r'(.*?)<([^>]+)>', raw_sender)
    if match:
        name = match.group(1).strip(' \t"\'').lower()
        email = match.group(2).strip().lower()
    else:
        name = ""
        email = raw_sender.strip().lower()
    
    domain = metadata.get("sender_domain")
    if not domain and "@" in email:
        domain = email.split("@")[-1]
        
    profile_key = email if email else raw_sender.strip().lower()
    return profile_key, email, domain or "", name

def _analyze_sender_internal(
    sender_id: str,
    has_link: bool = False,
    has_file: bool = False,
    metadata: dict | None = None,
    client_id: str | None = None,
) -> dict:
    if not sender_id:
        return {}
        
    metadata = metadata or {}
    now = metadata.get("timestamp", time.time())
    profile_key, email, domain, display_name = _normalize_sender(sender_id, metadata)
    if not profile_key:
        profile_key = sender_id
    
    cid = (client_id or "").strip() if (client_id and isinstance(client_id, str)) else ""
    if not cid:
        cid = "anonymous"
    
    db_file = get_sender_db_path()
    init_db(db_file)
    conn = sqlite3.connect(db_file, timeout=5.0)
    try:
        cursor = conn.cursor()
        cursor.execute('''SELECT message_count, link_count, file_count, 
                          first_seen, last_seen, time_buckets, last_domain, 
                          recent_count, recent_window_start 
                          FROM senders WHERE client_id=? AND sender_id=?''', (cid, profile_key))
        row = cursor.fetchone()
        
        flags = []
        evidence = []
        score = 0.0
        
        from datetime import datetime
        current_hour = str(datetime.fromtimestamp(now).hour)
        
        if row is None:
            flags.append("new_sender")
            score = 0.2
            evidence.append(EvidenceItem(key="new_sender", value=True, description="Sender has not been observed before"))
            
            new_buckets = {current_hour: 1}
            cursor.execute('''INSERT INTO senders (
                              client_id, sender_id, message_count, link_count, file_count,
                              first_seen, last_seen, time_buckets, last_domain,
                              recent_count, recent_window_start
                              ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, 1, ?)''',
                           (cid, profile_key, 1 if has_link else 0, 1 if has_file else 0,
                            now, now, json.dumps(new_buckets), domain, now))
        else:
            (msg_count, link_count, file_count, first_seen, last_seen, 
             time_buckets_json, last_domain, recent_count, recent_window_start) = row
             
            time_buckets = {}
            try:
                time_buckets = json.loads(time_buckets_json) if time_buckets_json else {}
            except:
                pass
                
            if last_seen > 0 and (now - last_seen) < 60:
                flags.append("rapid_sender_activity")
                score += 0.3
                evidence.append(EvidenceItem(key="rapid_sender_activity", value=now-last_seen, description=f"Message received {now-last_seen:.1f}s after previous"))
                
            if now - recent_window_start > 3600:
                recent_count = 0
                recent_window_start = now
            
            recent_count += 1
            if msg_count > 5 and recent_count > 10:
                flags.append("unusual_frequency")
                score += 0.2
                evidence.append(EvidenceItem(key="unusual_sender_frequency", value=recent_count, description="Unusually high message volume recently"))
                
            if msg_count > 5 and time_buckets.get(current_hour, 0) == 0:
                flags.append("unusual_time")
                score += 0.2
                evidence.append(EvidenceItem(key="unusual_sender_time", value=current_hour, description="Message arrived at an unusual hour for this sender"))
                
            if msg_count > 0 and last_domain and domain and last_domain != domain:
                flags.append("sender_change")
                score += 0.4
                evidence.append(EvidenceItem(key="sender_domain_change", value=domain, description=f"Sender domain changed from {last_domain} to {domain}"))
                
            if has_link and link_count == 0 and msg_count > 3:
                flags.append("out_of_character_link")
                score += 0.3
            if has_file and file_count == 0 and msg_count > 3:
                flags.append("out_of_character_file")
                score += 0.3
                
            time_buckets[current_hour] = time_buckets.get(current_hour, 0) + 1
            new_links = link_count + (1 if has_link else 0)
            new_files = file_count + (1 if has_file else 0)
            
            cursor.execute('''UPDATE senders SET 
                              message_count=message_count+1, 
                              link_count=?, 
                              file_count=?,
                              last_seen=?,
                              time_buckets=?,
                              last_domain=?,
                              recent_count=?,
                              recent_window_start=?
                              WHERE client_id=? AND sender_id=?''',
                           (new_links, new_files, max(last_seen, now), json.dumps(time_buckets), domain, recent_count, recent_window_start, cid, profile_key))

        # Check separate lightweight display-name/domain history mechanism for sender_change detection
        if display_name:
            cursor.execute('''SELECT last_domain, last_email, last_seen, count 
                              FROM sender_name_history WHERE client_id=? AND display_name=?''', (cid, display_name))
            name_row = cursor.fetchone()
            if name_row:
                prev_name_domain, prev_name_email, prev_name_last_seen, prev_name_count = name_row
                if prev_name_domain and domain and prev_name_domain != domain:
                    if "sender_change" not in flags:
                        flags.append("sender_change")
                        score += 0.4
                        evidence.append(EvidenceItem(
                            key="sender_domain_change", 
                            value=domain, 
                            description=f"Sender domain changed from {prev_name_domain} to {domain}"
                        ))
                
                # Keep established domain if discrepancy detected to preserve security against cache poisoning
                target_domain = prev_name_domain if (prev_name_domain and domain and prev_name_domain != domain) else (domain or prev_name_domain)
                cursor.execute('''UPDATE sender_name_history SET 
                                  last_domain=?, 
                                  last_email=?, 
                                  last_seen=?, 
                                  count=count+1 
                                  WHERE client_id=? AND display_name=?''',
                               (target_domain, email, max(prev_name_last_seen, now), cid, display_name))
            else:
                cursor.execute('''INSERT INTO sender_name_history (
                                  client_id, display_name, last_domain, last_email, last_seen, count
                                  ) VALUES (?, ?, ?, ?, ?, 1)''',
                               (cid, display_name, domain, email, now))
                               
        score = min(score, 1.0)
        _prune_tables(cursor)
        conn.commit()
        
    finally:
        conn.close()

    return {
        "score": score,
        "flags": flags,
        "details": {"previous_history_found": bool(row)},
        "evidence": evidence
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
        
        client_id = input_data.client_id
        if not client_id and isinstance(input_data.metadata, dict):
            client_id = input_data.metadata.get("client_id")
        
        try:
            res = _analyze_sender_internal(
                sender_id,
                has_link,
                has_file,
                metadata=input_data.metadata,
                client_id=client_id,
            )
        except Exception as e:
            return EngineResult.error(self.name, f"Database error: {str(e)}")
        
        return self._build_result(
            risk_score=res.get("score", 0.0) * 100.0,
            confidence=0.8 if res.get("details", {}).get("previous_history_found") else 0.5,
            flags=res.get("flags", []),
            evidence=res.get("evidence", []),
            status=EngineStatus.SUCCESS,
            metadata=res.get("details", {})
        )

engine_registry.register(SenderEngine())
