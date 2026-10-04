import pytest
import os
import time
import sqlite3
from app.engines.sender_engine import SenderEngine, init_db, DB_PATH
from app.models.scan_input import ScanInput

@pytest.fixture(autouse=True)
def setup_db():
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except OSError:
            pass
    init_db()
    yield
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except OSError:
            pass

@pytest.mark.asyncio
async def test_sender_skipped_when_no_sender_id():
    engine = SenderEngine()
    result = await engine.analyze(ScanInput(sender_id=""))
    assert result.status == "skipped"
    assert result.risk_score == 0.0

@pytest.mark.asyncio
async def test_first_time_sender_cold_start():
    engine = SenderEngine()
    result = await engine.analyze(ScanInput(sender_id="new@domain.com"))
    
    assert result.status == "success"
    assert "new_sender" in result.flags
    assert result.risk_score == 20.0 # 0.2 * 100
    assert result.confidence == 0.5
    
    ev_keys = [e.key for e in result.evidence]
    assert "new_sender" in ev_keys

@pytest.mark.asyncio
async def test_repeated_sender_rapid_sender_activity():
    engine = SenderEngine()
    now = time.time()
    
    await engine.analyze(ScanInput(sender_id="alice@test.com", metadata={"timestamp": now}))
    
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata={"timestamp": now + 10}))
    
    assert "rapid_sender_activity" in result.flags
    assert result.risk_score > 0
    assert result.confidence == 0.8
    
    ev_keys = [e.key for e in result.evidence]
    assert "rapid_sender_activity" in ev_keys

@pytest.mark.asyncio
async def test_unusual_time():
    engine = SenderEngine()
    now = time.time()
    
    for i in range(6):
        await engine.analyze(ScanInput(sender_id="bob@test.com", metadata={"timestamp": now - 3600*24*(i+1)}))
        
    result = await engine.analyze(ScanInput(sender_id="bob@test.com", metadata={"timestamp": now - 3600*12}))
    assert "unusual_time" in result.flags
    
    ev_keys = [e.key for e in result.evidence]
    assert "unusual_sender_time" in ev_keys

@pytest.mark.asyncio
async def test_unusual_frequency():
    engine = SenderEngine()
    now = time.time()
    
    # Establish history > 5 messages
    for i in range(6):
        await engine.analyze(ScanInput(sender_id="spam@test.com", metadata={"timestamp": now - 3600*24*(i+1)}))
        
    # Send 10 messages rapidly to trigger unusual frequency
    for i in range(11):
        result = await engine.analyze(ScanInput(sender_id="spam@test.com", metadata={"timestamp": now + i}))
        
    assert "unusual_frequency" in result.flags
    ev_keys = [e.key for e in result.evidence]
    assert "unusual_sender_frequency" in ev_keys

@pytest.mark.asyncio
async def test_sender_change():
    engine = SenderEngine()
    now = time.time()
    
    # Key is now normalized email. Since "internal_id_123" doesn't have an email format, the key is "internal_id_123"
    await engine.analyze(ScanInput(sender_id="internal_id_123", metadata={"sender_domain": "old.com", "timestamp": now - 3600}))
    
    result = await engine.analyze(ScanInput(sender_id="internal_id_123", metadata={"sender_domain": "new.com", "timestamp": now}))
    assert "sender_change" in result.flags
    
    ev_keys = [e.key for e in result.evidence]
    assert "sender_domain_change" in ev_keys
    
@pytest.mark.asyncio
async def test_normalization_and_malformed():
    engine = SenderEngine()
    
    # Malformed or complex string
    sender_str = "=?UTF-8?Q?Some_Name?= <complex.email+tag@weird-domain.co.uk>"
    
    result = await engine.analyze(ScanInput(sender_id=sender_str))
    assert result.status == "success"
    assert "new_sender" in result.flags

@pytest.mark.asyncio
async def test_sender_change_with_name():
    engine = SenderEngine()
    now = time.time()

    # Use same name but different emails to trigger domain change
    await engine.analyze(ScanInput(sender_id='"Apple Support" <support@apple.com>', metadata={"timestamp": now - 3600}))

    result = await engine.analyze(ScanInput(sender_id='"Apple Support" <hacker@evil.com>', metadata={"timestamp": now}))
    assert "sender_change" in result.flags

    ev_keys = [e.key for e in result.evidence]
    assert "sender_domain_change" in ev_keys

@pytest.mark.asyncio
async def test_normal_sender_profiling_keyed_by_email():
    """Prove that normal sender behavioral profiling is keyed by normalized email."""
    engine = SenderEngine()
    now = time.time()

    # Message 1 with display name "Alice Engineering" <alice@company.com>
    r1 = await engine.analyze(ScanInput(
        sender_id='"Alice Engineering" <alice@company.com>',
        metadata={"timestamp": now}
    ))
    assert "new_sender" in r1.flags
    assert r1.status == "success"

    # Message 2 with different display name "Alice Dev Lead" <alice@company.com>
    # Should update the existing profile keyed by alice@company.com
    r2 = await engine.analyze(ScanInput(
        sender_id='"Alice Dev Lead" <alice@company.com>',
        metadata={"timestamp": now + 120}
    ))
    assert "new_sender" not in r2.flags
    assert r2.confidence == 0.8
    assert r2.metadata.get("previous_history_found") is True

    # Verify directly in SQLite: senders table has exactly 1 row keyed by normalized email
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT sender_id, message_count FROM senders")
        rows = cursor.fetchall()
        assert len(rows) == 1
        sender_id, msg_count = rows[0]
        assert sender_id == "alice@company.com"
        assert msg_count == 2
    finally:
        conn.close()

@pytest.mark.asyncio
async def test_same_display_name_different_senders_does_not_merge_behavioral_profiles():
    """Prove that two different senders sharing the same display name maintain separate profiles."""
    engine = SenderEngine()
    now = time.time()

    # Sender 1: "IT Support" <support@internal-hq.com> sends 3 messages
    for i in range(3):
        await engine.analyze(ScanInput(
            sender_id='"IT Support" <support@internal-hq.com>',
            metadata={"timestamp": now - 3600 * (3 - i)}
        ))

    # Sender 2: "IT Support" <support@external-phish.com> sends a message shortly after
    r_sender2 = await engine.analyze(ScanInput(
        sender_id='"IT Support" <support@external-phish.com>',
        metadata={"timestamp": now + 10}
    ))

    # Sender 2 is a new sender and must NOT inherit Sender 1's behavioral history
    assert "new_sender" in r_sender2.flags
    # Rapid sender activity must NOT trigger on Sender 2 since Sender 2 has no previous message
    assert "rapid_sender_activity" not in r_sender2.flags

    # Verify SQLite state: each sender has an independent row and unmerged message count
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT sender_id, message_count FROM senders ORDER BY sender_id")
        rows = dict(cursor.fetchall())
        assert rows["support@internal-hq.com"] == 3
        assert rows["support@external-phish.com"] == 1
    finally:
        conn.close()

@pytest.mark.asyncio
async def test_genuine_sender_domain_change_detected():
    """Prove that a genuine sender/domain change is detected via display name + domain history."""
    engine = SenderEngine()
    now = time.time()

    # Legitimate sender establishes display name history
    r_legit = await engine.analyze(ScanInput(
        sender_id='"PayPal Billing" <service@paypal.com>',
        metadata={"timestamp": now - 7200}
    ))
    assert "new_sender" in r_legit.flags
    assert "sender_change" not in r_legit.flags

    # Impersonation / domain change: attacker uses same display name with a different domain
    r_attack = await engine.analyze(ScanInput(
        sender_id='"PayPal Billing" <receipt@paypal-security-update.com>',
        metadata={"timestamp": now}
    ))

    assert "sender_change" in r_attack.flags
    ev_keys = [e.key for e in r_attack.evidence]
    assert "sender_domain_change" in ev_keys

    # Verify evidence description mentions previous and new domain
    domain_ev = next(e for e in r_attack.evidence if e.key == "sender_domain_change")
    assert domain_ev.value == "paypal-security-update.com"
    assert "paypal.com" in domain_ev.description
    assert "paypal-security-update.com" in domain_ev.description
    assert r_attack.risk_score >= 40.0

