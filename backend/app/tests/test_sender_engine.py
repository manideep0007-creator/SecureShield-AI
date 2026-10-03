import pytest
import os
import time
from app.engines.sender_engine import SenderEngine, init_db, DB_PATH
from app.models.scan_input import ScanInput

@pytest.fixture(autouse=True)
def setup_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

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
async def test_repeated_sender_rapid_repeat():
    engine = SenderEngine()
    now = time.time()
    
    await engine.analyze(ScanInput(sender_id="alice@test.com", metadata={"timestamp": now}))
    
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata={"timestamp": now + 10}))
    
    assert "rapid_repeat" in result.flags
    assert result.risk_score > 0
    assert result.confidence == 0.8
    
    ev_keys = [e.key for e in result.evidence]
    assert "rapid_repeat" in ev_keys

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
async def test_sender_domain_change():
    engine = SenderEngine()
    now = time.time()
    
    # Key is sender_id. So we use the same sender_id but simulate domain change via metadata
    await engine.analyze(ScanInput(sender_id="internal_id_123", metadata={"sender_domain": "old.com", "timestamp": now - 3600}))
    
    result = await engine.analyze(ScanInput(sender_id="internal_id_123", metadata={"sender_domain": "new.com", "timestamp": now}))
    assert "sender_domain_change" in result.flags
    
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
