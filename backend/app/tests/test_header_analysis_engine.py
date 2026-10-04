import pytest
import time
from app.engines.header_analysis_engine import HeaderAnalysisEngine
from app.models.scan_input import ScanInput

@pytest.mark.asyncio
async def test_header_engine_skipped_empty_metadata():
    engine = HeaderAnalysisEngine()
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata={}))
    assert result.status == "skipped"

@pytest.mark.asyncio
async def test_header_engine_clean_headers():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Reply-To": "alice@test.com",
            "Return-Path": "alice@test.com",
            "Message-ID": "<123@test.com>",
            "Authentication-Results": "pass"
        },
        "timestamp": time.time()
    }
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert result.status == "success"
    assert len(result.flags) == 0
    assert result.risk_score == 0.0

@pytest.mark.asyncio
async def test_reply_to_mismatch():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Reply-To": "hacker@evil.com",
            "Message-ID": "<123@test.com>"
        }
    }
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert "REPLY_TO_MISMATCH" in result.flags
    assert result.risk_score == 30.0 # 0.3 * 100

@pytest.mark.asyncio
async def test_return_path_mismatch():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Return-Path": "hacker@evil.com",
            "Message-ID": "<123@test.com>"
        }
    }
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert "RETURN_PATH_MISMATCH" in result.flags
    assert result.risk_score == 30.0

@pytest.mark.asyncio
async def test_authentication_failures_spf_dkim_dmarc():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Message-ID": "<123@test.com>",
            "Authentication-Results": "spf=fail dkim=fail dmarc=reject"
        }
    }
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert "AUTHENTICATION_FAILURE" in result.flags
    assert "SPF_FAILURE" in result.flags
    assert "DKIM_FAILURE" in result.flags
    assert "DMARC_FAILURE" in result.flags
    assert result.risk_score == 40.0 # 0.4 * 100

@pytest.mark.asyncio
async def test_message_id_anomaly():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Message-ID": "<123@evil.com>",
        }
    }
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert "MESSAGE_ID_ANOMALY" in result.flags
    assert result.risk_score == 10.0
    
    # Missing Message-ID
    metadata2 = {
        "headers": {
            "From": "alice@test.com",
            "Reply-To": "alice@test.com"
        }
    }
    result2 = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata2))
    assert "MESSAGE_ID_ANOMALY" in result2.flags

@pytest.mark.asyncio
async def test_timestamp_anomaly():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Message-ID": "<123@test.com>",
            "Date": "Wed, 01 Jan 2020 00:00:00 +0000"
        },
        "timestamp": 1577836800 + (86400 * 10) # 10 days after the email Date
    }
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert "TIMESTAMP_ANOMALY" in result.flags
    assert result.risk_score == 20.0

@pytest.mark.asyncio
async def test_received_chain_anomaly():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Message-ID": "<123@test.com>",
            "Received": ["forged IP hop", "normal hop"]
        }
    }
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert "RECEIVED_CHAIN_ANOMALY" in result.flags
    assert result.risk_score == 30.0

@pytest.mark.asyncio
async def test_deterministic_scoring_bounds_confidence():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Reply-To": "hacker@evil.com", # 0.3
            "Return-Path": "hacker@evil.com", # 0.3
            "Message-ID": "<123@evil.com>", # 0.1
            "Authentication-Results": "spf=fail", # 0.4
            "Received": "forged", # 0.3
            "Date": "Wed, 01 Jan 2020 00:00:00 +0000"
        },
        "timestamp": 1577836800 + (86400 * 10) # 0.2
    }
    # Total sum is 1.6, but capped at 0.9 (90.0) so it does not exceed Malware independently merely on headers.
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert result.risk_score == 90.0
    assert result.confidence == 0.8 # Since there are flags, confidence is 0.8
    assert result.status == "success"

@pytest.mark.asyncio
async def test_no_high_risk_from_single_weak_signal():
    engine = HeaderAnalysisEngine()
    metadata = {
        "headers": {
            "From": "alice@test.com",
            "Message-ID": "<123@evil.com>" # Creates single weak signal
        }
    }
    result = await engine.analyze(ScanInput(sender_id="alice@test.com", metadata=metadata))
    assert result.risk_score == 10.0
    assert result.risk_score < 45.0 # Max boundary for lower tier (not High/Phishing/Malware)

@pytest.mark.asyncio
async def test_engine_failure_isolation():
    engine = HeaderAnalysisEngine()
    # Mocking to throw error
    async def bad_analyze(*args, **kwargs):
        raise ValueError("Simulated catastrophic crash")
    
    engine.analyze = bad_analyze
    result = await engine.safe_analyze(ScanInput(metadata={"headers": {"From": "alice"}}))
    assert result.status == "error"
    assert "Simulated catastrophic crash" in result.error_message
    assert result.risk_score == 0.0
