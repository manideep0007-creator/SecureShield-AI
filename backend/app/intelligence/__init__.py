"""
SecureShield-AI Live Threat Intelligence Module.

Provides integration with global open-source threat intelligence feeds:
- Abuse.ch URLhaus (Verified malware distribution URLs)
- Abuse.ch MalwareBazaar (Verified malware payload hashes & family signatures)
- OpenPhish & PhishTank (Verified community phishing URLs)
- Tranco Top Legitimate Domains Whitelist
"""

from app.intelligence.threat_feeds import threat_store, init_threat_db

__all__ = ["threat_store", "init_threat_db"]
