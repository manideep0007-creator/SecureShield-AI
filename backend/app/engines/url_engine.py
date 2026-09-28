import re
import httpx
from urllib.parse import urlparse
from app.config.config import settings
from app.engines.base_engine import BaseEngine
from app.engines.registry import engine_registry
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.scan_input import ScanInput

def lexical_heuristics(url: str) -> dict:
    """Analyze URL string for suspicious patterns."""
    score = 0.0
    flags = []
    evidence = []
    
    # Pre-parse URL
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    
    # 1. IP-based host
    if re.search(r'://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 0.3
        flags.append("ip_based_host")
        
    # 2. @ symbol check (credential injection)
    if "@" in url:
        score += 0.2
        flags.append("at_symbol_present")
        
    # 3. Hyphen count
    hostname = url.split("://")[-1].split("/")[0]
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        score += 0.2
        flags.append(f"high_hyphen_count({hyphen_count})")
        
    # 4. Suspicious TLDs
    suspicious_tlds = [".xyz", ".top", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq"]
    if any(hostname.endswith(t) for t in suspicious_tlds):
        score += 0.4
        flags.append("suspicious_tld")
        
    # 5. URL Shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cli.gs"]
    if any(s in hostname for s in shorteners):
        flags.append("url_shortener") # doesn't necessarily add malice, but noted
        
    # --- PHASE 2: Core Lexical & Host Features (6-9) ---
    # Scoring is unchanged intentionally. We only flag and build evidence.

    # 6. URL Length Deviation
    url_length = len(url)
    if url_length >= 75:
        flags.append("url_length_anomaly")
        evidence.append(EvidenceItem(
            key="URL_LENGTH", 
            value=url_length, 
            description=f"Total URL length is {url_length} characters, exceeding normal limits."
        ))

    # 7. Path Length Deviation
    path_length = len(path)
    if path_length >= 20:
        flags.append("path_length_anomaly")
        evidence.append(EvidenceItem(
            key="PATH_LENGTH",
            value=path_length,
            description=f"URL path depth is {path_length} characters."
        ))

    # 8. Subdomain Depth Count
    # Example approximation (without external TLD database):
    parts = hostname.split('.')
    subdomains = max(0, len(parts) - 2)
    if len(parts) > 0 and parts[0] == "www":
        subdomains = max(0, subdomains - 1)
        
    if subdomains >= 2:
        flags.append("subdomain_depth_anomaly")
        evidence.append(EvidenceItem(
            key="SUBDOMAIN_DEPTH",
            value=subdomains,
            description=f"Hostname exhibits excessive subdomain nesting: {subdomains} layers."
        ))

    # 9. Suspicious Keyword Matches
    target_text = (hostname + path).lower()
    keywords = ["login", "verify", "secure", "account", "banking", "update"]
    matched = [k for k in keywords if k in target_text]
    if matched:
        flags.append("suspicious_keywords")
        evidence.append(EvidenceItem(
            key="SUSPICIOUS_KEYWORDS",
            value=matched,
            description=f"Security-critical keywords detected in URL path/subdomain: {', '.join(matched)}."
        ))

    # 10. Open Redirect Signature (Double Slash)
    # Start looking just after the scheme designation
    idx = url.find("//", url.find("://") + 3) if "://" in url else url.find("//")
    if idx != -1:
        flags.append("double_slash_redirect")
        evidence.append(EvidenceItem(
            key="DOUBLE_SLASH_REDIRECT",
            value=idx,
            description=f"Double-slash redirect artifact detected at index {idx}."
        ))

    # 11. Unencrypted Protocol Check
    if parsed.scheme.lower() == "http":
        flags.append("http_without_https")
        evidence.append(EvidenceItem(
            key="HTTP_WITHOUT_HTTPS",
            value=True,
            description="Protocol defaults to unencrypted HTTP."
        ))

    # 12. Non-Standard Port Mapping
    if parsed.port and parsed.port not in [80, 443]:
        flags.append("non_standard_port")
        evidence.append(EvidenceItem(
            key="NON_STANDARD_PORT",
            value=parsed.port,
            description=f"URL points to non-standard HTTP port: {parsed.port}."
        ))

    # 13. HTTPS Spoofing (Domain Context)
    if "http" in hostname.lower():
        flags.append("https_in_hostname")
        evidence.append(EvidenceItem(
            key="HTTPS_IN_HOSTNAME",
            value=True,
            description="Deceptive 'http/https' string found within the hostname payload."
        ))

    return {"lexical_score": min(score, 1.0), "lexical_flags": flags, "evidence": evidence}

async def check_google_safe_browsing(url: str) -> dict:
    """Call the Google Safe Browsing API."""
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        return {"gsb_score": 0.0, "error": "GSB_API_KEY_NOT_CONFIGURED"}
        
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "SecureShieldAI", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(endpoint, json=payload, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = list(set([m["threatType"] for m in matches]))
                    return {"gsb_score": 1.0, "gsb_threats": threat_types}
                return {"gsb_score": 0.0, "gsb_threats": []}
            return {"gsb_score": 0.0, "error": f"GSB_API_ERROR_{response.status_code}"}
    except Exception as e:
        return {"gsb_score": 0.0, "error": str(e)}

class URLEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "url_engine"

    async def analyze(self, input_data: ScanInput) -> EngineResult:
        url = input_data.url
        if not url:
            return EngineResult.skipped(self.name, "No URL provided")
            
        heuristics = lexical_heuristics(url)
        gsb_result = await check_google_safe_browsing(url)
        
        lexical = heuristics["lexical_score"]
        gsb = gsb_result["gsb_score"]
        
        if gsb > 0:
            combined_score = lexical * 0.4 + gsb * 0.6
        else:
            combined_score = lexical * 0.7 + gsb * 0.3
            
        flags = heuristics["lexical_flags"] + gsb_result.get("gsb_threats", [])
        evidence = heuristics.get("evidence", [])
        
        status = EngineStatus.SUCCESS
        error_message = None
        if "error" in gsb_result:
            status = EngineStatus.PARTIAL
            error_message = gsb_result["error"]
            
        # risk_score (0-100), confidence (0.8 based on V1 fusion)
        return self._build_result(
            risk_score=combined_score * 100.0,
            confidence=0.8,
            flags=flags,
            evidence=evidence,
            status=status,
            error_message=error_message,
            metadata={**heuristics, **gsb_result}
        )

# Register engine
engine_registry.register(URLEngine())

# Legacy function to preserve working functionality for existing pipeline
async def analyze_url(url: str) -> dict:
    engine = URLEngine()
    res = await engine.analyze(ScanInput(url=url))
    
    legacy_dict = {
        "type": "url",
        "score": res.risk_score / 100.0,
        "flags": res.flags,
        "details": res.metadata
    }
    if res.error_message:
        legacy_dict["error"] = res.error_message
        
    return legacy_dict
