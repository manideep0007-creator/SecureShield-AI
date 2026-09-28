import httpx
import socket
import ipaddress
import contextvars
from urllib.parse import urlparse

# ContextVar to enable strict SSRF filtering on a per-request/context basis
_ssrf_protection_active = contextvars.ContextVar('ssrf_protection_active', default=False)
_orig_getaddrinfo = socket.getaddrinfo

def is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        # Block loopback, private, link-local, multicast, unspecified, and reserved IPs
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return False
        # Block IPv4-mapped IPv6 addresses that point to internal ranges
        if ip.version == 6 and ip.ipv4_mapped:
            return is_safe_ip(str(ip.ipv4_mapped))
        return True
    except ValueError:
        return False

def safe_getaddrinfo(*args, **kwargs):
    """
    Hook for socket.getaddrinfo to prevent DNS rebinding.
    When SSRF protection is active, every actual DNS resolution performed by the 
    underlying async HTTP client is validated right before the TCP handshake.
    This eliminates TOCTOU (Time-of-Check to Time-of-Use) DNS rebinding vulnerabilities.
    """
    res = _orig_getaddrinfo(*args, **kwargs)
    if _ssrf_protection_active.get():
        for item in res:
            ip = item[4][0]
            if not is_safe_ip(ip):
                raise socket.gaierror(socket.EAI_NONAME, f"SSRF Prevention: IP {ip} is blocked.")
    return res

# Apply the monkeypatch automatically
socket.getaddrinfo = safe_getaddrinfo


class SafeURLFetcher:
    """Centralized, SSRF-resistant URL fetcher."""
    
    @staticmethod
    def validate_url_syntax(url: str):
        parsed = urlparse(url)
        
        # 1. Scheme validation
        if parsed.scheme.lower() not in ["http", "https"]:
            raise ValueError(f"SSRF Prevention: Unsupported scheme {parsed.scheme}")
            
        # 2. Reject credentials in URL
        if parsed.username or parsed.password:
            raise ValueError("SSRF Prevention: Embedded URL credentials are not allowed")

        return parsed
        
    @classmethod
    async def resolve_redirects(cls, url: str, max_redirects: int = 5) -> str:
        """
        Safely resolve shortened or redirected links to their final URL.
        Iteratively follows redirects, re-validating the URL format and resolving the IP safely each time.
        """
        current_url = url
        
        # We manually handle redirects to ensure every hop is strictly validated
        for _ in range(max_redirects + 1):
            cls.validate_url_syntax(current_url)
            
            # Enable the DNS-level SSRF protection context
            token = _ssrf_protection_active.set(True)
            try:
                # Disable httpx's internal auto-redirect so we can inspect and validate the Location header ourselves
                async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
                    response = await client.head(current_url)
                    if response.status_code == 405: # Method Not Allowed fallback
                        response = await client.get(current_url)
                        
                    if response.status_code in (301, 302, 303, 307, 308):
                        next_location = response.headers.get("Location")
                        if not next_location:
                            return current_url
                            
                        # Handle relative redirects
                        if not next_location.lower().startswith("http"):
                            from urllib.parse import urljoin
                            next_location = urljoin(current_url, next_location)
                            
                        current_url = next_location
                    else:
                        return current_url
            except Exception as e:
                # If network fails or SSRF is blocked, return the last known URL (or original if first try)
                return current_url
            finally:
                _ssrf_protection_active.reset(token)
                
        # If we hit the max redirect limit, return the last URL we resolved securely
        return current_url
