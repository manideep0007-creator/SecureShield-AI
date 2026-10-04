import httpx
import socket
import ipaddress
from urllib.parse import urlparse, urljoin


def is_safe_ip(ip_str: str) -> bool:
    """
    Validate whether an IP address is safe for outbound fetching.
    Blocks loopback, private, link-local, multicast, unspecified, reserved,
    non-global, and internal IPv4-mapped IPv6 addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # Block loopback, private, link-local, multicast, unspecified, and reserved IPs
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved or not ip.is_global:
            return False
        # Block IPv4-mapped IPv6 addresses that point to internal ranges
        if ip.version == 6 and ip.ipv4_mapped:
            return is_safe_ip(str(ip.ipv4_mapped))
        return True
    except ValueError:
        return False


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

        # 3. Host validation
        if not parsed.hostname:
            raise ValueError("SSRF Prevention: Missing URL host")

        return parsed
        
    @classmethod
    async def resolve_redirects(cls, url: str, max_redirects: int = 5) -> str:
        """
        Safely resolve shortened or redirected links to their final URL.
        Iteratively follows redirects, synchronously validating every hop's DNS/IP BEFORE connecting.
        Connects directly to the already-validated IP with Host and SNI headers to prevent TOCTOU / DNS rebinding.
        """
        current_url = url
        
        # We manually handle redirects to ensure every hop is strictly validated before connection
        for _ in range(max_redirects + 1):
            parsed = cls.validate_url_syntax(current_url)
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            
            # Fast-path check if hostname is already an IP address literal
            try:
                ip_obj = ipaddress.ip_address(parsed.hostname)
                if not is_safe_ip(str(ip_obj)):
                    return current_url
                safe_ips = [(socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET, str(ip_obj))]
            except ValueError:
                # Synchronously resolve hostname before opening any network connection
                try:
                    addr_info = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
                except (socket.gaierror, socket.herror, OSError):
                    return current_url
                
                if not addr_info:
                    return current_url
                
                safe_ips = []
                for item in addr_info:
                    ip_str = item[4][0]
                    if not is_safe_ip(ip_str):
                        return current_url
                    safe_ips.append((item[0], ip_str))
            
            if not safe_ips:
                return current_url

            # Prefer IPv4 for socket connection reliability if available
            ipv4_ips = [ip for family, ip in safe_ips if family == socket.AF_INET]
            chosen_ip = ipv4_ips[0] if ipv4_ips else safe_ips[0][1]
            formatted_ip = f"[{chosen_ip}]" if ":" in chosen_ip else chosen_ip

            scheme = parsed.scheme.lower()
            path = parsed.path or "/"
            query = f"?{parsed.query}" if parsed.query else ""
            target_url = f"{scheme}://{formatted_ip}:{port}{path}{query}"

            # Set Host header and SNI hostname separately so TLS/SNI and vhosts work correctly
            headers = {"Host": parsed.netloc}
            extensions = {}
            if scheme == "https":
                extensions["sni_hostname"] = parsed.hostname

            try:
                # Disable httpx's internal auto-redirect so we inspect and validate each hop ourselves
                async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
                    response = await client.head(target_url, headers=headers, extensions=extensions)
                    if response.status_code == 405:  # Method Not Allowed fallback
                        response = await client.get(target_url, headers=headers, extensions=extensions)
                        
                    if response.status_code in (301, 302, 303, 307, 308):
                        next_location = response.headers.get("Location")
                        if not next_location:
                            return current_url
                            
                        # Handle relative redirects
                        if not next_location.lower().startswith("http"):
                            next_location = urljoin(current_url, next_location)
                            
                        current_url = next_location
                    else:
                        return current_url
            except Exception:
                # If network fails or connection fails, return the last known safe URL
                return current_url
                
        # If we hit the max redirect limit, return the last URL we reached
        return current_url

