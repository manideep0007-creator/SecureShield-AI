import httpx
import socket
import ipaddress
from urllib.parse import urlparse, urljoin


BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (source only)
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 private
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier Grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud metadata (AWS, GCP, etc.)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (Documentation)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 private
    ipaddress.ip_network("198.18.0.0/15"),      # Network interconnect device benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (Documentation)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (Documentation)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"), # Limited broadcast
]

BLOCKED_EXACT_IPS = {
    ipaddress.ip_address("168.63.129.16"),     # Azure virtual network metadata
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud internal metadata
}

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("64:ff9b:1::/48"),     # Local-use IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique local (private)
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

PROHIBITED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".localdomain",
    ".corp",
    ".home",
    ".arpa",
)

PROHIBITED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "metadata.azure.com",
}


def is_safe_ip(ip_str: str) -> bool:
    """
    Validate whether an IP address is safe for outbound fetching.
    Blocks loopback, private, link-local, multicast, unspecified, reserved,
    non-global, cloud metadata endpoints, Carrier Grade NAT, internal
    IPv4-mapped IPv6 addresses, and IPv6 zone identifiers.
    """
    if not ip_str or "%" in ip_str:
        # Block IPv6 zone indices (e.g. fe80::1%eth0)
        return False

    try:
        ip = ipaddress.ip_address(ip_str)
        # Block loopback, private, link-local, multicast, unspecified, and reserved IPs
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved or not ip.is_global:
            return False

        # Block IPv4-mapped IPv6 addresses that point to internal ranges
        if ip.version == 6 and ip.ipv4_mapped:
            return is_safe_ip(str(ip.ipv4_mapped))

        if ip.version == 4:
            if ip in BLOCKED_EXACT_IPS:
                return False
            for net in BLOCKED_IP_NETWORKS:
                if ip in net:
                    return False
        elif ip.version == 6:
            for net in BLOCKED_IPV6_NETWORKS:
                if ip in net:
                    return False

        return True
    except ValueError:
        return False


class SafeURLFetcher:
    """Centralized, SSRF-resistant URL fetcher with DNS-rebinding protection."""

    @staticmethod
    def validate_url_syntax(url: str):
        # 1. Reject whitespace, control characters, and CRLF injection
        if any(c in url for c in ("\r", "\n", "\t", " ")):
            raise ValueError("SSRF Prevention: URL contains whitespace or control characters")

        # 2. Reject unicode full-width dot homographs (e.g. \u3002, \uff0e, \uff61)
        if any(c in url for c in ("\u3002", "\uff0e", "\uff61")):
            raise ValueError("SSRF Prevention: Prohibited unicode homograph characters in URL")

        parsed = urlparse(url)

        # 3. Scheme validation
        if parsed.scheme.lower() not in ["http", "https"]:
            raise ValueError(f"SSRF Prevention: Unsupported scheme {parsed.scheme}")

        # 4. Reject credentials or userinfo in URL
        if parsed.username or parsed.password or ("@" in (parsed.netloc or "")):
            raise ValueError("SSRF Prevention: Embedded URL credentials are not allowed")

        # 5. Port validation
        try:
            port = parsed.port
            if port is not None and not (1 <= port <= 65535):
                raise ValueError(f"SSRF Prevention: Invalid port {port}")
        except ValueError as e:
            if "SSRF Prevention" in str(e):
                raise
            raise ValueError(f"SSRF Prevention: Invalid port in URL: {e}")

        # 6. Host validation
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError("SSRF Prevention: Missing URL host")

        if hostname in PROHIBITED_HOSTNAMES or any(hostname.endswith(sfx) for sfx in PROHIBITED_HOST_SUFFIXES):
            raise ValueError(f"SSRF Prevention: Prohibited internal host '{hostname}'")

        # 7. Check for dotted hex or octal IP format (e.g. 0x7f.0.0.1, 0177.0.0.1)
        labels = hostname.split(".")
        for label in labels:
            if label.startswith("0x") or (len(label) > 1 and label.startswith("0") and label.isdigit()):
                raise ValueError(f"SSRF Prevention: Obfuscated IP format not allowed: '{hostname}'")

        # 8. Disallow raw integer, octal, or hex obfuscated IP addresses that map to unsafe targets
        if hostname.isdigit():
            try:
                int_val = int(hostname)
                if 0 <= int_val <= 0xFFFFFFFF:
                    ip_obj = ipaddress.ip_address(int_val)
                    if not is_safe_ip(str(ip_obj)):
                        raise ValueError(f"SSRF Prevention: Disallowed integer IP address '{hostname}'")
            except OverflowError:
                pass
        elif hostname.startswith("0x"):
            try:
                int_val = int(hostname, 16)
                if 0 <= int_val <= 0xFFFFFFFF:
                    ip_obj = ipaddress.ip_address(int_val)
                    if not is_safe_ip(str(ip_obj)):
                        raise ValueError(f"SSRF Prevention: Disallowed hex IP address '{hostname}'")
            except OverflowError:
                pass

        return parsed

    @classmethod
    async def resolve_redirects(cls, url: str, max_redirects: int = 5) -> str:
        """
        Safely resolve shortened or redirected links to their final URL.
        Iteratively follows redirects, validating every hop's DNS/IP BEFORE connecting.
        Connects directly to the already-validated IP with Host and SNI headers to prevent TOCTOU / DNS rebinding.
        """
        current_url = url
        visited_urls: set[str] = set()

        for _ in range(max_redirects + 1):
            if current_url in visited_urls:
                # Prevent circular redirect loops
                return current_url
            visited_urls.add(current_url)

            try:
                parsed = cls.validate_url_syntax(current_url)
            except ValueError:
                return current_url

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
                        # If any resolved IP is unsafe, abort connection to prevent rebinding
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
                async with httpx.AsyncClient(verify=True, follow_redirects=False, timeout=5.0) as client:
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

                        if next_location in visited_urls:
                            return current_url

                        current_url = next_location
                    else:
                        return current_url
            except Exception:
                # If network fails or connection fails, return the last known safe URL
                return current_url

        return current_url
