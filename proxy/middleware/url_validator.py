"""Origin URL validation to prevent SSRF attacks."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Private/reserved IP ranges that should never be origin targets
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

_ALLOWED_SCHEMES = {"http", "https"}


def _normalize_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Normalize IPv4-mapped IPv6 addresses to their IPv4 equivalent.

    ::ffff:127.0.0.1 → 127.0.0.1, so it correctly matches IPv4 blocked networks.
    """
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def _is_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address falls within any blocked network."""
    normalized = _normalize_ip(addr)
    return any(normalized in net for net in _BLOCKED_NETWORKS)


def validate_origin_url(url: str, *, strict_dns: bool = False) -> str | None:
    """Validate an origin URL, returning an error message or None if valid.

    Checks:
    - Scheme is http or https
    - No userinfo (@) in URL authority (prevents parser confusion attacks)
    - Hostname is not a private/reserved IP (including IPv4-mapped IPv6)
    - Hostname does not resolve to a private/reserved IP

    When strict_dns=True (recommended for webhooks), DNS resolution failure
    is treated as an error (fail-closed). When False (default, for origin
    URLs), DNS failure is allowed since upstream will fail naturally.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return f"Invalid URL: {url}"

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return f"Invalid scheme '{parsed.scheme}' — only http/https allowed"

    hostname = parsed.hostname
    if not hostname:
        return "Missing hostname in URL"

    # Reject URLs with userinfo (@) to prevent parser-confusion SSRF attacks.
    # http://public.com@169.254.169.254/ can be parsed differently by urlparse vs httpx.
    if "@" in (parsed.netloc or ""):
        return "URL with userinfo (@) is not allowed"

    # Check if hostname is a literal IP address
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_blocked(addr):
            return f"Blocked private/reserved IP: {hostname}"
        return None
    except ValueError:
        pass  # Not an IP literal — it's a hostname

    # DNS resolution check for hostnames
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            if _is_blocked(addr):
                return f"Hostname '{hostname}' resolves to blocked IP"
    except socket.gaierror:
        if strict_dns:
            return f"DNS resolution failed for hostname '{hostname}'"
        # Non-strict: allow through (upstream will fail naturally)

    return None
