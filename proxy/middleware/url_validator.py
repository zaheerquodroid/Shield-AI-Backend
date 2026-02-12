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


def validate_origin_url(url: str) -> str | None:
    """Validate an origin URL, returning an error message or None if valid.

    Checks:
    - Scheme is http or https
    - Hostname is not a private/reserved IP
    - Hostname does not resolve to a private/reserved IP
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

    # Check if hostname is a literal IP address
    try:
        addr = ipaddress.ip_address(hostname)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                return f"Blocked private/reserved IP: {hostname}"
        return None
    except ValueError:
        pass  # Not an IP literal — it's a hostname

    # DNS resolution check for hostnames
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            for net in _BLOCKED_NETWORKS:
                if addr in net:
                    return f"Hostname '{hostname}' resolves to blocked IP: {info[4][0]}"
    except socket.gaierror:
        pass  # DNS resolution failure — allow (upstream will fail naturally)

    return None
