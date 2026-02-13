"""Origin URL validation to prevent SSRF attacks."""

from __future__ import annotations

import ipaddress
import socket
import unicodedata
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
    ipaddress.ip_network("::/128"),  # IPv6 unspecified (equivalent to 0.0.0.0)
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
    - No null bytes or backslashes (parser confusion / truncation attacks)
    - Scheme is http or https
    - No userinfo (@) in URL authority (prevents parser confusion attacks)
    - Hostname is not a private/reserved IP (including IPv4-mapped IPv6)
    - Hostname in alternative notation (decimal/hex/octal/short) is checked
    - Hostname does not resolve to a private/reserved IP

    When strict_dns=True (recommended for webhooks), DNS resolution failure
    is treated as an error (fail-closed). When False (default, for origin
    URLs), DNS failure is allowed since upstream will fail naturally.
    """
    # Reject null bytes — prevents truncation attacks where
    # "evil.com%00.allowed.com" is parsed differently by URL lib vs DNS.
    if "\x00" in url or "%00" in url.lower():
        return "URL contains null byte"

    # Reject backslashes — WHATWG treats \ as / but RFC 3986 does not,
    # causing parser differentials between validation and HTTP client.
    if "\\" in url:
        return "URL contains backslash (parser confusion risk)"

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

    # NFKC-normalize hostname — fullwidth dots (U+FF0E, U+3002, U+FF61)
    # normalize to ASCII '.', and fullwidth digits to ASCII digits.
    # Without this, "169．254．169．254" bypasses IP checks but may resolve
    # after normalization in HTTP clients that apply IDNA.
    normalized_hostname = unicodedata.normalize("NFKC", hostname)
    if normalized_hostname != hostname:
        # Re-validate with the normalized hostname by substituting it
        hostname = normalized_hostname

    # Strip IPv6 zone IDs (%25xx / %xx) — zone IDs can cause parsing
    # anomalies and ipaddress.ip_address() doesn't handle them.
    if "%" in hostname:
        hostname = hostname.split("%", 1)[0]

    # After normalization and zone-ID stripping, reject hostnames that still
    # contain whitespace (e.g. NBSP → space via NFKC) or non-ASCII characters.
    # This prevents Unicode bypass attacks and IDNA confusion.
    if any(c.isspace() for c in hostname):
        return "Hostname contains whitespace"
    if any(ord(c) > 127 for c in hostname):
        return "Hostname contains non-ASCII characters"

    # Check if hostname is a literal IP address (standard notation)
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_blocked(addr):
            return f"Blocked private/reserved IP: {hostname}"
        return None
    except ValueError:
        pass  # Not a standard IP literal — continue checks

    # Check for alternative IP representations: decimal (2130706433),
    # hex (0x7f000001), octal (0177.0.0.1), short form (127.1).
    # ipaddress.ip_address() doesn't handle these but inet_aton() does.
    try:
        packed = socket.inet_aton(hostname)
        addr = ipaddress.IPv4Address(packed)
        if _is_blocked(addr):
            return f"Blocked private/reserved IP (alternative notation): {hostname}"
        return None
    except OSError:
        pass  # Not a valid IPv4 representation in any notation

    # DNS resolution check for hostnames
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            if _is_blocked(addr):
                return f"Hostname '{hostname}' resolves to blocked IP"
    except (socket.gaierror, UnicodeError):
        # UnicodeError: getaddrinfo raises UnicodeEncodeError for hostnames
        # containing Unicode chars that can't be IDNA-encoded (e.g. U+2029).
        if strict_dns:
            return f"DNS resolution failed for hostname '{hostname}'"
        # Non-strict: allow through (upstream will fail naturally)

    return None
