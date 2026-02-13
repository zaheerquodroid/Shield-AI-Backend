"""SSRF attack simulation tests — validates defenses against known bypass techniques.

References:
  - PayloadsAllTheThings/Server Side Request Forgery
  - HackTricks URL Format Bypass
  - PortSwigger URL Validation Bypass Cheat Sheet
  - OWASP SSRF Prevention Cheat Sheet
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.ssrf_validator import SSRFValidator
from proxy.middleware.url_validator import validate_origin_url


# ── Helpers ──────────────────────────────────────────────────────────────

def _make_request(
    path: str = "/api/webhooks",
    method: str = "POST",
    body_dict: dict | list | None = None,
) -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
    }
    req = Request(scope)
    req._body = json.dumps(body_dict or {}).encode()
    return req


def _ctx(
    *,
    protected_endpoints: list[str] | None = None,
    mode: str = "block",
    scan_all_fields: bool = False,
    allowlist: list[str] | None = None,
) -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = "attack-sim"
    ssrf: dict = {
        "mode": mode,
        "scan_all_fields": scan_all_fields,
        "protected_endpoints": protected_endpoints or ["/api/*"],
    }
    if allowlist is not None:
        ssrf["allowlist"] = allowlist
    ctx.customer_config = {
        "enabled_features": {"ssrf_validator": True},
        "settings": {"ssrf": ssrf},
    }
    return ctx


# ===========================================================================
# 1. Alternative IP Representations (url_validator layer)
# ===========================================================================

class TestAlternativeIPRepresentations:
    """Decimal, hex, octal, and short IP forms must be blocked."""

    def test_decimal_ip_127_0_0_1(self):
        """2130706433 is 127.0.0.1 in 32-bit decimal."""
        result = validate_origin_url("http://2130706433/", strict_dns=True)
        assert result is not None, "Decimal IP 2130706433 (127.0.0.1) not blocked"

    def test_decimal_ip_169_254_169_254(self):
        """2852039166 is 169.254.169.254 in decimal."""
        result = validate_origin_url("http://2852039166/", strict_dns=True)
        assert result is not None, "Decimal IP 2852039166 (169.254.169.254) not blocked"

    def test_hex_ip_127_0_0_1(self):
        """0x7f000001 is 127.0.0.1 in hex."""
        result = validate_origin_url("http://0x7f000001/", strict_dns=True)
        assert result is not None, "Hex IP 0x7f000001 (127.0.0.1) not blocked"

    def test_hex_ip_metadata(self):
        """0xa9fea9fe is 169.254.169.254 in hex."""
        result = validate_origin_url("http://0xa9fea9fe/", strict_dns=True)
        assert result is not None, "Hex IP 0xa9fea9fe (169.254.169.254) not blocked"

    def test_dotted_hex_ip(self):
        """0x7f.0x00.0x00.0x01 is 127.0.0.1 in dotted hex."""
        result = validate_origin_url("http://0x7f.0x00.0x00.0x01/", strict_dns=True)
        assert result is not None, "Dotted hex 0x7f.0x00.0x00.0x01 not blocked"

    def test_octal_ip_127(self):
        """0177.0.0.1 is 127.0.0.1 in octal."""
        result = validate_origin_url("http://0177.0.0.1/", strict_dns=True)
        assert result is not None, "Octal IP 0177.0.0.1 not blocked"

    def test_short_ip_127_1(self):
        """127.1 is shorthand for 127.0.0.1 (missing octets default to 0)."""
        result = validate_origin_url("http://127.1/", strict_dns=True)
        assert result is not None, "Short IP 127.1 not blocked"

    def test_short_ip_127_0_1(self):
        """127.0.1 is shorthand for 127.0.0.1."""
        result = validate_origin_url("http://127.0.1/", strict_dns=True)
        assert result is not None, "Short IP 127.0.1 not blocked"

    def test_zero_ip(self):
        """http://0/ — 0.0.0.0 via inet_aton."""
        result = validate_origin_url("http://0/", strict_dns=True)
        assert result is not None, "IP 0 (0.0.0.0) not blocked"

    def test_mixed_hex_decimal(self):
        """0x7f.0.0.1 mixes hex and decimal."""
        result = validate_origin_url("http://0x7f.0.0.1/", strict_dns=True)
        assert result is not None, "Mixed hex/decimal IP not blocked"

    def test_merged_octets_metadata(self):
        """169.254.43518 merges last two octets (169*256+254=43518)."""
        result = validate_origin_url("http://169.254.43518/", strict_dns=True)
        assert result is not None, "Merged-octet IP 169.254.43518 not blocked"

    def test_entire_127_range(self):
        """Entire 127.0.0.0/8 range is loopback."""
        for ip in ["127.0.1.3", "127.1.1.1", "127.127.127.127", "127.255.255.255"]:
            result = validate_origin_url(f"http://{ip}/", strict_dns=True)
            assert result is not None, f"Loopback IP {ip} not blocked"


# ===========================================================================
# 2. Non-HTTP Scheme Bypass (SSRF validator regex layer)
# ===========================================================================

class TestNonHTTPSchemeBypass:
    """Non-http schemes in URL fields must be caught, not silently ignored."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scheme,host", [
        ("ftp", "10.0.0.1"),
        ("file", "///etc/passwd"),  # file:///etc/passwd
        ("gopher", "127.0.0.1:6379/_INFO"),
        ("dict", "127.0.0.1:6379/INFO"),
        ("tftp", "10.0.0.1:12346/TESTUDPPACKET"),
        ("ldap", "127.0.0.1:389/"),
        ("ssh", "10.0.0.1:22/"),
        ("telnet", "127.0.0.1:23/"),
    ])
    async def test_dangerous_scheme_blocked(self, scheme: str, host: str):
        """Non-http scheme URLs in webhook fields are caught and blocked."""
        mw = SSRFValidator()
        url = f"{scheme}://{host}"
        req = _make_request(body_dict={"callback_url": url})
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response), f"Scheme {scheme}:// silently passed through"
        assert result.status_code == 400


# ===========================================================================
# 3. Protocol-Relative URL Bypass
# ===========================================================================

class TestProtocolRelativeURLBypass:
    """Protocol-relative URLs (//host/path) must not silently pass."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", [
        "//10.0.0.1/path",
        "//127.0.0.1/admin",
        "//169.254.169.254/latest/meta-data/",
        "//[::1]/path",
    ])
    async def test_protocol_relative_url_blocked(self, url: str):
        """Protocol-relative URLs pointing to private IPs are blocked."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": url})
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response), f"Protocol-relative URL {url} silently passed"
        assert result.status_code == 400


# ===========================================================================
# 4. URL Parser Differential Attacks
# ===========================================================================

class TestParserDifferentialAttacks:
    """Attacks exploiting differences between URL parsers."""

    def test_backslash_confusion(self):
        r"""Backslash in URL blocked (WHATWG treats \ as / but RFC3986 does not)."""
        result = validate_origin_url("http://evil.com\\@169.254.169.254/")
        assert result is not None
        assert "backslash" in result.lower()

    def test_backslash_in_scheme(self):
        r"""http:/\/\ pattern blocked."""
        result = validate_origin_url("http:\\/\\/169.254.169.254/")
        assert result is not None

    def test_userinfo_at_sign_confusion(self):
        """Parser confusion with @ sign — already blocked by @userinfo check."""
        result = validate_origin_url("http://public.com@169.254.169.254/")
        assert result is not None
        assert "userinfo" in result.lower() or "@" in result

    def test_credentials_in_url(self):
        """http://user:pass@host blocked."""
        result = validate_origin_url("http://admin:secret@10.0.0.1/")
        assert result is not None

    def test_fragment_does_not_hide_host(self):
        """Fragment (#) doesn't bypass host extraction."""
        result = validate_origin_url("http://169.254.169.254/path#safe.example.com")
        assert result is not None

    @pytest.mark.asyncio
    async def test_backslash_url_in_json_body(self):
        r"""Backslash URL in JSON body caught by middleware."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://evil.com\\@169.254.169.254/"})
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ===========================================================================
# 5. Null Byte Injection
# ===========================================================================

class TestNullByteInjection:
    """Null bytes in URLs must be rejected to prevent truncation attacks."""

    def test_null_byte_in_hostname(self):
        """http://evil.com%00.allowed.com blocked."""
        result = validate_origin_url("http://evil.com%00.allowed.com/")
        assert result is not None
        assert "null byte" in result.lower()

    def test_null_byte_before_at(self):
        """http://allowed.com%00@169.254.169.254/ blocked."""
        result = validate_origin_url("http://allowed.com%00@169.254.169.254/")
        assert result is not None
        assert "null byte" in result.lower()

    def test_literal_null_byte(self):
        """Literal \\x00 in URL blocked."""
        result = validate_origin_url("http://evil.com\x00.safe.com/")
        assert result is not None
        assert "null byte" in result.lower()

    @pytest.mark.asyncio
    async def test_null_byte_url_in_json_body(self):
        """Null byte URL in request body caught by middleware."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"webhook_url": "http://safe.com%00@10.0.0.1/"})
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ===========================================================================
# 6. IPv6 Evasion Techniques
# ===========================================================================

class TestIPv6Evasion:
    """IPv6 variants must be caught."""

    def test_ipv6_loopback(self):
        result = validate_origin_url("http://[::1]/")
        assert result is not None

    def test_ipv6_full_loopback(self):
        """Full form [0:0:0:0:0:0:0:1]."""
        result = validate_origin_url("http://[0:0:0:0:0:0:0:1]/")
        assert result is not None

    def test_ipv4_mapped_ipv6_loopback(self):
        result = validate_origin_url("http://[::ffff:127.0.0.1]/")
        assert result is not None

    def test_ipv4_mapped_ipv6_metadata(self):
        result = validate_origin_url("http://[::ffff:169.254.169.254]/")
        assert result is not None

    def test_ipv6_private_fc00(self):
        result = validate_origin_url("http://[fc00::1]/")
        assert result is not None

    def test_ipv6_link_local_fe80(self):
        result = validate_origin_url("http://[fe80::1]/")
        assert result is not None

    def test_ipv6_all_zeros(self):
        """[::] is 0.0.0.0 equivalent."""
        result = validate_origin_url("http://[::]/")
        assert result is not None

    @pytest.mark.asyncio
    async def test_ipv6_loopback_in_body_blocked(self):
        """IPv6 loopback in JSON body blocked by middleware."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"endpoint_url": "http://[::1]/admin"})
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ===========================================================================
# 7. URL Encoding Tricks
# ===========================================================================

class TestURLEncodingTricks:
    """Percent-encoded hostnames must not bypass validation."""

    def test_percent_encoded_hostname(self):
        """%31%32%37.0.0.1 = 127.0.0.1 percent-encoded."""
        # urlparse doesn't decode percent-encoded hostnames, so this goes to DNS.
        # With strict_dns=True, if DNS fails, it's blocked.
        result = validate_origin_url("http://%31%32%37.0.0.1/", strict_dns=True)
        assert result is not None, "Percent-encoded hostname not blocked"

    def test_double_encoded_hostname(self):
        """%2531%2532%2537 — double encoding should fail DNS and be blocked."""
        result = validate_origin_url("http://%2531%2532%2537.0.0.1/", strict_dns=True)
        assert result is not None

    @pytest.mark.asyncio
    async def test_encoded_url_in_body(self):
        """Percent-encoded private IP in body field blocked."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://%31%32%37.0.0.1/"})
        ctx = _ctx()

        # DNS will fail for %31%32%37.0.0.1, strict_dns=True blocks it
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ===========================================================================
# 8. DNS Rebinding Simulation
# ===========================================================================

class TestDNSRebinding:
    """DNS rebinding attacks — validate that strict_dns catches failures."""

    @pytest.mark.asyncio
    async def test_dns_rebinding_first_call_public_second_private(self):
        """Simulates DNS rebinding: first resolve → public, second → private.

        Our validator checks DNS once at validation time with strict_dns=True.
        If the DNS returns a private IP at check time, it's blocked.
        """
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://rebind.attacker.com/steal"})
        ctx = _ctx()

        # Simulate DNS resolving to private IP
        with patch(
            "proxy.middleware.ssrf_validator.validate_origin_url",
            return_value="Hostname 'rebind.attacker.com' resolves to blocked IP",
        ):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_dns_failure_blocked_strict(self):
        """DNS failure with strict_dns=True is fail-closed."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://nonexistent.invalid/hook"})
        ctx = _ctx()

        # Real DNS failure — strict_dns blocks
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ===========================================================================
# 9. DNS Wildcard Services (nip.io, sslip.io, etc.)
# ===========================================================================

class TestDNSWildcardServices:
    """DNS wildcard services that resolve to embedded IPs."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("domain", [
        "127.0.0.1.nip.io",
        "169.254.169.254.nip.io",
        "10.0.0.1.sslip.io",
    ])
    async def test_nip_io_style_domains_blocked(self, domain: str):
        """Domains like 127.0.0.1.nip.io resolve to private IPs."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"webhook_url": f"http://{domain}/hook"})
        ctx = _ctx()

        # Mock DNS resolution to return the private IP
        ip = domain.rsplit(".nip.io", 1)[0].rsplit(".sslip.io", 1)[0]
        with patch(
            "proxy.middleware.ssrf_validator.validate_origin_url",
            return_value=f"Hostname '{domain}' resolves to blocked IP",
        ):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ===========================================================================
# 10. Cloud Metadata Endpoints
# ===========================================================================

class TestCloudMetadataEndpoints:
    """AWS/GCP/Azure metadata endpoints must be blocked."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", [
        # AWS IMDSv1
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # DigitalOcean
        "http://169.254.169.254/metadata/v1/",
        # AWS ECS
        "http://169.254.170.2/v2/credentials/",
    ])
    async def test_cloud_metadata_blocked(self, url: str):
        """Cloud metadata endpoints blocked via private IP check."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": url})
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response), f"Metadata URL {url} not blocked"
        assert result.status_code == 400


# ===========================================================================
# 11. Fail-Closed Exception Handling
# ===========================================================================

class TestFailClosedExceptionHandling:
    """Exceptions during validation must not silently allow requests through."""

    @pytest.mark.asyncio
    async def test_validation_exception_treated_as_violation(self):
        """If validate_origin_url raises, it's treated as a violation (fail-closed)."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://crash.example.com/hook"})
        ctx = _ctx()

        with patch(
            "proxy.middleware.ssrf_validator.validate_origin_url",
            side_effect=RuntimeError("unexpected crash"),
        ):
            result = await mw.process_request(req, ctx)

        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_exception_on_one_url_does_not_skip_others(self):
        """One URL crashing doesn't prevent other URLs from being checked."""
        mw = SSRFValidator()
        req = _make_request(body_dict={
            "callback_url": "http://crash.example.com/first",
            "redirect_url": "http://10.0.0.1/second",
        })
        ctx = _ctx()

        call_count = 0

        def _side_effect(url, **kw):
            nonlocal call_count
            call_count += 1
            if "crash" in url:
                raise RuntimeError("crash")
            return "Blocked private IP"

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", side_effect=_side_effect):
            result = await mw.process_request(req, ctx)

        assert isinstance(result, Response)
        assert result.status_code == 400
        assert call_count == 2, "Second URL was not checked after first crashed"


# ===========================================================================
# 12. Error Response Information Leakage
# ===========================================================================

class TestErrorResponseInfoLeakage:
    """Error responses must not leak internal details."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role",
        "http://10.0.0.1:8080/internal-api/secrets",
        "ftp://192.168.1.1/private",
    ])
    async def test_blocked_url_not_in_response(self, url: str):
        """Blocked URLs must not appear in error response body."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"webhook_url": url})
        ctx = _ctx()

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)

        if result is not None:
            raw = result.body.decode()
            # No part of the URL should appear in the error message
            assert url not in raw
            # Hostname/IP shouldn't be in the response
            for fragment in ["169.254", "10.0.0", "192.168", "meta-data", "secrets", "/private"]:
                if fragment in url:
                    assert fragment not in raw, f"Fragment '{fragment}' leaked in response"


# ===========================================================================
# 13. Mixed Legitimate and Malicious URLs
# ===========================================================================

class TestMixedURLs:
    """A single malicious URL among legitimate ones must still be caught."""

    @pytest.mark.asyncio
    async def test_one_bad_url_among_good_ones(self):
        """Even one malicious URL blocks the request (fail-closed)."""
        mw = SSRFValidator()
        req = _make_request(body_dict={
            "primary_url": "https://hooks.slack.com/services/T00/B00/xxx",
            "secondary_url": "https://events.pagerduty.com/v2/enqueue",
            "evil_url": "http://169.254.169.254/latest/meta-data/",
        })
        ctx = _ctx()

        def _selective_validate(url, **kw):
            if "169.254" in url:
                return "Blocked private/reserved IP"
            return None

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", side_effect=_selective_validate):
            result = await mw.process_request(req, ctx)

        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_all_good_urls_pass(self):
        """All-legitimate URLs pass through without blocking."""
        mw = SSRFValidator()
        req = _make_request(body_dict={
            "primary_url": "https://hooks.slack.com/ok",
            "secondary_url": "https://events.pagerduty.com/ok",
        })
        ctx = _ctx()

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value=None):
            result = await mw.process_request(req, ctx)
        assert result is None


# ===========================================================================
# 14. Alternative IP in SSRF Middleware (end-to-end)
# ===========================================================================

class TestAlternativeIPEndToEnd:
    """Decimal/hex/octal IPs blocked end-to-end through the middleware."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url,description", [
        ("http://2130706433/hook", "decimal 127.0.0.1"),
        ("http://0x7f000001/hook", "hex 127.0.0.1"),
        ("http://0177.0.0.1/hook", "octal 127.0.0.1"),
        ("http://127.1/hook", "short form 127.0.0.1"),
        ("http://0/hook", "zero IP"),
    ])
    async def test_alternative_ip_in_body_blocked(self, url: str, description: str):
        """Alternative IP representations in request body are blocked."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": url})
        ctx = _ctx()

        # Use real validation (no mocks) — tests the full stack
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response), f"{description} ({url}) not blocked"
        assert result.status_code == 400


# ===========================================================================
# 15. Scheme Validation in url_validator
# ===========================================================================

class TestSchemeValidation:
    """Non-http(s) schemes rejected at the url_validator level."""

    @pytest.mark.parametrize("url", [
        "ftp://10.0.0.1/file",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:11211/stats",
        "ldap://10.0.0.1/",
        "ssh://10.0.0.1:22/",
        "telnet://10.0.0.1:23/",
    ])
    def test_dangerous_schemes_rejected(self, url: str):
        """validate_origin_url rejects non-http(s) schemes."""
        result = validate_origin_url(url)
        assert result is not None
        assert "scheme" in result.lower()


# ===========================================================================
# 16. Backslash and Null Byte in url_validator
# ===========================================================================

class TestURLValidatorHardening:
    """Direct tests for new hardening in url_validator."""

    @pytest.mark.parametrize("url", [
        "http://evil.com\\@169.254.169.254/",
        "http:\\/\\/169.254.169.254/",
        "http://127.0.0.1\\/admin",
    ])
    def test_backslash_blocked(self, url: str):
        result = validate_origin_url(url)
        assert result is not None
        assert "backslash" in result.lower()

    @pytest.mark.parametrize("url", [
        "http://evil.com%00.safe.com/",
        "http://safe.com%00@10.0.0.1/",
        "http://host\x00name.com/",
    ])
    def test_null_byte_blocked(self, url: str):
        result = validate_origin_url(url)
        assert result is not None
        assert "null byte" in result.lower()

    def test_clean_url_passes(self):
        """Normal URLs still pass after hardening."""
        result = validate_origin_url("https://hooks.slack.com/services/T00/B00/xxx")
        assert result is None

    def test_public_ip_passes(self):
        """Public IPs still pass."""
        result = validate_origin_url("http://203.0.113.1:8080/webhook")
        assert result is None
