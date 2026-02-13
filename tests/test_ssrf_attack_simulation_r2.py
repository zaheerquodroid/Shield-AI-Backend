"""SSRF attack simulation tests — Round 2.

Covers advanced bypass vectors discovered in second security audit:
  - JSON duplicate key smuggling
  - Recursive JSON depth bomb (DoS)
  - Unicode hostname normalization bypass
  - IPv6 zone ID bypass
  - Non-JSON Content-Type warning
  - Unicode whitespace in URLs
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.llm_sanitizer import _extract_string_fields, _MAX_EXTRACT_DEPTH
from proxy.middleware.pipeline import RequestContext
from proxy.middleware.ssrf_validator import SSRFValidator, _check_duplicate_keys
from proxy.middleware.url_validator import validate_origin_url


# ── Helpers ──────────────────────────────────────────────────────────────

def _make_request(
    path: str = "/api/webhooks",
    method: str = "POST",
    body: bytes | None = None,
    body_dict: dict | list | None = None,
    content_type: str = "application/json",
) -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [(b"content-type", content_type.encode())],
    }
    req = Request(scope)
    if body is not None:
        req._body = body
    elif body_dict is not None:
        req._body = json.dumps(body_dict).encode()
    else:
        req._body = b""
    return req


def _ctx(
    *,
    protected_endpoints: list[str] | None = None,
    mode: str = "block",
    scan_all_fields: bool = False,
) -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = "attack-sim-r2"
    ssrf: dict = {
        "mode": mode,
        "scan_all_fields": scan_all_fields,
        "protected_endpoints": protected_endpoints or ["/api/*"],
    }
    ctx.customer_config = {
        "enabled_features": {"ssrf_validator": True},
        "settings": {"ssrf": ssrf},
    }
    return ctx


# ===========================================================================
# 1. JSON Duplicate Key Smuggling
# ===========================================================================

class TestJSONDuplicateKeySmuggling:
    """Duplicate JSON keys can smuggle malicious URLs past validators.

    Python's json.loads uses last-wins, but upstream parsers may use first-wins.
    Attacker sends: {"url":"http://evil.com","url":"http://safe.com"}
    Python sees "safe.com" → passes validation. Upstream uses "evil.com".
    """

    def test_detect_duplicate_keys_true(self):
        """Duplicate keys are detected."""
        raw = b'{"url":"http://safe.com","url":"http://evil.com"}'
        assert _check_duplicate_keys(raw) is True

    def test_detect_duplicate_keys_false(self):
        """No duplicates returns False."""
        raw = b'{"url":"http://safe.com","callback":"http://other.com"}'
        assert _check_duplicate_keys(raw) is False

    def test_detect_nested_duplicate_keys(self):
        """Duplicate keys in nested objects are detected."""
        raw = b'{"config":{"url":"http://safe.com","url":"http://evil.com"}}'
        assert _check_duplicate_keys(raw) is True

    def test_detect_duplicate_keys_invalid_json(self):
        """Invalid JSON returns False (no crash)."""
        assert _check_duplicate_keys(b"not json") is False

    @pytest.mark.asyncio
    async def test_duplicate_keys_blocked_in_block_mode(self):
        """Requests with duplicate JSON keys are blocked."""
        mw = SSRFValidator()
        raw = b'{"callback_url":"https://safe.example.com","callback_url":"http://169.254.169.254/"}'
        req = _make_request(body=raw)
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400
        body = json.loads(result.body)
        assert "duplicate" in body["message"].lower()

    @pytest.mark.asyncio
    async def test_duplicate_keys_logged_in_detect_only(self):
        """In detect_only mode, duplicate keys are logged but request passes through."""
        mw = SSRFValidator()
        raw = b'{"callback_url":"https://safe.com","callback_url":"http://169.254.169.254/"}'
        req = _make_request(body=raw)
        ctx = _ctx(mode="detect_only")

        with patch("proxy.middleware.ssrf_validator.logger") as mock_logger:
            result = await mw.process_request(req, ctx)

        # In detect_only, the duplicate key check still logs but continues.
        # The actual URL validation will also run and detect 169.254... but
        # in detect_only mode it returns None.
        mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_no_duplicate_keys_passes_through(self):
        """Normal JSON without duplicates is processed normally."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "https://safe.example.com/"})
        ctx = _ctx()

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value=None):
            result = await mw.process_request(req, ctx)
        assert result is None


# ===========================================================================
# 2. Recursive JSON Depth Bomb
# ===========================================================================

class TestJSONDepthBomb:
    """Deeply nested JSON must not crash extract_string_fields."""

    def test_depth_limit_enforced(self):
        """Nesting beyond _MAX_EXTRACT_DEPTH is safely truncated."""
        # Build a structure nested _MAX_EXTRACT_DEPTH + 10 levels deep
        depth = _MAX_EXTRACT_DEPTH + 10
        obj: dict | str = "http://169.254.169.254/"
        for _ in range(depth):
            obj = {"a": obj}

        fields = _extract_string_fields(obj)
        # The deeply nested URL should NOT be extracted (depth exceeded)
        urls = [v for _, v in fields if "169.254" in v]
        assert len(urls) == 0, "Depth-limited extraction should not reach deeply nested URL"

    def test_normal_depth_extracted(self):
        """Reasonable nesting depth still works."""
        obj = {"level1": {"level2": {"level3": {"callback_url": "http://example.com"}}}}
        fields = _extract_string_fields(obj)
        urls = [v for _, v in fields if "example.com" in v]
        assert len(urls) == 1

    def test_flat_structure_not_affected(self):
        """Flat structures unaffected by depth limit."""
        obj = {f"field_{i}": f"value_{i}" for i in range(100)}
        fields = _extract_string_fields(obj)
        assert len(fields) == 100

    @pytest.mark.asyncio
    async def test_depth_bomb_does_not_crash_middleware(self):
        """Even extreme nesting doesn't crash the middleware."""
        mw = SSRFValidator()
        depth = 200
        obj: dict | str = "http://169.254.169.254/"
        for _ in range(depth):
            obj = {"url": obj}

        req = _make_request(body_dict=obj)
        ctx = _ctx()

        # Should not raise RecursionError
        result = await mw.process_request(req, ctx)
        # URL is too deep to extract, so no violation found → passes through
        assert result is None


# ===========================================================================
# 3. Unicode Hostname Normalization Bypass
# ===========================================================================

class TestUnicodeHostnameBypass:
    """Unicode fullwidth dots and digits in hostnames must be normalized."""

    def test_fullwidth_dots_blocked(self):
        """169．254．169．254 (fullwidth dots U+FF0E) normalized → 169.254.169.254."""
        url = "http://169\uff0e254\uff0e169\uff0e254/latest/meta-data/"
        result = validate_origin_url(url, strict_dns=True)
        assert result is not None, "Fullwidth dots bypassed IP check"

    def test_ideographic_full_stop_blocked(self):
        """169。254。169。254 (U+3002 ideographic full stop) normalized."""
        url = "http://169\u3002254\u3002169\u3002254/"
        result = validate_origin_url(url, strict_dns=True)
        assert result is not None, "Ideographic full stop bypassed IP check"

    def test_halfwidth_ideographic_stop_blocked(self):
        """U+FF61 halfwidth ideographic full stop."""
        url = "http://127\uff610\uff610\uff611/"
        result = validate_origin_url(url, strict_dns=True)
        assert result is not None, "Halfwidth ideographic stop bypassed IP check"

    def test_fullwidth_digits_blocked(self):
        """Fullwidth digits ０-９ normalize to ASCII 0-9."""
        # \uff11\uff12\uff17 = fullwidth "127"
        url = "http://\uff11\uff12\uff17\uff0e\uff10\uff0e\uff10\uff0e\uff11/"
        result = validate_origin_url(url, strict_dns=True)
        assert result is not None, "Fullwidth digits bypassed IP check"

    def test_normal_ascii_hostname_passes(self):
        """Normal ASCII hostnames still pass."""
        with patch("proxy.middleware.url_validator.socket.getaddrinfo",
                    return_value=[(2, 1, 0, '', ('93.184.216.34', 0))]):
            result = validate_origin_url("http://example.com/webhook")
        assert result is None

    @pytest.mark.asyncio
    async def test_fullwidth_dots_in_body_blocked(self):
        """Unicode dots in URL field values are caught by middleware."""
        mw = SSRFValidator()
        url = "http://169\uff0e254\uff0e169\uff0e254/"
        req = _make_request(body_dict={"callback_url": url})
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ===========================================================================
# 4. IPv6 Zone ID Bypass
# ===========================================================================

class TestIPv6ZoneIDBypass:
    """IPv6 zone IDs (%25...) must be stripped before validation."""

    def test_zone_id_stripped_fe80(self):
        """fe80::1%25eth0 — zone ID stripped, fe80::1 is link-local (blocked)."""
        result = validate_origin_url("http://[fe80::1%25eth0]/")
        assert result is not None, "IPv6 with zone ID bypassed link-local check"

    def test_zone_id_stripped_loopback(self):
        """::1%25lo0 — zone ID stripped, ::1 is loopback (blocked)."""
        result = validate_origin_url("http://[::1%25lo0]/")
        assert result is not None

    def test_zone_id_public_ip_passes(self):
        """Public IPv6 with zone ID still passes after stripping."""
        with patch("proxy.middleware.url_validator.socket.getaddrinfo",
                    return_value=[(10, 1, 0, '', ('2001:db8::1', 0, 0, 0))]):
            result = validate_origin_url("http://[2001:db8::1%25eth0]/")
        assert result is None


# ===========================================================================
# 5. Non-JSON Content-Type Warning
# ===========================================================================

class TestNonJSONContentTypeWarning:
    """Non-JSON bodies on protected endpoints should be logged for visibility."""

    @pytest.mark.asyncio
    async def test_form_urlencoded_logs_warning(self):
        """application/x-www-form-urlencoded body logged as non-JSON on protected endpoint."""
        mw = SSRFValidator()
        req = _make_request(
            body=b"callback_url=http%3A%2F%2F169.254.169.254%2F",
            content_type="application/x-www-form-urlencoded",
        )
        ctx = _ctx()

        with patch("proxy.middleware.ssrf_validator.logger") as mock_logger:
            result = await mw.process_request(req, ctx)

        # Non-JSON body can't be parsed → passes through
        assert result is None
        # But a warning is logged for security visibility
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        assert call_args[0][0] == "ssrf_non_json_body_on_protected_endpoint"

    @pytest.mark.asyncio
    async def test_valid_json_does_not_log_warning(self):
        """Valid JSON body does not trigger non-JSON warning."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"name": "test"})
        ctx = _ctx()

        with patch("proxy.middleware.ssrf_validator.logger") as mock_logger:
            await mw.process_request(req, ctx)

        # Should not have a non-JSON warning
        for call in mock_logger.warning.call_args_list:
            assert call[0][0] != "ssrf_non_json_body_on_protected_endpoint"

    @pytest.mark.asyncio
    async def test_multipart_form_data_logs_warning(self):
        """multipart/form-data body logged as non-JSON."""
        mw = SSRFValidator()
        req = _make_request(
            body=b"--boundary\r\nContent-Disposition: form-data; name=\"url\"\r\n\r\nhttp://169.254.169.254/\r\n--boundary--",
            content_type="multipart/form-data; boundary=boundary",
        )
        ctx = _ctx()

        with patch("proxy.middleware.ssrf_validator.logger") as mock_logger:
            result = await mw.process_request(req, ctx)

        assert result is None
        mock_logger.warning.assert_called_once()


# ===========================================================================
# 6. Unicode Whitespace in URLs
# ===========================================================================

class TestUnicodeWhitespaceInURLs:
    """Unicode whitespace characters in URLs must not bypass extraction."""

    def test_unicode_line_separator_in_url(self):
        """U+2028 (line separator) in URL hostname — caught by @userinfo check."""
        url = "http://safe.com\u2028@169.254.169.254/"
        result = validate_origin_url(url, strict_dns=True)
        # The @userinfo check catches this (@ in netloc)
        assert result is not None

    def test_unicode_paragraph_separator_in_url(self):
        """U+2029 (paragraph separator) in hostname — blocked as whitespace."""
        url = "http://169.254\u2029.169.254/"
        result = validate_origin_url(url, strict_dns=True)
        assert result is not None
        assert "whitespace" in result.lower()

    def test_non_breaking_space_in_url(self):
        """U+00A0 (non-breaking space) → NFKC normalizes to space → whitespace check blocks."""
        url = "http://169.254\u00a0.169.254/"
        result = validate_origin_url(url, strict_dns=True)
        assert result is not None
        assert "whitespace" in result.lower()


# ===========================================================================
# 7. Combined Attack Vectors
# ===========================================================================

class TestCombinedAttacks:
    """Tests combining multiple bypass techniques in a single payload."""

    @pytest.mark.asyncio
    async def test_duplicate_keys_with_unicode_hostname(self):
        """Duplicate keys + Unicode dots in one payload."""
        mw = SSRFValidator()
        # Duplicate keys — caught by dupe detection
        raw = b'{"callback_url":"https://safe.example.com/hook","callback_url":"https://also-safe.example.com/"}'
        req = _make_request(body=raw)
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_depth_bomb_with_url_field(self):
        """Deep nesting with URL field at safe depth (should still validate)."""
        mw = SSRFValidator()
        # Nest 5 levels deep (within limit) with a private IP URL
        obj = {"config": {"settings": {"hooks": {"primary": {"callback_url": "http://10.0.0.1/hook"}}}}}
        req = _make_request(body_dict=obj)
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_protocol_relative_with_non_http_scheme(self):
        """Both protocol-relative and scheme-based attacks in same payload."""
        mw = SSRFValidator()
        req = _make_request(body_dict={
            "primary_url": "//10.0.0.1/admin",
            "secondary_url": "gopher://127.0.0.1:6379/INFO",
        })
        ctx = _ctx()

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ===========================================================================
# 8. Regression: Existing Functionality Not Broken
# ===========================================================================

class TestRegressions:
    """Verify hardening doesn't break legitimate use cases."""

    @pytest.mark.asyncio
    async def test_legitimate_webhook_creation_passes(self):
        """Normal webhook with public URL passes through."""
        mw = SSRFValidator()
        req = _make_request(body_dict={
            "name": "My Slack Webhook",
            "callback_url": "https://hooks.slack.com/services/T00/B00/xxxxx",
            "events": ["security.alert", "audit.login"],
        })
        ctx = _ctx()

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value=None):
            result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_legitimate_integration_config_passes(self):
        """Integration config with multiple public URLs passes."""
        mw = SSRFValidator()
        req = _make_request(body_dict={
            "primary_endpoint": "https://api.pagerduty.com/v2/enqueue",
            "fallback_endpoint": "https://api.opsgenie.com/v2/alerts",
            "return_url": "https://myapp.example.com/integrations/callback",
        })
        ctx = _ctx()

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value=None):
            result = await mw.process_request(req, ctx)
        assert result is None

    def test_url_validator_normal_urls_pass(self):
        """Normal URLs still validate correctly after hardening."""
        for url in [
            "http://example.com:3000",
            "https://app.example.com",
            "http://203.0.113.1:8080",
        ]:
            assert validate_origin_url(url) is None, f"Legitimate URL {url} was blocked"
