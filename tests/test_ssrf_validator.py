"""Unit tests for proxy.middleware.ssrf_validator."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.ssrf_validator import SSRFValidator


def _make_request(
    path: str = "/api/webhooks",
    method: str = "POST",
    body: bytes | None = None,
    body_dict: dict | list | None = None,
) -> Request:
    """Build a fake Starlette request."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
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
    url_field_patterns: list[str] | None = None,
    allowlist: list[str] | None = None,
    mode: str = "block",
    scan_all_fields: bool = False,
    feature_enabled: bool = True,
) -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = "test-tenant"
    ssrf: dict = {"mode": mode, "scan_all_fields": scan_all_fields}
    if protected_endpoints is not None:
        ssrf["protected_endpoints"] = protected_endpoints
    if url_field_patterns is not None:
        ssrf["url_field_patterns"] = url_field_patterns
    if allowlist is not None:
        ssrf["allowlist"] = allowlist
    ctx.customer_config = {
        "enabled_features": {"ssrf_validator": feature_enabled},
        "settings": {"ssrf": ssrf},
    }
    return ctx


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------

class TestFeatureFlag:

    @pytest.mark.asyncio
    async def test_feature_flag_off_passes_through(self):
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://169.254.169.254/"})
        ctx = _ctx(protected_endpoints=["/api/*"], feature_enabled=False)
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_feature_flag_on_validates(self):
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://169.254.169.254/"})
        ctx = _ctx(protected_endpoints=["/api/*"], feature_enabled=True)
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ---------------------------------------------------------------------------
# Method filtering
# ---------------------------------------------------------------------------

class TestMethodFiltering:

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method", ["GET", "DELETE", "HEAD", "OPTIONS"])
    async def test_non_body_methods_pass_through(self, method: str):
        mw = SSRFValidator()
        req = _make_request(method=method, body_dict={"callback_url": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/*"])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
    async def test_body_methods_are_scanned(self, method: str):
        mw = SSRFValidator()
        req = _make_request(method=method, body_dict={"callback_url": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/*"])
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------

class TestPathMatching:

    @pytest.mark.asyncio
    async def test_exact_path_match(self):
        mw = SSRFValidator()
        req = _make_request(path="/api/webhooks", body_dict={"url": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/webhooks"])
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)

    @pytest.mark.asyncio
    async def test_wildcard_path_match(self):
        mw = SSRFValidator()
        req = _make_request(path="/api/v2/hooks/create", body_dict={"url": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/*/hooks/*"])
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)

    @pytest.mark.asyncio
    async def test_no_match_passes_through(self):
        mw = SSRFValidator()
        req = _make_request(path="/api/users", body_dict={"url": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/webhooks"])
        assert await mw.process_request(req, ctx) is None


# ---------------------------------------------------------------------------
# Field name matching
# ---------------------------------------------------------------------------

class TestFieldNameMatching:

    @pytest.mark.asyncio
    async def test_default_patterns_match_url_fields(self):
        """Default patterns match common URL field names."""
        mw = SSRFValidator()
        for field_name in ["callback_url", "webhook_endpoint", "redirect_uri", "target_link", "dest_href"]:
            req = _make_request(body_dict={field_name: "http://10.0.0.1/"})
            ctx = _ctx(protected_endpoints=["/api/*"])
            with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
                result = await mw.process_request(req, ctx)
            assert isinstance(result, Response), f"Field {field_name} should be scanned"

    @pytest.mark.asyncio
    async def test_non_url_field_names_ignored(self):
        """Fields with non-URL names are skipped."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"name": "http://10.0.0.1/", "description": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/*"])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_custom_field_patterns(self):
        """Custom url_field_patterns override defaults."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"my_custom_field": "http://10.0.0.1/"})
        ctx = _ctx(
            protected_endpoints=["/api/*"],
            url_field_patterns=["my_custom_*"],
        )
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)

    @pytest.mark.asyncio
    async def test_scan_all_fields_overrides_patterns(self):
        """scan_all_fields=True scans all string fields regardless of name."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"description": "Visit http://10.0.0.1/ now"})
        ctx = _ctx(protected_endpoints=["/api/*"], scan_all_fields=True)
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

class TestURLExtraction:

    @pytest.mark.asyncio
    async def test_multiple_urls_in_one_field(self):
        """Multiple URLs in a single field value are all checked."""
        mw = SSRFValidator()
        req = _make_request(
            body_dict={"callback_url": "primary: http://example.com/ok secondary: http://10.0.0.1/evil"},
        )
        ctx = _ctx(protected_endpoints=["/api/*"])
        with patch(
            "proxy.middleware.ssrf_validator.validate_origin_url",
            side_effect=lambda url, **kw: "Blocked" if "10.0.0.1" in url else None,
        ):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_no_url_in_field_passes(self):
        """Fields with no URLs pass through."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "just a plain string"})
        ctx = _ctx(protected_endpoints=["/api/*"])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_nested_url_fields(self):
        """URLs in nested objects are extracted and validated."""
        mw = SSRFValidator()
        req = _make_request(body_dict={
            "config": {"webhook_url": "http://10.0.0.1/hook"},
        })
        ctx = _ctx(protected_endpoints=["/api/*"])
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)


# ---------------------------------------------------------------------------
# Block mode vs detect_only
# ---------------------------------------------------------------------------

class TestModes:

    @pytest.mark.asyncio
    async def test_block_mode_returns_400(self):
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/*"], mode="block")
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_detect_only_returns_none(self):
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/*"], mode="detect_only")
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert result is None


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

class TestAllowlist:

    @pytest.mark.asyncio
    async def test_allowlisted_url_skipped(self):
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://10.0.0.5/internal"})
        ctx = _ctx(
            protected_endpoints=["/api/*"],
            allowlist=["http://10.0.0.5/*"],
        )
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_partial_allowlist_still_blocks_others(self):
        """If one URL is allowlisted but another isn't, the non-allowlisted one is still blocked."""
        mw = SSRFValidator()
        req = _make_request(body_dict={
            "primary_url": "http://10.0.0.5/ok",
            "secondary_url": "http://10.0.0.99/bad",
        })
        ctx = _ctx(
            protected_endpoints=["/api/*"],
            allowlist=["http://10.0.0.5/*"],
        )
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    @pytest.mark.asyncio
    async def test_empty_body(self):
        mw = SSRFValidator()
        req = _make_request(body=b"")
        ctx = _ctx(protected_endpoints=["/api/*"])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_non_json_body(self):
        mw = SSRFValidator()
        req = _make_request(body=b"not json at all")
        ctx = _ctx(protected_endpoints=["/api/*"])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_json_array_body(self):
        """JSON array bodies are handled (extract_string_fields supports lists)."""
        mw = SSRFValidator()
        req = _make_request(body=json.dumps([{"callback_url": "http://10.0.0.1/"}]).encode())
        ctx = _ctx(protected_endpoints=["/api/*"])
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_json_scalar_body(self):
        """JSON scalar (string/number) body passes through."""
        mw = SSRFValidator()
        req = _make_request(body=b'"just a string"')
        ctx = _ctx(protected_endpoints=["/api/*"])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_no_url_fields_in_body(self):
        """Body with no URL-matching field names passes through."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"name": "Alice", "age": "30"})
        ctx = _ctx(protected_endpoints=["/api/*"])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_error_response_has_error_id(self):
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://10.0.0.1/"})
        ctx = _ctx(protected_endpoints=["/api/*"], mode="block")
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        body = json.loads(result.body)
        assert "error_id" in body
        assert len(body["error_id"]) == 8

    @pytest.mark.asyncio
    async def test_error_response_does_not_echo_url(self):
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://169.254.169.254/secret"})
        ctx = _ctx(protected_endpoints=["/api/*"], mode="block")
        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        raw = result.body.decode()
        assert "169.254.169.254" not in raw
        assert "/secret" not in raw

    @pytest.mark.asyncio
    async def test_middleware_name_property(self):
        mw = SSRFValidator()
        assert mw.name == "SSRFValidator"

    @pytest.mark.asyncio
    async def test_default_config_no_ssrf_section(self):
        """Missing ssrf config section treated as empty protected_endpoints."""
        mw = SSRFValidator()
        req = _make_request(body_dict={"callback_url": "http://10.0.0.1/"})
        ctx = RequestContext()
        ctx.customer_config = {"enabled_features": {"ssrf_validator": True}, "settings": {}}
        assert await mw.process_request(req, ctx) is None
