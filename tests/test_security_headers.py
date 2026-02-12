"""Tests for security headers middleware."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.security_headers import SecurityHeaders, reset_presets_cache


def _make_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "root_path": "",
        "server": ("localhost", 8080),
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


def _make_context(
    security_headers: bool = True,
    header_preset: str | None = None,
    csp_override: str = "",
) -> RequestContext:
    ctx = RequestContext(tenant_id="tenant-1")
    settings: dict = {}
    if header_preset:
        settings["header_preset"] = header_preset
    if csp_override:
        settings["csp_override"] = csp_override
    ctx.customer_config = {
        "enabled_features": {"security_headers": security_headers},
        "settings": settings,
    }
    return ctx


@pytest.fixture(autouse=True)
def _reset_cache():
    reset_presets_cache()
    yield
    reset_presets_cache()


class TestSecurityHeadersPresets:
    @pytest.mark.asyncio
    async def test_balanced_preset_applied(self):
        """Default balanced preset should inject standard security headers."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        assert "strict-transport-security" in result.headers
        assert "content-security-policy" in result.headers
        assert "x-content-type-options" in result.headers
        assert result.headers["x-content-type-options"] == "nosniff"
        assert result.headers["x-frame-options"] == "SAMEORIGIN"

    @pytest.mark.asyncio
    async def test_strict_preset(self):
        """Strict preset should use DENY for X-Frame-Options."""
        mw = SecurityHeaders()
        ctx = _make_context(header_preset="strict")
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        assert result.headers["x-frame-options"] == "DENY"
        assert "preload" in result.headers["strict-transport-security"]

    @pytest.mark.asyncio
    async def test_permissive_preset(self):
        """Permissive preset should allow more sources."""
        mw = SecurityHeaders()
        ctx = _make_context(header_preset="permissive")
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        csp = result.headers["content-security-policy"]
        assert "'unsafe-eval'" in csp


class TestSecurityHeadersStripping:
    @pytest.mark.asyncio
    async def test_strips_server_header(self):
        """Server header should be stripped from upstream response."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="ok", status_code=200, headers={"server": "nginx/1.24"})

        result = await mw.process_response(response, ctx)

        assert "server" not in result.headers

    @pytest.mark.asyncio
    async def test_strips_x_powered_by(self):
        """X-Powered-By header should be stripped."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="ok", status_code=200, headers={"x-powered-by": "Express"})

        result = await mw.process_response(response, ctx)

        assert "x-powered-by" not in result.headers


class TestSecurityHeadersCspMerge:
    @pytest.mark.asyncio
    async def test_csp_override_merged(self):
        """Customer CSP override should be merged with preset."""
        mw = SecurityHeaders()
        ctx = _make_context(csp_override="script-src https://cdn.example.com")
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        csp = result.headers["content-security-policy"]
        assert "https://cdn.example.com" in csp
        assert "'self'" in csp  # base should still be there

    @pytest.mark.asyncio
    async def test_empty_csp_override(self):
        """Empty CSP override should leave preset CSP unchanged."""
        mw = SecurityHeaders()
        ctx = _make_context(csp_override="")
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        csp = result.headers["content-security-policy"]
        assert "'self'" in csp


class TestSecurityHeadersFeatureFlag:
    @pytest.mark.asyncio
    async def test_disabled_via_feature_flag(self):
        """When security_headers is disabled, headers should not be modified."""
        mw = SecurityHeaders()
        ctx = _make_context(security_headers=False)
        response = Response(content="ok", status_code=200, headers={"server": "nginx"})

        result = await mw.process_response(response, ctx)

        # Headers should be untouched
        assert "strict-transport-security" not in result.headers
        assert result.headers.get("server") == "nginx"


class TestSecurityHeadersErrorResponses:
    @pytest.mark.asyncio
    async def test_applied_to_error_responses(self):
        """Security headers should be applied even to error responses."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="Not Found", status_code=404)

        result = await mw.process_response(response, ctx)

        assert "strict-transport-security" in result.headers
        assert "x-content-type-options" in result.headers
