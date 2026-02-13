"""Tests for security headers middleware."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.security_headers import SecurityHeaders, reset_presets_cache, _load_presets


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


# ── Preset application ──────────────────────────────────────────────────


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


class TestSecurityHeadersAllPresetValues:
    """Verify all headers for each preset match YAML values."""

    @pytest.mark.asyncio
    async def test_balanced_all_headers(self):
        """Balanced preset has all expected headers."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        assert result.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
        assert result.headers["x-frame-options"] == "SAMEORIGIN"
        assert result.headers["x-content-type-options"] == "nosniff"
        assert result.headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert result.headers["x-xss-protection"] == "1; mode=block"
        assert "permissions-policy" in result.headers
        assert "content-security-policy" in result.headers

    @pytest.mark.asyncio
    async def test_strict_all_headers(self):
        """Strict preset has all expected headers including COOP/CORP."""
        mw = SecurityHeaders()
        ctx = _make_context(header_preset="strict")
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        assert result.headers["referrer-policy"] == "no-referrer"
        assert result.headers["cross-origin-opener-policy"] == "same-origin"
        assert result.headers["cross-origin-resource-policy"] == "same-origin"
        assert "preload" in result.headers["strict-transport-security"]
        assert "63072000" in result.headers["strict-transport-security"]

    @pytest.mark.asyncio
    async def test_permissive_all_headers(self):
        """Permissive preset has all expected headers."""
        mw = SecurityHeaders()
        ctx = _make_context(header_preset="permissive")
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        assert result.headers["strict-transport-security"] == "max-age=31536000"
        assert result.headers["referrer-policy"] == "strict-origin-when-cross-origin"
        csp = result.headers["content-security-policy"]
        assert "'unsafe-inline'" in csp
        assert "'unsafe-eval'" in csp


# ── Header stripping ────────────────────────────────────────────────────


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

    @pytest.mark.asyncio
    async def test_strips_both_headers_together(self):
        """Both server and x-powered-by should be stripped in same response."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(
            content="ok",
            status_code=200,
            headers={"server": "Apache", "x-powered-by": "PHP/8.0"},
        )

        result = await mw.process_response(response, ctx)

        assert "server" not in result.headers
        assert "x-powered-by" not in result.headers


# ── CSP merging ──────────────────────────────────────────────────────────


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

    @pytest.mark.asyncio
    async def test_csp_override_multiple_directives(self):
        """CSP override with multiple directives are all merged."""
        mw = SecurityHeaders()
        ctx = _make_context(
            csp_override="script-src https://cdn.example.com; img-src https://images.example.com"
        )
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        csp = result.headers["content-security-policy"]
        assert "https://cdn.example.com" in csp
        assert "https://images.example.com" in csp

    @pytest.mark.asyncio
    async def test_csp_override_new_directive(self):
        """CSP override adding a new directive not in preset."""
        mw = SecurityHeaders()
        ctx = _make_context(csp_override="worker-src https://workers.example.com")
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        csp = result.headers["content-security-policy"]
        assert "worker-src https://workers.example.com" in csp

    @pytest.mark.asyncio
    async def test_csp_no_override_key_in_settings(self):
        """When csp_override key is missing from settings, preset CSP is used as-is."""
        mw = SecurityHeaders()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {
            "enabled_features": {"security_headers": True},
            "settings": {},  # no csp_override key
        }
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        assert "content-security-policy" in result.headers


# ── Feature flag ─────────────────────────────────────────────────────────


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

    @pytest.mark.asyncio
    async def test_missing_enabled_features_key(self):
        """Missing enabled_features defaults to headers enabled."""
        mw = SecurityHeaders()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {"settings": {}}  # no enabled_features key
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        assert "strict-transport-security" in result.headers

    @pytest.mark.asyncio
    async def test_missing_security_headers_flag(self):
        """Missing security_headers key in features defaults to True."""
        mw = SecurityHeaders()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {
            "enabled_features": {"waf": True},  # no security_headers key
            "settings": {},
        }
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        assert "strict-transport-security" in result.headers


# ── Error handling ───────────────────────────────────────────────────────


class TestSecurityHeadersErrorHandling:
    @pytest.mark.asyncio
    async def test_applied_to_error_responses(self):
        """Security headers should be applied even to error responses."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="Not Found", status_code=404)

        result = await mw.process_response(response, ctx)

        assert "strict-transport-security" in result.headers
        assert "x-content-type-options" in result.headers

    @pytest.mark.asyncio
    async def test_applied_to_500_responses(self):
        """Security headers should be applied to 500 error responses."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="Internal Error", status_code=500)

        result = await mw.process_response(response, ctx)

        assert "strict-transport-security" in result.headers

    @pytest.mark.asyncio
    async def test_exception_returns_original_response(self):
        """If _apply_headers raises, original response is returned."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="ok", status_code=200)

        with patch.object(mw, "_apply_headers", side_effect=RuntimeError("boom")):
            result = await mw.process_response(response, ctx)

        assert result.status_code == 200
        # Security headers NOT applied due to exception — just pass through
        assert "strict-transport-security" not in result.headers


# ── Preset fallback ─────────────────────────────────────────────────────


class TestSecurityHeadersPresetFallback:
    @pytest.mark.asyncio
    async def test_unknown_preset_falls_back_to_balanced(self):
        """Unknown preset name should fallback to balanced."""
        mw = SecurityHeaders()
        ctx = _make_context(header_preset="nonexistent")
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        # Should get balanced headers
        assert result.headers["x-frame-options"] == "SAMEORIGIN"
        assert "strict-transport-security" in result.headers

    @pytest.mark.asyncio
    async def test_missing_settings_key_uses_global_default(self):
        """When no header_preset in customer settings, global default is used."""
        mw = SecurityHeaders()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {
            "enabled_features": {"security_headers": True},
            "settings": {},  # no header_preset
        }
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)

        # Default from ProxySettings is "balanced"
        assert result.headers["x-frame-options"] == "SAMEORIGIN"


# ── YAML loading ─────────────────────────────────────────────────────────


class TestPresetsLoading:
    def test_presets_cache_persists(self):
        """Presets should be cached after first load."""
        reset_presets_cache()
        first = _load_presets()
        second = _load_presets()
        assert first is second  # same object reference (cached)

    def test_reset_clears_cache(self):
        """reset_presets_cache clears the cached presets."""
        _load_presets()
        reset_presets_cache()
        # After reset, next load should reload from file
        result = _load_presets()
        assert result is not None
        assert "balanced" in result

    def test_presets_have_three_profiles(self):
        """YAML should define exactly three profiles."""
        presets = _load_presets()
        assert "strict" in presets
        assert "balanced" in presets
        assert "permissive" in presets

    def test_missing_yaml_returns_empty(self):
        """If YAML file doesn't exist, returns empty dict."""
        reset_presets_cache()
        import proxy.middleware.security_headers as sh_module

        original = sh_module._PRESETS_PATH
        from pathlib import Path

        sh_module._PRESETS_PATH = Path("/nonexistent/presets.yaml")
        try:
            reset_presets_cache()
            result = _load_presets()
            assert result == {}
        finally:
            sh_module._PRESETS_PATH = original
            reset_presets_cache()


# ── process_request noop ─────────────────────────────────────────────────


class TestSecurityHeadersProcessRequest:
    @pytest.mark.asyncio
    async def test_process_request_returns_none(self):
        """process_request should always return None (noop)."""
        mw = SecurityHeaders()
        ctx = _make_context()
        result = await mw.process_request(_make_request(), ctx)
        assert result is None


# ── Idempotency ──────────────────────────────────────────────────────────


class TestSecurityHeadersIdempotency:
    @pytest.mark.asyncio
    async def test_double_apply_does_not_duplicate_headers(self):
        """Applying headers twice should not corrupt values."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(content="ok", status_code=200)

        result = await mw.process_response(response, ctx)
        result = await mw.process_response(result, ctx)

        # Headers should be set (overwritten), not duplicated
        assert result.headers["x-content-type-options"] == "nosniff"

    @pytest.mark.asyncio
    async def test_preset_headers_override_upstream_headers(self):
        """Preset headers should replace any existing upstream headers."""
        mw = SecurityHeaders()
        ctx = _make_context()
        response = Response(
            content="ok",
            status_code=200,
            headers={"x-frame-options": "ALLOW-FROM *"},
        )

        result = await mw.process_response(response, ctx)

        # Should be overwritten by balanced preset
        assert result.headers["x-frame-options"] == "SAMEORIGIN"
