"""SHIELD-16 — Inject security headers into all responses.

Acceptance Criteria:
  AC1: All responses include: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
       Referrer-Policy, Permissions-Policy.
  AC2: Customer can choose preset modes: Strict, Balanced, Permissive.
  AC3: Customer can customize individual headers via dashboard (CSP overrides).
  AC4: Server and X-Powered-By headers are stripped from upstream responses.
  AC5: CSP builder merges customer's app-specific CSP needs with security defaults.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from starlette.responses import Response

from proxy.middleware.csp_builder import build_csp, merge_csp, parse_csp
from proxy.middleware.pipeline import RequestContext
from proxy.middleware.security_headers import SecurityHeaders, reset_presets_cache


# Required security headers per AC1
REQUIRED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _make_context(
    preset: str = "balanced",
    security_headers: bool = True,
    csp_override: str = "",
) -> RequestContext:
    """Build a RequestContext with customer config."""
    ctx = RequestContext()
    ctx.customer_config = {
        "enabled_features": {"security_headers": security_headers},
        "settings": {"header_preset": preset},
    }
    if csp_override:
        ctx.customer_config["settings"]["csp_override"] = csp_override
    return ctx


@pytest.fixture(autouse=True)
def _reset_preset_cache():
    """Ensure fresh preset loading for each test."""
    reset_presets_cache()
    yield
    reset_presets_cache()


# ---------------------------------------------------------------------------
# AC1: All responses include required security headers
# ---------------------------------------------------------------------------


class TestAC1_AllSecurityHeaders:
    """All responses include HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy."""

    @pytest.mark.asyncio
    async def test_balanced_preset_includes_all_required_headers(self):
        """Balanced preset adds all 6 required security headers."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="balanced")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)

        for header in REQUIRED_HEADERS:
            assert header in resp.headers, f"Missing header: {header}"

    @pytest.mark.asyncio
    async def test_strict_preset_includes_all_required_headers(self):
        """Strict preset adds all 6 required security headers."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="strict")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)

        for header in REQUIRED_HEADERS:
            assert header in resp.headers, f"Missing header: {header}"

    @pytest.mark.asyncio
    async def test_permissive_preset_includes_all_required_headers(self):
        """Permissive preset adds all 6 required security headers."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="permissive")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)

        for header in REQUIRED_HEADERS:
            assert header in resp.headers, f"Missing header: {header}"

    @pytest.mark.asyncio
    async def test_headers_added_to_error_responses(self):
        """Security headers are added even to 4xx/5xx responses."""
        mw = SecurityHeaders()
        ctx = _make_context()

        for status in [400, 403, 404, 500, 502]:
            resp = Response(content="error", status_code=status)
            resp = await mw.process_response(resp, ctx)
            for header in REQUIRED_HEADERS:
                assert header in resp.headers, f"Missing {header} on {status}"

    @pytest.mark.asyncio
    async def test_xss_protection_header_included(self):
        """X-XSS-Protection header is also included."""
        mw = SecurityHeaders()
        ctx = _make_context()
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        assert resp.headers["x-xss-protection"] == "1; mode=block"


# ---------------------------------------------------------------------------
# AC2: Customer can choose preset modes (Strict, Balanced, Permissive)
# ---------------------------------------------------------------------------


class TestAC2_PresetModes:
    """Customer can choose Strict, Balanced, or Permissive preset."""

    @pytest.mark.asyncio
    async def test_strict_hsts_includes_preload(self):
        """Strict preset HSTS includes preload and 2-year max-age."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="strict")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        hsts = resp.headers["strict-transport-security"]
        assert "preload" in hsts
        assert "63072000" in hsts

    @pytest.mark.asyncio
    async def test_strict_x_frame_options_deny(self):
        """Strict preset uses DENY for X-Frame-Options (no framing allowed)."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="strict")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        assert resp.headers["x-frame-options"] == "DENY"

    @pytest.mark.asyncio
    async def test_strict_referrer_policy_no_referrer(self):
        """Strict preset uses no-referrer."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="strict")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        assert resp.headers["referrer-policy"] == "no-referrer"

    @pytest.mark.asyncio
    async def test_strict_csp_self_only(self):
        """Strict CSP only allows 'self' — no unsafe-inline/eval."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="strict")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        csp = resp.headers["content-security-policy"]
        assert "'self'" in csp  # 'self' must be present
        assert "'unsafe-inline'" not in csp
        assert "'unsafe-eval'" not in csp

    @pytest.mark.asyncio
    async def test_balanced_x_frame_options_sameorigin(self):
        """Balanced preset uses SAMEORIGIN (allows same-site framing)."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="balanced")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        assert resp.headers["x-frame-options"] == "SAMEORIGIN"

    @pytest.mark.asyncio
    async def test_balanced_hsts_one_year(self):
        """Balanced HSTS uses 1-year max-age (31536000)."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="balanced")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        assert "31536000" in resp.headers["strict-transport-security"]

    @pytest.mark.asyncio
    async def test_permissive_csp_allows_unsafe(self):
        """Permissive CSP allows unsafe-inline and unsafe-eval."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="permissive")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        csp = resp.headers["content-security-policy"]
        assert "'unsafe-inline'" in csp
        assert "'unsafe-eval'" in csp

    @pytest.mark.asyncio
    async def test_permissive_allows_wildcard_images(self):
        """Permissive CSP allows wildcard image sources."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="permissive")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        csp = resp.headers["content-security-policy"]
        parsed = parse_csp(csp)
        assert "*" in parsed.get("img-src", [])

    @pytest.mark.asyncio
    async def test_unknown_preset_falls_back_to_balanced(self):
        """Unknown preset name falls back to balanced."""
        mw = SecurityHeaders()
        ctx = _make_context(preset="nonexistent")
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        # Should get balanced headers (SAMEORIGIN, not DENY)
        assert resp.headers["x-frame-options"] == "SAMEORIGIN"


# ---------------------------------------------------------------------------
# AC3: Customer can customize individual headers (CSP overrides)
# ---------------------------------------------------------------------------


class TestAC3_CustomerCustomization:
    """Customer can customize headers, especially CSP overrides."""

    @pytest.mark.asyncio
    async def test_csp_override_adds_cdn(self):
        """Customer CSP override adds a CDN to script-src."""
        mw = SecurityHeaders()
        ctx = _make_context(
            preset="balanced",
            csp_override="script-src https://cdn.example.com",
        )
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        csp = resp.headers["content-security-policy"]
        assert "https://cdn.example.com" in csp

    @pytest.mark.asyncio
    async def test_csp_override_preserves_base(self):
        """CSP override merges with preset — doesn't replace."""
        mw = SecurityHeaders()
        ctx = _make_context(
            preset="balanced",
            csp_override="script-src https://cdn.example.com",
        )
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        csp = resp.headers["content-security-policy"]
        # Balanced base has 'self' and 'unsafe-inline' in script-src
        assert "'self'" in csp
        assert "https://cdn.example.com" in csp

    @pytest.mark.asyncio
    async def test_csp_override_adds_new_directive(self):
        """CSP override can add entirely new directives."""
        mw = SecurityHeaders()
        ctx = _make_context(
            preset="strict",
            csp_override="worker-src 'self' blob:",
        )
        resp = Response(content="ok", status_code=200)
        resp = await mw.process_response(resp, ctx)
        csp = resp.headers["content-security-policy"]
        assert "worker-src" in csp
        assert "blob:" in csp

    @pytest.mark.asyncio
    async def test_empty_csp_override_no_change(self):
        """Empty CSP override leaves CSP identical to no override."""
        mw = SecurityHeaders()
        ctx_no_override = _make_context(preset="balanced")
        # Manually set an empty csp_override to actually exercise the code path
        ctx_empty = _make_context(preset="balanced")
        ctx_empty.customer_config["settings"]["csp_override"] = ""

        resp1 = Response(content="ok", status_code=200)
        resp1 = await mw.process_response(resp1, ctx_no_override)

        resp2 = Response(content="ok", status_code=200)
        resp2 = await mw.process_response(resp2, ctx_empty)

        assert resp1.headers["content-security-policy"] == resp2.headers["content-security-policy"]
        # Verify the CSP is actually populated (not silently empty)
        assert len(resp1.headers["content-security-policy"]) > 20

    def test_headers_api_endpoint(self):
        """PUT /apps/{id}/headers writes preset into settings."""
        import proxy.main as main_module
        main_module._pipeline = None
        main_module._http_client = None

        from proxy.main import app

        aid = uuid4()
        mock_app = {"id": str(aid), "settings": {"rate_limits": {"auth_max": 50}}}
        mock_updated = {**mock_app, "settings": {"rate_limits": {"auth_max": 50}, "header_preset": "strict"}}

        with TestClient(app, raise_server_exceptions=False) as c:
            mock_update = AsyncMock(return_value=mock_updated)
            with (
                patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=mock_app),
                patch("proxy.api.config_routes.pg_store.update_app", mock_update),
            ):
                resp = c.put(
                    f"/api/config/apps/{aid}/headers",
                    json={"header_preset": "strict"},
                    headers={"Authorization": "Bearer test-api-key"},
                )
                assert resp.status_code == 200
                # Verify update_app received merged settings (existing rate_limits preserved)
                call_kwargs = mock_update.call_args
                settings_arg = call_kwargs.kwargs.get("settings") or call_kwargs[1].get("settings")
                assert settings_arg["header_preset"] == "strict"
                assert settings_arg["rate_limits"]["auth_max"] == 50  # preserved

    def test_headers_api_validates_preset(self):
        """PUT /apps/{id}/headers rejects invalid preset names."""
        import proxy.main as main_module
        main_module._pipeline = None
        main_module._http_client = None

        from proxy.main import app

        aid = uuid4()
        mock_app = {"id": str(aid), "settings": {}}

        with TestClient(app, raise_server_exceptions=False) as c:
            with patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=mock_app):
                resp = c.put(
                    f"/api/config/apps/{aid}/headers",
                    json={"header_preset": "invalid_preset"},
                    headers={"Authorization": "Bearer test-api-key"},
                )
            assert resp.status_code == 422


# ---------------------------------------------------------------------------
# AC4: Server and X-Powered-By stripped
# ---------------------------------------------------------------------------


class TestAC4_HeaderStripping:
    """Server and X-Powered-By headers are stripped from upstream responses."""

    @pytest.mark.asyncio
    async def test_server_header_stripped(self):
        """Server header from upstream is removed."""
        mw = SecurityHeaders()
        ctx = _make_context()
        resp = Response(content="ok", status_code=200, headers={"server": "nginx/1.24"})
        resp = await mw.process_response(resp, ctx)
        assert "server" not in resp.headers

    @pytest.mark.asyncio
    async def test_x_powered_by_stripped(self):
        """X-Powered-By header from upstream is removed."""
        mw = SecurityHeaders()
        ctx = _make_context()
        resp = Response(content="ok", status_code=200, headers={"x-powered-by": "Express"})
        resp = await mw.process_response(resp, ctx)
        assert "x-powered-by" not in resp.headers

    @pytest.mark.asyncio
    async def test_both_stripped_simultaneously(self):
        """Both Server and X-Powered-By are stripped in one pass."""
        mw = SecurityHeaders()
        ctx = _make_context()
        resp = Response(
            content="ok",
            status_code=200,
            headers={"server": "Apache", "x-powered-by": "PHP/8.2"},
        )
        resp = await mw.process_response(resp, ctx)
        assert "server" not in resp.headers
        assert "x-powered-by" not in resp.headers


# ---------------------------------------------------------------------------
# AC5: CSP builder merges customer CSP with security defaults
# ---------------------------------------------------------------------------


class TestAC5_CSPBuilder:
    """CSP builder merges customer app-specific CSP needs with preset defaults."""

    def test_parse_csp_string(self):
        """parse_csp correctly splits CSP string into directive dict."""
        result = parse_csp("default-src 'self'; script-src 'self' https:")
        assert result == {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https:"],
        }

    def test_merge_csp_adds_new_source(self):
        """merge_csp adds a new source to an existing directive."""
        base = {"script-src": ["'self'"]}
        override = {"script-src": ["https://cdn.example.com"]}
        result = merge_csp(base, override)
        assert result["script-src"] == ["'self'", "https://cdn.example.com"]

    def test_merge_csp_deduplicates(self):
        """merge_csp does not duplicate sources."""
        base = {"script-src": ["'self'", "https:"]}
        override = {"script-src": ["'self'", "https://cdn.example.com"]}
        result = merge_csp(base, override)
        assert result["script-src"].count("'self'") == 1

    def test_merge_csp_adds_new_directive(self):
        """merge_csp adds entirely new directives from override."""
        base = {"default-src": ["'self'"]}
        override = {"font-src": ["https://fonts.googleapis.com"]}
        result = merge_csp(base, override)
        assert "font-src" in result
        assert "default-src" in result

    def test_merge_csp_does_not_mutate_inputs(self):
        """merge_csp returns a new dict without modifying inputs."""
        base = {"script-src": ["'self'"]}
        override = {"script-src": ["https:"]}
        merge_csp(base, override)
        assert base == {"script-src": ["'self'"]}
        assert override == {"script-src": ["https:"]}

    def test_build_csp_roundtrip(self):
        """parse → build → parse roundtrip preserves structure."""
        original = "default-src 'self'; script-src 'self' https:; img-src * data:"
        parsed = parse_csp(original)
        rebuilt = build_csp(parsed)
        reparsed = parse_csp(rebuilt)
        assert parsed == reparsed

    def test_real_world_google_fonts_merge(self):
        """Customer adds Google Fonts to balanced preset — merges correctly."""
        balanced_csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' https:"
        customer_csp = "font-src https://fonts.googleapis.com; style-src https://fonts.googleapis.com"

        base = parse_csp(balanced_csp)
        override = parse_csp(customer_csp)
        merged = merge_csp(base, override)
        result = build_csp(merged)

        # Google Fonts URL should be in the merged result
        assert "https://fonts.googleapis.com" in result
        # Original sources preserved
        assert "'self'" in result

    @pytest.mark.asyncio
    async def test_feature_flag_off_skips_headers(self):
        """When security_headers=False, response is returned unmodified."""
        mw = SecurityHeaders()
        ctx = _make_context(security_headers=False)
        original_resp = Response(content="ok", status_code=200)
        result = await mw.process_response(original_resp, ctx)
        # Should be the exact same object (not a copy)
        assert result is original_resp
        for header in REQUIRED_HEADERS:
            assert header not in result.headers
        # Also verify Server/X-Powered-By are NOT stripped when flag is off
        resp_with_server = Response(content="ok", status_code=200, headers={"server": "nginx"})
        result2 = await mw.process_response(resp_with_server, ctx)
        assert result2.headers.get("server") == "nginx"
