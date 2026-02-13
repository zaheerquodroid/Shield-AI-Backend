"""SHIELD-19 — SSRF Validator Middleware.

Acceptance Criteria:
  AC1: Customer configures which endpoints contain URL fields (webhooks, integrations, callbacks).
  AC2: URL fields are parsed and resolved; private IPs, loopback, link-local, and metadata IPs are rejected.
  AC3: Configurable allowlist for known-good internal URLs.
  AC4: Blocked SSRF attempts are logged.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response
from starlette.testclient import TestClient

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.ssrf_validator import SSRFValidator


def _make_request(path: str = "/api/webhooks", method: str = "POST", body: dict | None = None) -> Request:
    """Build a fake Starlette request with JSON body."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
    }
    req = Request(scope)
    raw = json.dumps(body or {}).encode()
    req._body = raw
    return req


def _make_context(
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
    ssrf_cfg: dict = {"mode": mode, "scan_all_fields": scan_all_fields}
    if protected_endpoints is not None:
        ssrf_cfg["protected_endpoints"] = protected_endpoints
    if url_field_patterns is not None:
        ssrf_cfg["url_field_patterns"] = url_field_patterns
    if allowlist is not None:
        ssrf_cfg["allowlist"] = allowlist
    ctx.customer_config = {
        "enabled_features": {"ssrf_validator": feature_enabled},
        "settings": {"ssrf": ssrf_cfg},
    }
    return ctx


# ---------------------------------------------------------------------------
# AC1: Customer configures which endpoints contain URL fields
# ---------------------------------------------------------------------------

class TestAC1_EndpointConfiguration:
    """Only configured endpoint patterns are scanned for SSRF."""

    @pytest.mark.asyncio
    async def test_empty_protected_endpoints_disables_scanning(self):
        """No protected endpoints configured = middleware passes through."""
        mw = SSRFValidator()
        req = _make_request(body={"url": "http://169.254.169.254/latest/meta-data/"})
        ctx = _make_context(protected_endpoints=[])

        result = await mw.process_request(req, ctx)
        assert result is None  # No scanning

    @pytest.mark.asyncio
    async def test_matching_endpoint_is_scanned(self):
        """Request to a configured endpoint pattern is scanned."""
        mw = SSRFValidator()
        req = _make_request(
            path="/api/webhooks",
            body={"callback_url": "http://169.254.169.254/latest/meta-data/"},
        )
        ctx = _make_context(protected_endpoints=["/api/webhooks"])

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked private/reserved IP"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_non_matching_endpoint_is_skipped(self):
        """Request to a non-configured endpoint passes through."""
        mw = SSRFValidator()
        req = _make_request(
            path="/api/users",
            body={"callback_url": "http://169.254.169.254/"},
        )
        ctx = _make_context(protected_endpoints=["/api/webhooks"])

        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_fnmatch_wildcard_patterns(self):
        """Endpoint patterns support fnmatch wildcards."""
        mw = SSRFValidator()
        req = _make_request(
            path="/api/v2/integrations/slack",
            body={"webhook_url": "http://10.0.0.1/hook"},
        )
        ctx = _make_context(protected_endpoints=["/api/*/integrations/*"])

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ---------------------------------------------------------------------------
# AC2: Private IPs, loopback, link-local, and metadata IPs rejected
# ---------------------------------------------------------------------------

class TestAC2_PrivateIPRejection:
    """SSRF-dangerous URLs are rejected."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
    ])
    async def test_private_ips_blocked(self, ip: str):
        """Private/reserved IPs are blocked."""
        mw = SSRFValidator()
        req = _make_request(body={"callback_url": f"http://{ip}/path"})
        ctx = _make_context(protected_endpoints=["/api/*"])

        # Use real validate_origin_url for integration test
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_ipv4_mapped_ipv6_blocked(self):
        """IPv4-mapped IPv6 addresses are normalized and blocked."""
        mw = SSRFValidator()
        req = _make_request(body={"target_url": "http://[::ffff:127.0.0.1]/path"})
        ctx = _make_context(protected_endpoints=["/api/*"])

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_userinfo_url_blocked(self):
        """URLs with @userinfo are blocked (parser confusion attack)."""
        mw = SSRFValidator()
        req = _make_request(body={"redirect_url": "http://public.com@169.254.169.254/"})
        ctx = _make_context(protected_endpoints=["/api/*"])

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_public_url_allowed(self):
        """Public URLs pass validation."""
        mw = SSRFValidator()
        req = _make_request(body={"callback_url": "https://hooks.example.com/webhook"})
        ctx = _make_context(protected_endpoints=["/api/*"])

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value=None):
            result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_dns_resolving_to_private_blocked(self):
        """Hostnames that resolve to private IPs are blocked."""
        mw = SSRFValidator()
        req = _make_request(body={"endpoint_url": "http://evil.example.com/steal"})
        ctx = _make_context(protected_endpoints=["/api/*"])

        with patch(
            "proxy.middleware.ssrf_validator.validate_origin_url",
            return_value="Hostname 'evil.example.com' resolves to blocked IP",
        ):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400


# ---------------------------------------------------------------------------
# AC3: Configurable allowlist for known-good internal URLs
# ---------------------------------------------------------------------------

class TestAC3_Allowlist:
    """Allowlisted URLs bypass SSRF validation."""

    @pytest.mark.asyncio
    async def test_allowlisted_url_passes(self):
        """URLs matching allowlist patterns are not validated."""
        mw = SSRFValidator()
        req = _make_request(body={"callback_url": "http://10.0.0.5/internal-hook"})
        ctx = _make_context(
            protected_endpoints=["/api/*"],
            allowlist=["http://10.0.0.5/*"],
        )

        result = await mw.process_request(req, ctx)
        assert result is None  # Allowlisted, so no block

    @pytest.mark.asyncio
    async def test_non_allowlisted_private_still_blocked(self):
        """Private URLs NOT in allowlist are still blocked."""
        mw = SSRFValidator()
        req = _make_request(body={"callback_url": "http://10.0.0.99/evil"})
        ctx = _make_context(
            protected_endpoints=["/api/*"],
            allowlist=["http://10.0.0.5/*"],
        )

        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_allowlist_fnmatch_pattern(self):
        """Allowlist supports fnmatch wildcard patterns."""
        mw = SSRFValidator()
        req = _make_request(body={"webhook_url": "http://192.168.1.100/api/v2/hooks"})
        ctx = _make_context(
            protected_endpoints=["/api/*"],
            allowlist=["http://192.168.1.*"],
        )

        result = await mw.process_request(req, ctx)
        assert result is None


# ---------------------------------------------------------------------------
# AC4: Blocked SSRF attempts are logged
# ---------------------------------------------------------------------------

class TestAC4_Logging:
    """Blocked SSRF attempts produce structured log entries."""

    @pytest.mark.asyncio
    async def test_block_mode_logs_warning(self):
        """Blocked SSRF in block mode produces a warning log."""
        mw = SSRFValidator()
        req = _make_request(body={"callback_url": "http://169.254.169.254/metadata"})
        ctx = _make_context(protected_endpoints=["/api/*"], mode="block")

        with patch("proxy.middleware.ssrf_validator.logger") as mock_logger:
            with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
                result = await mw.process_request(req, ctx)

            assert isinstance(result, Response)
            mock_logger.warning.assert_called_once()
            call_kwargs = mock_logger.warning.call_args
            assert call_kwargs[0][0] == "ssrf_attempt_detected"
            assert call_kwargs[1]["mode"] == "block"
            assert call_kwargs[1]["request_id"] == ctx.request_id
            assert call_kwargs[1]["tenant_id"] == "test-tenant"

    @pytest.mark.asyncio
    async def test_detect_only_logs_but_passes(self):
        """detect_only mode logs the SSRF attempt but allows the request through."""
        mw = SSRFValidator()
        req = _make_request(body={"callback_url": "http://169.254.169.254/metadata"})
        ctx = _make_context(protected_endpoints=["/api/*"], mode="detect_only")

        with patch("proxy.middleware.ssrf_validator.logger") as mock_logger:
            with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
                result = await mw.process_request(req, ctx)

            assert result is None  # Allowed through
            mock_logger.warning.assert_called_once()
            call_kwargs = mock_logger.warning.call_args
            assert call_kwargs[1]["mode"] == "detect_only"

    @pytest.mark.asyncio
    async def test_error_response_has_error_id_no_url(self):
        """Error response includes error_id but does NOT echo blocked URLs."""
        mw = SSRFValidator()
        req = _make_request(body={"callback_url": "http://169.254.169.254/secret"})
        ctx = _make_context(protected_endpoints=["/api/*"], mode="block")

        with patch("proxy.middleware.ssrf_validator.validate_origin_url", return_value="Blocked"):
            result = await mw.process_request(req, ctx)

        body = json.loads(result.body)
        assert "error_id" in body
        assert "169.254" not in body["message"]
        assert "169.254" not in json.dumps(body)
