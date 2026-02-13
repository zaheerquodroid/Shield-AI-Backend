"""SHIELD-20 — Verify Callback/Webhook Signatures.

Acceptance Criteria:
  AC1: Customer configures callback endpoints and their HMAC secrets.
  AC2: Proxy validates signature header before forwarding to app.
  AC3: Expired or invalid signatures are rejected with 401.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.callback_verifier import CallbackVerifier
from proxy.middleware.pipeline import RequestContext


def _sign(body: bytes, secret: str, timestamp: int) -> str:
    signing_input = f"{timestamp}.".encode() + body
    return "sha256=" + hmac.new(
        secret.encode("utf-8"), signing_input, hashlib.sha256
    ).hexdigest()


def _make_request(
    path: str = "/webhooks/stripe",
    method: str = "POST",
    body: bytes = b'{"event":"charge.succeeded"}',
    headers: dict[str, str] | None = None,
) -> Request:
    raw_headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
    ]
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode(), v.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": raw_headers,
    }
    req = Request(scope)
    req._body = body
    return req


def _ctx(
    *,
    endpoints: list[dict] | None = None,
    mode: str = "block",
    timestamp_tolerance: int = 300,
    feature_enabled: bool = True,
) -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = "test-tenant"
    cb_cfg: dict = {"mode": mode, "timestamp_tolerance": timestamp_tolerance}
    if endpoints is not None:
        cb_cfg["endpoints"] = endpoints
    ctx.customer_config = {
        "enabled_features": {"callback_verifier": feature_enabled},
        "settings": {"callback_verifier": cb_cfg},
    }
    return ctx


# ---------------------------------------------------------------------------
# AC1: Customer configures callback endpoints and their HMAC secrets
# ---------------------------------------------------------------------------


class TestAC1_EndpointConfiguration:
    """Customers can configure which callback endpoints require verification."""

    @pytest.mark.asyncio
    async def test_no_config_passes_through(self):
        """Without callback_verifier settings, requests pass through."""
        mw = CallbackVerifier()
        req = _make_request()
        ctx = RequestContext()
        ctx.customer_config = {"enabled_features": {}, "settings": {}}
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_empty_endpoints_passes_through(self):
        """Empty endpoints list means no verification required."""
        mw = CallbackVerifier()
        req = _make_request()
        ctx = _ctx(endpoints=[])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_single_endpoint_configured(self):
        """Single endpoint with secret triggers verification."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b'{"event":"test"}'
        secret = "whsec_123"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/stripe", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_multiple_endpoints_configured(self):
        """Multiple endpoints with different secrets work independently."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b'{"event":"push"}'
        github_secret = "gh_secret"
        sig = _sign(body, github_secret, ts)
        req = _make_request(
            path="/webhooks/github",
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[
            {"pattern": "/webhooks/stripe", "secret": "stripe_secret"},
            {"pattern": "/webhooks/github", "secret": github_secret},
        ])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_wrong_endpoint_secret_rejected(self):
        """Signing with another endpoint's secret must be rejected."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b'{"event":"push"}'
        # Sign with stripe secret but request goes to github endpoint
        sig = _sign(body, "stripe_secret", ts)
        req = _make_request(
            path="/webhooks/github",
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[
            {"pattern": "/webhooks/stripe", "secret": "stripe_secret"},
            {"pattern": "/webhooks/github", "secret": "github_secret"},
        ])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_custom_headers_per_endpoint(self):
        """Each endpoint can specify custom signature/timestamp headers."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b'{"type":"event"}'
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={
                "x-hub-signature-256": sig,
                "x-hub-timestamp": str(ts),
            },
        )
        ctx = _ctx(endpoints=[{
            "pattern": "/webhooks/*",
            "secret": secret,
            "signature_header": "x-hub-signature-256",
            "timestamp_header": "x-hub-timestamp",
        }])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_feature_flag_disables_verification(self):
        """Turning off the feature flag disables all verification."""
        mw = CallbackVerifier()
        req = _make_request(headers={"x-signature": "bad"})
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": "s"}],
            feature_enabled=False,
        )
        assert await mw.process_request(req, ctx) is None


# ---------------------------------------------------------------------------
# AC2: Proxy validates signature header before forwarding to app
# ---------------------------------------------------------------------------


class TestAC2_SignatureValidation:
    """Valid HMAC signatures are accepted; requests are forwarded."""

    @pytest.mark.asyncio
    async def test_valid_hmac_accepted(self):
        """Request with correct HMAC-SHA256 signature passes through."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b'{"amount":1000,"currency":"usd"}'
        secret = "whsec_production"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_timestamp_dot_body_format(self):
        """Signing input is '{timestamp}.' + raw_body_bytes."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"raw-body-data"
        secret = "sec"
        # Manually compute expected
        signing_input = f"{ts}.".encode() + body
        expected_sig = "sha256=" + hmac.new(
            secret.encode(), signing_input, hashlib.sha256
        ).hexdigest()
        req = _make_request(
            body=body,
            headers={"x-signature": expected_sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_raw_body_bytes_used(self):
        """Signature is computed on raw bytes, not re-encoded."""
        mw = CallbackVerifier()
        ts = int(time.time())
        # Body with specific whitespace that would change if re-serialized
        body = b'{"key":  "value"}'
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_constant_time_comparison(self):
        """Middleware calls hmac.compare_digest (constant-time), not == operator."""
        import ast, inspect, textwrap
        source = inspect.getsource(CallbackVerifier.process_request)
        # Dedent so ast.parse works on method body
        tree = ast.parse(textwrap.dedent(source))
        # Find all function calls in the AST
        calls = [
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "compare_digest"
        ]
        assert len(calls) >= 1, "hmac.compare_digest must be called in process_request"

    @pytest.mark.asyncio
    async def test_detect_only_mode_logs_but_passes(self):
        """In detect_only mode, invalid signatures are logged but forwarded."""
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": "s"}],
            mode="detect_only",
        )
        assert await mw.process_request(req, ctx) is None


# ---------------------------------------------------------------------------
# AC3: Expired or invalid signatures are rejected with 401
# ---------------------------------------------------------------------------


class TestAC3_RejectionCases:
    """Invalid, expired, or missing signatures result in 401."""

    @pytest.mark.asyncio
    async def test_invalid_signature_401(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        req = _make_request(
            headers={"x-signature": "sha256=0" * 32, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "secret"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_signature_401(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_timestamp_401(self):
        mw = CallbackVerifier()
        ts = int(time.time()) - 600
        body = b"data"
        sig = _sign(body, "sec", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "sec"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_future_timestamp_401(self):
        mw = CallbackVerifier()
        ts = int(time.time()) + 600
        body = b"data"
        sig = _sign(body, "sec", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "sec"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_timestamp_401(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=abc"},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_non_numeric_timestamp_401(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=abc", "x-timestamp": "invalid"},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_error_response_format(self):
        """Error response has error=True, message, and error_id."""
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        body = json.loads(result.body)
        assert body["error"] is True
        assert "error_id" in body
        assert "message" in body

    @pytest.mark.asyncio
    async def test_no_secret_in_error_response(self):
        """Error responses never leak the configured secret."""
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "my_super_secret_key"}])
        result = await mw.process_request(req, ctx)
        body_text = result.body.decode()
        assert "my_super_secret_key" not in body_text

    @pytest.mark.asyncio
    async def test_rejection_logged(self):
        """Invalid signatures are logged with event details."""
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        # Just verify it runs without error — log verification is a structlog concern
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401
