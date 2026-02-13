"""Unit tests for proxy.middleware.callback_verifier."""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.callback_verifier import CallbackVerifier
from proxy.middleware.pipeline import RequestContext


def _sign(body: bytes, secret: str, timestamp: int) -> str:
    """Compute expected HMAC-SHA256 signature."""
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
    """Build a fake Starlette request with optional headers."""
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
# Feature flag
# ---------------------------------------------------------------------------


class TestFeatureFlag:

    @pytest.mark.asyncio
    async def test_feature_flag_off_passes_through(self):
        """Bad sig + flag off → passes through (proves flag skips checking)."""
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": "secret123"}],
            feature_enabled=False,
        )
        # Would be 401 if flag was ignored — proves flag check works
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_feature_flag_on_validates(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": "secret123"}],
            feature_enabled=True,
        )
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_default_feature_flag_is_false(self):
        """Default config has callback_verifier disabled."""
        from proxy.config.customer_config import _DEFAULT_CONFIG

        assert _DEFAULT_CONFIG["enabled_features"]["callback_verifier"] is False


# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------


class TestPathMatching:

    @pytest.mark.asyncio
    async def test_exact_match(self):
        mw = CallbackVerifier()
        req = _make_request(
            path="/webhooks/stripe",
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/stripe", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result is not None and result.status_code == 401

    @pytest.mark.asyncio
    async def test_wildcard_match(self):
        mw = CallbackVerifier()
        req = _make_request(
            path="/webhooks/github/events",
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result is not None and result.status_code == 401

    @pytest.mark.asyncio
    async def test_no_match_passes_through(self):
        mw = CallbackVerifier()
        req = _make_request(path="/api/users")
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_empty_endpoints_passes_through(self):
        mw = CallbackVerifier()
        req = _make_request()
        ctx = _ctx(endpoints=[])
        assert await mw.process_request(req, ctx) is None


# ---------------------------------------------------------------------------
# Signature validation
# ---------------------------------------------------------------------------


class TestSignatureValidation:

    @pytest.mark.asyncio
    async def test_valid_signature_accepted(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b'{"event":"charge.succeeded"}'
        secret = "whsec_test123"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b'{"event":"charge.succeeded"}'
        req = _make_request(
            body=body,
            headers={"x-signature": "sha256=0000000000000000000000000000000000000000000000000000000000000000", "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "real_secret"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_signature_rejected(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_signature_rejected(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401


# ---------------------------------------------------------------------------
# Timestamp validation
# ---------------------------------------------------------------------------


class TestTimestampValidation:

    @pytest.mark.asyncio
    async def test_fresh_timestamp_accepted(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"hello"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_expired_timestamp_rejected(self):
        mw = CallbackVerifier()
        ts = int(time.time()) - 600  # 10 min ago
        body = b"hello"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_future_timestamp_rejected(self):
        mw = CallbackVerifier()
        ts = int(time.time()) + 600  # 10 min in future
        body = b"hello"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_custom_tolerance(self):
        mw = CallbackVerifier()
        ts = int(time.time()) - 60  # 1 min ago
        body = b"hello"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        # tolerance = 30s, so 60s ago should be rejected
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": secret}],
            timestamp_tolerance=30,
        )
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_boundary_timestamp_accepted(self):
        mw = CallbackVerifier()
        ts = int(time.time()) - 299  # just inside 300s tolerance
        body = b"hello"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_missing_timestamp_rejected(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=abc"},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_non_numeric_timestamp_rejected(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=abc", "x-timestamp": "not-a-number"},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401


# ---------------------------------------------------------------------------
# Custom headers
# ---------------------------------------------------------------------------


class TestCustomHeaders:

    @pytest.mark.asyncio
    async def test_custom_signature_header(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-hub-signature-256": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{
            "pattern": "/webhooks/*",
            "secret": secret,
            "signature_header": "x-hub-signature-256",
        }])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_custom_timestamp_header(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-webhook-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{
            "pattern": "/webhooks/*",
            "secret": secret,
            "timestamp_header": "x-webhook-timestamp",
        }])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_custom_sig_header_ignores_default(self):
        """Valid sig in DEFAULT header must be ignored when custom header is configured."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts)
        # Send valid sig in default x-signature but custom header is configured
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{
            "pattern": "/webhooks/*",
            "secret": secret,
            "signature_header": "x-hub-signature-256",
        }])
        # x-hub-signature-256 is missing → 401 (must NOT fall back to x-signature)
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_custom_ts_header_ignores_default(self):
        """Valid timestamp in DEFAULT header must be ignored when custom header is configured."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts)
        # Send valid ts in default x-timestamp but custom header is configured
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{
            "pattern": "/webhooks/*",
            "secret": secret,
            "timestamp_header": "x-custom-ts",
        }])
        # x-custom-ts is missing → 401 (must NOT fall back to x-timestamp)
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401


# ---------------------------------------------------------------------------
# Secret rotation
# ---------------------------------------------------------------------------


class TestSecretRotation:

    @pytest.mark.asyncio
    async def test_single_secret(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"payload"
        secret = "only-secret"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_secrets_list_first_match(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"payload"
        sig = _sign(body, "new-secret", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{
            "pattern": "/webhooks/*",
            "secrets": ["new-secret", "old-secret"],
        }])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_secrets_list_second_match(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"payload"
        sig = _sign(body, "old-secret", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{
            "pattern": "/webhooks/*",
            "secrets": ["new-secret", "old-secret"],
        }])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_no_secret_matches_rejected(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"payload"
        sig = _sign(body, "wrong-secret", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{
            "pattern": "/webhooks/*",
            "secrets": ["secret-a", "secret-b"],
        }])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------


class TestModes:

    @pytest.mark.asyncio
    async def test_block_mode_returns_401(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": "s"}],
            mode="block",
        )
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_detect_only_passes_through(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": "s"}],
            mode="detect_only",
        )
        result = await mw.process_request(req, ctx)
        assert result is None


# ---------------------------------------------------------------------------
# Error responses
# ---------------------------------------------------------------------------


class TestErrorResponses:

    @pytest.mark.asyncio
    async def test_error_has_error_id(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        import json
        body = json.loads(result.body)
        assert "error_id" in body
        assert len(body["error_id"]) == 8

    @pytest.mark.asyncio
    async def test_no_secret_leaked_in_response(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "supersecretkey"}])
        result = await mw.process_request(req, ctx)
        body_text = result.body.decode()
        assert "supersecretkey" not in body_text
        assert "sha256=" not in body_text

    @pytest.mark.asyncio
    async def test_generic_error_message(self):
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        import json
        body = json.loads(result.body)
        assert body["message"] == "Callback signature verification failed."


# ---------------------------------------------------------------------------
# Signing format test vector (independent of _sign helper)
# ---------------------------------------------------------------------------


class TestSigningFormatVector:
    """Pre-computed test vector — catches signing format bugs that mirror in
    both the _sign helper and middleware (e.g., missing '.' separator)."""

    VECTOR_BODY = b'{"event":"test"}'
    VECTOR_SECRET = "test-secret-123"
    VECTOR_TS = 1700000000
    # Pre-computed: HMAC-SHA256 of "1700000000.{\"event\":\"test\"}" with key "test-secret-123"
    VECTOR_SIG = "sha256=8529ce3cddf6279f6414ce27262464356290cc752c3c521cd5cf97fa38a85e91"

    @pytest.mark.asyncio
    async def test_known_good_signature_accepted(self):
        """Known pre-computed signature is accepted by middleware."""
        from unittest.mock import patch

        mw = CallbackVerifier()
        req = _make_request(
            body=self.VECTOR_BODY,
            headers={
                "x-signature": self.VECTOR_SIG,
                "x-timestamp": str(self.VECTOR_TS),
            },
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": self.VECTOR_SECRET}])
        # Freeze time so timestamp tolerance passes
        with patch("proxy.middleware.callback_verifier.time") as mock_time:
            mock_time.time.return_value = self.VECTOR_TS + 10
            result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_wrong_format_no_dot_rejected(self):
        """Signature computed WITHOUT '.' separator is rejected."""
        from unittest.mock import patch

        # Compute HMAC with "{ts}{body}" (missing dot) — wrong format
        signing_input = f"{self.VECTOR_TS}".encode() + self.VECTOR_BODY
        wrong_sig = "sha256=" + hmac.new(
            self.VECTOR_SECRET.encode(), signing_input, hashlib.sha256
        ).hexdigest()
        # Sanity: wrong format produces different sig
        assert wrong_sig != self.VECTOR_SIG

        mw = CallbackVerifier()
        req = _make_request(
            body=self.VECTOR_BODY,
            headers={
                "x-signature": wrong_sig,
                "x-timestamp": str(self.VECTOR_TS),
            },
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": self.VECTOR_SECRET}])
        with patch("proxy.middleware.callback_verifier.time") as mock_time:
            mock_time.time.return_value = self.VECTOR_TS + 10
            result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_signing_input_format_is_ts_dot_body(self):
        """Independently verify signing input = '{ts}.' + body."""
        expected_input = b"1700000000." + b'{"event":"test"}'
        expected_sig = "sha256=" + hmac.new(
            b"test-secret-123", expected_input, hashlib.sha256
        ).hexdigest()
        assert expected_sig == self.VECTOR_SIG


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:

    @pytest.mark.asyncio
    async def test_empty_body(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b""
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_binary_body(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = bytes(range(256))
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_get_request_on_protected_endpoint(self):
        """GET requests on protected endpoints are also verified."""
        mw = CallbackVerifier()
        req = _make_request(
            method="GET",
            headers={"x-signature": "sha256=bad", "x-timestamp": str(int(time.time()))},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_middleware_name(self):
        mw = CallbackVerifier()
        assert mw.name == "CallbackVerifier"

    @pytest.mark.asyncio
    async def test_multiple_endpoints_first_match_wins(self):
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"test"
        sig = _sign(body, "stripe-secret", ts)
        req = _make_request(
            path="/webhooks/stripe",
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[
            {"pattern": "/webhooks/stripe", "secret": "stripe-secret"},
            {"pattern": "/webhooks/*", "secret": "generic-secret"},
        ])
        # Should match first endpoint with stripe-secret
        assert await mw.process_request(req, ctx) is None


# ---------------------------------------------------------------------------
# Attack simulation tests (security hardening round 1)
# ---------------------------------------------------------------------------


class TestAttackEmptySecretBypass:
    """Attacker forges signature using empty-string HMAC key."""

    @pytest.mark.asyncio
    async def test_empty_string_secret_in_list_rejected(self):
        """secrets: [''] must not allow forged signatures."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b'{"event":"test"}'
        # Attacker computes HMAC with empty key
        forged_sig = _sign(body, "", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": forged_sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secrets": [""]}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_whitespace_only_secret_rejected(self):
        """secrets: ['  '] must not allow forged signatures."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        forged_sig = _sign(body, "  ", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": forged_sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secrets": ["  "]}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_single_secret_rejected(self):
        """secret: '' must not allow forged signatures."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        forged_sig = _sign(body, "", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": forged_sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": ""}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_mixed_empty_and_valid_secret_uses_valid(self):
        """secrets: ['', 'real'] filters empty but keeps real secret."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        sig = _sign(body, "real", ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secrets": ["", "real"]}])
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_non_string_secret_filtered(self):
        """Non-string secrets (int, None) are filtered out."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        req = _make_request(
            body=body,
            headers={"x-signature": "sha256=bad", "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secrets": [123, None, ""]}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401


class TestAttackReplayWindow:
    """Attacker replays valid signature with manipulated tolerance."""

    @pytest.mark.asyncio
    async def test_huge_tolerance_clamped_to_max(self):
        """tolerance: 999999999 is clamped to 3600s (1 hour)."""
        mw = CallbackVerifier()
        ts = int(time.time()) - 7200  # 2 hours ago
        body = b"replay"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": secret}],
            timestamp_tolerance=999999999,
        )
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_negative_tolerance_uses_default(self):
        """Negative tolerance falls back to 300s default."""
        mw = CallbackVerifier()
        ts = int(time.time()) - 200  # 200s ago, inside 300s default
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": secret}],
            timestamp_tolerance=-100,
        )
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_non_numeric_tolerance_uses_default(self):
        """Non-numeric tolerance falls back to 300s default."""
        mw = CallbackVerifier()
        ts = int(time.time()) - 200
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        # Manually construct context with non-numeric tolerance
        ctx = RequestContext()
        ctx.tenant_id = "test-tenant"
        ctx.customer_config = {
            "enabled_features": {"callback_verifier": True},
            "settings": {"callback_verifier": {
                "mode": "block",
                "timestamp_tolerance": "invalid",
                "endpoints": [{"pattern": "/webhooks/*", "secret": secret}],
            }},
        }
        assert await mw.process_request(req, ctx) is None

    @pytest.mark.asyncio
    async def test_within_clamped_max_accepted(self):
        """Timestamp 30 min ago accepted when tolerance set to huge value (clamped to 3600)."""
        mw = CallbackVerifier()
        ts = int(time.time()) - 1800  # 30 min ago — inside 3600s max
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(
            endpoints=[{"pattern": "/webhooks/*", "secret": secret}],
            timestamp_tolerance=999999999,
        )
        assert await mw.process_request(req, ctx) is None


class TestAttackNoSecretsConfigured:
    """Endpoint matched but customer forgot to configure secrets."""

    @pytest.mark.asyncio
    async def test_no_secret_key_at_all_rejected(self):
        """Endpoint with pattern but no secret/secrets → 401."""
        mw = CallbackVerifier()
        ts = int(time.time())
        req = _make_request(
            headers={"x-signature": "sha256=anything", "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_all_empty_secrets_list_rejected(self):
        """secrets: ['', '  ', ''] → all filtered → 401."""
        mw = CallbackVerifier()
        ts = int(time.time())
        req = _make_request(
            headers={"x-signature": "sha256=anything", "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secrets": ["", "  ", ""]}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401


class TestAttackTimestampManipulation:
    """Attacker manipulates timestamp to bypass checks."""

    @pytest.mark.asyncio
    async def test_negative_timestamp_rejected(self):
        mw = CallbackVerifier()
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, -1)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": "-1"},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_zero_timestamp_rejected(self):
        mw = CallbackVerifier()
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, 0)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": "0"},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_huge_future_timestamp_rejected(self):
        mw = CallbackVerifier()
        body = b"data"
        secret = "sec"
        huge_ts = 99999999999
        sig = _sign(body, secret, huge_ts)
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(huge_ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_float_timestamp_rejected(self):
        """Float like '1234.5' should be rejected (not int)."""
        mw = CallbackVerifier()
        req = _make_request(
            headers={"x-signature": "sha256=abc", "x-timestamp": "1234567890.5"},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": "s"}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401


class TestAttackSignatureFormatManipulation:
    """Attacker manipulates signature format."""

    @pytest.mark.asyncio
    async def test_missing_sha256_prefix_rejected(self):
        """Signature without 'sha256=' prefix doesn't match."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        secret = "sec"
        # Compute raw hex without prefix
        signing_input = f"{ts}.".encode() + body
        raw_hex = hmac.new(secret.encode(), signing_input, hashlib.sha256).hexdigest()
        req = _make_request(
            body=body,
            headers={"x-signature": raw_hex, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_prefix_rejected(self):
        """Signature with 'sha512=' prefix doesn't match expected 'sha256='."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        secret = "sec"
        signing_input = f"{ts}.".encode() + body
        raw_hex = hmac.new(secret.encode(), signing_input, hashlib.sha256).hexdigest()
        req = _make_request(
            body=body,
            headers={"x-signature": f"sha512={raw_hex}", "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_uppercase_hex_rejected(self):
        """Uppercase hex doesn't match lowercase hexdigest()."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts).upper()  # SHA256=ABCD...
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        # "SHA256=..." != "sha256=..." → rejected
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_body_tampering_detected(self):
        """Changing body after signing invalidates signature."""
        mw = CallbackVerifier()
        ts = int(time.time())
        original_body = b'{"amount":100}'
        secret = "sec"
        sig = _sign(original_body, secret, ts)
        tampered_body = b'{"amount":999}'
        req = _make_request(
            body=tampered_body,
            headers={"x-signature": sig, "x-timestamp": str(ts)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_timestamp_tampering_detected(self):
        """Reusing signature with different timestamp fails."""
        mw = CallbackVerifier()
        ts = int(time.time())
        body = b"data"
        secret = "sec"
        sig = _sign(body, secret, ts)
        # Send with different timestamp
        req = _make_request(
            body=body,
            headers={"x-signature": sig, "x-timestamp": str(ts + 1)},
        )
        ctx = _ctx(endpoints=[{"pattern": "/webhooks/*", "secret": secret}])
        result = await mw.process_request(req, ctx)
        assert result.status_code == 401
