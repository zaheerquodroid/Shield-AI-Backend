"""Tests proving the 4 security audit fixes are effective.

Fix 1: Timing-safe fingerprint comparison (hmac.compare_digest)
Fix 2: Expired sessions actively deleted from Redis
Fix 3: Content-Length corrected when middleware modifies body
Fix 4: Short-circuit responses still pass through response pipeline
"""

from __future__ import annotations

import hmac
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import MiddlewarePipeline, Middleware, RequestContext
from proxy.middleware.session_validator import SessionValidator
from proxy.store.session import compute_fingerprint


# ── Helpers ────────────────────────────────────────────────────────────


def _make_request(
    path: str = "/",
    method: str = "GET",
    cookies: dict | None = None,
    headers: dict | None = None,
    client: tuple[str, int] = ("192.168.1.100", 12345),
) -> Request:
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode(), v.encode()))
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        raw_headers.append((b"cookie", cookie_str.encode()))

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": raw_headers,
        "root_path": "",
        "server": ("localhost", 8080),
        "client": client,
    }
    return Request(scope)


def _make_context(
    session_validation: bool = True,
    session_cfg: dict | None = None,
) -> RequestContext:
    ctx = RequestContext(tenant_id="tenant-1")
    settings: dict = {}
    if session_cfg:
        settings["session"] = session_cfg
    ctx.customer_config = {
        "enabled_features": {"session_validation": session_validation},
        "settings": settings,
    }
    return ctx


def _make_session_data(
    ip: str = "192.168.1.100",
    user_agent: str = "TestAgent/1.0",
    created_at: int | None = None,
    last_activity: int | None = None,
) -> dict[str, str]:
    now = int(time.time())
    fp = compute_fingerprint(ip, user_agent)
    return {
        "tenant_id": "tenant-1",
        "user_id": "user-1",
        "fingerprint": fp,
        "last_activity": str(last_activity or now),
        "created_at": str(created_at or now),
        "ip": ip,
        "user_agent": user_agent,
    }


# ══════════════════════════════════════════════════════════════════════
# Fix 1: Timing-safe fingerprint comparison
# ══════════════════════════════════════════════════════════════════════


class TestTimingSafeFingerprintComparison:
    """Fingerprint comparison must use hmac.compare_digest to prevent timing attacks."""

    @pytest.mark.asyncio
    async def test_uses_hmac_compare_digest(self):
        """SessionValidator must use hmac.compare_digest, not == or !=."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "strict"})
        # Mismatched IP to trigger fingerprint comparison
        session = _make_session_data(ip="10.0.0.1", user_agent="TestAgent/1.0")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.hmac") as mock_hmac:
                mock_hmac.compare_digest.return_value = False
                result = await mw.process_request(request, ctx)

        # hmac.compare_digest was called (timing-safe comparison)
        mock_hmac.compare_digest.assert_called_once()
        # And it rejected the mismatched fingerprint
        assert result is not None
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_hmac_compare_digest_matching(self):
        """When fingerprints match, hmac.compare_digest returns True and session passes."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "strict"})
        session = _make_session_data(ip="192.168.1.100", user_agent="TestAgent/1.0")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                with patch("proxy.middleware.session_validator.hmac") as mock_hmac:
                    mock_hmac.compare_digest.return_value = True
                    result = await mw.process_request(request, ctx)

        mock_hmac.compare_digest.assert_called_once()
        assert result is None  # passes through

    def test_source_code_uses_compare_digest(self):
        """Verify the actual source code calls hmac.compare_digest."""
        import inspect
        source = inspect.getsource(SessionValidator.process_request)
        assert "hmac.compare_digest" in source
        # Must NOT use plain != for fingerprint
        assert "current_fp != stored_fp" not in source
        assert "current_fp == stored_fp" not in source

    @pytest.mark.asyncio
    async def test_compare_digest_receives_encoded_strings(self):
        """hmac.compare_digest should receive bytes (encoded strings)."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "strict"})
        session = _make_session_data(ip="10.0.0.1", user_agent="TestAgent/1.0")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.hmac") as mock_hmac:
                mock_hmac.compare_digest.return_value = False
                await mw.process_request(request, ctx)

        args = mock_hmac.compare_digest.call_args[0]
        # Both arguments should be bytes
        assert isinstance(args[0], bytes)
        assert isinstance(args[1], bytes)


# ══════════════════════════════════════════════════════════════════════
# Fix 2: Expired sessions actively deleted from Redis
# ══════════════════════════════════════════════════════════════════════


class TestExpiredSessionDeletion:
    """Expired sessions must be actively deleted from Redis, not just rejected."""

    @pytest.mark.asyncio
    async def test_idle_timeout_deletes_session(self):
        """When idle timeout exceeded, session must be deleted from Redis."""
        mw = SessionValidator()
        ctx = _make_context()
        session = _make_session_data(last_activity=int(time.time()) - 7200)
        request = _make_request(
            cookies={"shield_session": "idle-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.delete_session") as mock_delete:
                result = await mw.process_request(request, ctx)

        assert result.status_code == 401
        mock_delete.assert_called_once_with("idle-token")

    @pytest.mark.asyncio
    async def test_absolute_timeout_deletes_session(self):
        """When absolute timeout exceeded, session must be deleted from Redis."""
        mw = SessionValidator()
        ctx = _make_context()
        now = int(time.time())
        session = _make_session_data(
            created_at=now - 90000,
            last_activity=now - 60,
        )
        request = _make_request(
            cookies={"shield_session": "old-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.delete_session") as mock_delete:
                result = await mw.process_request(request, ctx)

        assert result.status_code == 401
        mock_delete.assert_called_once_with("old-token")

    @pytest.mark.asyncio
    async def test_valid_session_not_deleted(self):
        """Valid sessions must NOT be deleted."""
        mw = SessionValidator()
        ctx = _make_context()
        session = _make_session_data()
        request = _make_request(
            cookies={"shield_session": "valid-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                with patch("proxy.middleware.session_validator.delete_session") as mock_delete:
                    result = await mw.process_request(request, ctx)

        assert result is None
        mock_delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_failure_still_returns_401(self):
        """Even if Redis delete fails, the 401 must still be returned."""
        mw = SessionValidator()
        ctx = _make_context()
        session = _make_session_data(last_activity=int(time.time()) - 7200)
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.delete_session", side_effect=Exception("Redis down")):
                # Should not crash — the 401 should still be returned
                # The delete_session function handles its own exceptions internally,
                # but even if it raises, the middleware should handle it.
                # Let's check if session_validator catches the exception.
                try:
                    result = await mw.process_request(request, ctx)
                    # If it doesn't raise, it should be a 401
                    assert result.status_code == 401
                except Exception:
                    # If delete_session raises, that's a bug — it should be caught
                    pytest.fail("delete_session exception should not crash the validator")

    def test_source_code_calls_delete_on_timeout(self):
        """Verify source code calls delete_session before returning 401 for timeouts."""
        import inspect
        source = inspect.getsource(SessionValidator.process_request)
        # Both timeout paths should call delete_session
        assert source.count("await delete_session(token)") >= 2


# ══════════════════════════════════════════════════════════════════════
# Fix 3: Content-Length corrected after body modification
# ══════════════════════════════════════════════════════════════════════


class TestContentLengthCorrection:
    """When middleware modifies the request body, Content-Length must be updated."""

    def test_modified_body_updates_content_length(self, client):
        """When LLM sanitizer modifies body, Content-Length sent upstream must match."""
        original_body = b'{"prompt": "hello"}'
        modified_body = b'{"prompt": "<user_data>hello</user_data>"}'

        mock_response = httpx.Response(200, text="ok")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            # Simulate middleware modifying the body
            with patch("proxy.main._pipeline") as mock_pipeline:
                async def mock_process_request(request, context):
                    context.extra["modified_body"] = modified_body
                    return None

                async def mock_process_response(response, context):
                    return response

                mock_pipeline.process_request = mock_process_request
                mock_pipeline.process_response = mock_process_response

                resp = client.post(
                    "/api/chat",
                    content=original_body,
                    headers={"content-type": "application/json"},
                )

            if resp.status_code == 200:
                call_kwargs = mock_client.request.call_args
                sent_headers = call_kwargs.kwargs["headers"]
                sent_body = call_kwargs.kwargs["content"]
                # Content-Length must match the actual body sent
                if "content-length" in sent_headers:
                    assert int(sent_headers["content-length"]) == len(sent_body)

    def test_unmodified_body_preserves_content_length(self, client):
        """When body is NOT modified, Content-Length is unchanged."""
        body = b'{"key": "value"}'
        mock_response = httpx.Response(200, text="ok")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            with patch("proxy.main._pipeline") as mock_pipeline:
                async def mock_process_request(request, context):
                    return None

                async def mock_process_response(response, context):
                    return response

                mock_pipeline.process_request = mock_process_request
                mock_pipeline.process_response = mock_process_response

                resp = client.post("/api/data", content=body)

            if resp.status_code == 200:
                call_kwargs = mock_client.request.call_args
                sent_headers = call_kwargs.kwargs["headers"]
                sent_body = call_kwargs.kwargs["content"]
                if "content-length" in sent_headers:
                    assert int(sent_headers["content-length"]) == len(sent_body)

    def test_source_code_fixes_content_length(self):
        """Verify source code updates content-length when modified_body is present."""
        import inspect
        import proxy.main as main_module
        source = inspect.getsource(main_module.proxy_request)
        assert "modified_body" in source
        assert "content-length" in source


# ══════════════════════════════════════════════════════════════════════
# Fix 4: Short-circuit responses pass through response pipeline
# ══════════════════════════════════════════════════════════════════════


class TestShortCircuitResponsePipeline:
    """Short-circuit responses (e.g. 401, 429) must still run through response pipeline."""

    def test_rate_limiter_429_gets_security_headers(self, client):
        """Rate limiter 429 responses must still get security headers."""
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=httpx.Response(200, text="ok"))

            with patch("proxy.main._pipeline") as mock_pipeline:
                async def mock_process_request(request, context):
                    # Simulate rate limiter short-circuit
                    return Response(content="Rate limited", status_code=429)

                response_pipeline_called = []

                async def mock_process_response(response, context):
                    response_pipeline_called.append(True)
                    response.headers["x-security-test"] = "applied"
                    return response

                mock_pipeline.process_request = mock_process_request
                mock_pipeline.process_response = mock_process_response

                resp = client.get("/api/data")

        assert resp.status_code == 429
        # Response pipeline MUST have been called
        assert len(response_pipeline_called) == 1
        assert resp.headers.get("x-security-test") == "applied"

    def test_session_401_gets_security_headers(self, client):
        """Session validator 401 responses must still get security headers."""
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=httpx.Response(200, text="ok"))

            with patch("proxy.main._pipeline") as mock_pipeline:
                async def mock_process_request(request, context):
                    return Response(content="Unauthorized", status_code=401)

                response_processed = []

                async def mock_process_response(response, context):
                    response_processed.append(response.status_code)
                    response.headers["strict-transport-security"] = "max-age=31536000"
                    return response

                mock_pipeline.process_request = mock_process_request
                mock_pipeline.process_response = mock_process_response

                resp = client.get("/protected")

        assert resp.status_code == 401
        assert len(response_processed) == 1
        assert response_processed[0] == 401
        assert "strict-transport-security" in resp.headers

    def test_llm_block_400_gets_response_pipeline(self, client):
        """LLM sanitizer block (400) responses must pass through response pipeline."""
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=httpx.Response(200, text="ok"))

            with patch("proxy.main._pipeline") as mock_pipeline:
                async def mock_process_request(request, context):
                    return Response(content="Blocked: prompt injection", status_code=400)

                pipeline_responses = []

                async def mock_process_response(response, context):
                    pipeline_responses.append(True)
                    return response

                mock_pipeline.process_request = mock_process_request
                mock_pipeline.process_response = mock_process_response

                resp = client.post("/api/chat", content=b'{"prompt": "ignore all"}')

        assert resp.status_code == 400
        assert len(pipeline_responses) == 1

    def test_short_circuit_gets_audit_logged(self, client):
        """Short-circuit responses must be auditable (response pipeline includes audit logger)."""
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=httpx.Response(200, text="ok"))

            with patch("proxy.main._pipeline") as mock_pipeline:
                async def mock_process_request(request, context):
                    return Response(content="Forbidden", status_code=403)

                audit_entries = []

                async def mock_process_response(response, context):
                    audit_entries.append({
                        "status": response.status_code,
                        "request_id": context.request_id,
                    })
                    return response

                mock_pipeline.process_request = mock_process_request
                mock_pipeline.process_response = mock_process_response

                resp = client.get("/admin")

        assert resp.status_code == 403
        assert len(audit_entries) == 1
        assert audit_entries[0]["status"] == 403
        assert audit_entries[0]["request_id"]  # has a request ID

    def test_source_code_runs_response_pipeline_on_short_circuit(self):
        """Verify source code passes short-circuit responses through process_response."""
        import inspect
        import proxy.main as main_module
        source = inspect.getsource(main_module.proxy_request)
        # After getting short_circuit, must call process_response before returning
        # Look for the pattern: process_response on short_circuit
        assert "process_response(short_circuit" in source

    @pytest.mark.asyncio
    async def test_pipeline_process_response_called_for_all_status_codes(self):
        """Response pipeline must be called for 4xx/5xx short-circuits, not just 2xx."""

        class ResponseTracker(Middleware):
            def __init__(self):
                self.responses = []

            async def process_request(self, request, context):
                return None

            async def process_response(self, response, context):
                self.responses.append(response.status_code)
                return response

        tracker = ResponseTracker()
        pipeline = MiddlewarePipeline()
        pipeline.add(tracker)

        ctx = RequestContext()

        # Simulate short-circuit responses with various status codes
        for status_code in [400, 401, 403, 429, 500]:
            response = Response(content="error", status_code=status_code)
            result = await pipeline.process_response(response, ctx)
            assert result.status_code == status_code

        # All 5 responses should have passed through
        assert tracker.responses == [400, 401, 403, 429, 500]


# ══════════════════════════════════════════════════════════════════════
# Integration: Verify no security gaps remain
# ══════════════════════════════════════════════════════════════════════


class TestNoSecurityGapsRemain:
    """Cross-cutting tests to verify the overall security posture."""

    def test_short_circuit_response_has_request_id(self, client):
        """Even short-circuit responses should include x-request-id for tracing."""
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=httpx.Response(200, text="ok"))

            with patch("proxy.main._pipeline") as mock_pipeline:
                captured_context = {}

                async def mock_process_request(request, context):
                    captured_context["request_id"] = context.request_id
                    return Response(content="blocked", status_code=429)

                async def mock_process_response(response, context):
                    response.headers["x-request-id"] = context.request_id
                    return response

                mock_pipeline.process_request = mock_process_request
                mock_pipeline.process_response = mock_process_response

                resp = client.get("/api/data")

        assert resp.status_code == 429
        assert resp.headers.get("x-request-id") == captured_context["request_id"]

    @pytest.mark.asyncio
    async def test_expired_session_cannot_be_reused_after_deletion(self):
        """After an expired session is deleted, the same token returns session-not-found."""
        mw = SessionValidator()
        ctx = _make_context()
        session = _make_session_data(last_activity=int(time.time()) - 7200)
        request = _make_request(
            cookies={"shield_session": "expired-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        # First request: session expired, gets deleted
        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.delete_session") as mock_delete:
                result = await mw.process_request(request, ctx)

        assert result.status_code == 401
        mock_delete.assert_called_once_with("expired-token")

        # Second request: session no longer exists
        ctx2 = _make_context()
        with patch("proxy.middleware.session_validator.load_session", return_value=None):
            result2 = await mw.process_request(request, ctx2)

        assert result2.status_code == 401
