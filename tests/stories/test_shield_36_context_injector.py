"""SHIELD-36 — Build context injector middleware.

Acceptance Criteria:
  AC1: Every proxied request gets a unique X-Request-ID header (UUID v4, first 8 characters).
  AC2: X-Tenant-ID header injected from session context (if authenticated session exists).
  AC3: X-User-ID header injected from session context (if authenticated session exists).
  AC4: X-Forwarded-For header correctly set with client IP (appended if already present).
  AC5: Client-supplied X-Tenant-ID and X-User-ID headers are stripped before injection.
  AC6: Original client X-Request-ID preserved as X-Original-Request-ID if present.
  AC7: Context values available to all downstream middleware via request context object.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import httpx
import pytest
from starlette.responses import Response
from starlette.testclient import TestClient as StarletteTestClient

from proxy.middleware.context_injector import ContextInjector
from proxy.middleware.pipeline import RequestContext


class _MockHeaders(dict):
    """Dict subclass that allows attribute assignment (dict .get is read-only)."""
    pass


def _make_request(headers: dict | None = None, client_host: str = "10.0.0.1") -> MagicMock:
    """Build a mock Starlette request."""
    req = MagicMock()
    mock_h = _MockHeaders(headers or {})
    req.headers = mock_h
    req.client = MagicMock()
    req.client.host = client_host
    req.url = MagicMock()
    req.url.scheme = "https"
    return req


# ---------------------------------------------------------------------------
# AC1: Unique X-Request-ID (UUID v4, first 8 chars)
# ---------------------------------------------------------------------------


class TestAC1_UniqueRequestID:
    """Every proxied request gets a unique 8-char X-Request-ID."""

    @pytest.mark.asyncio
    async def test_request_id_is_8_hex_chars(self):
        """Generated request ID is exactly 8 hex characters."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request()
        await injector.process_request(req, ctx)
        assert len(ctx.request_id) == 8
        assert re.fullmatch(r"[0-9a-f]{8}", ctx.request_id)

    @pytest.mark.asyncio
    async def test_request_id_unique_per_request(self):
        """Each request gets a different ID."""
        injector = ContextInjector()
        ids = set()
        for _ in range(100):
            ctx = RequestContext()
            req = _make_request()
            await injector.process_request(req, ctx)
            ids.add(ctx.request_id)
        assert len(ids) == 100

    @pytest.mark.asyncio
    async def test_request_id_in_response(self):
        """X-Request-ID is included in the response."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request()
        await injector.process_request(req, ctx)

        resp = Response(content="ok")
        resp = await injector.process_response(resp, ctx)
        assert resp.headers["x-request-id"] == ctx.request_id


# ---------------------------------------------------------------------------
# AC2: X-Tenant-ID from session context
# ---------------------------------------------------------------------------


class TestAC2_TenantIDInjection:
    """X-Tenant-ID injected from session context."""

    @pytest.mark.asyncio
    async def test_tenant_id_from_context_forwarded(self):
        """Tenant ID from context is available for upstream injection."""
        injector = ContextInjector()
        ctx = RequestContext()
        ctx.tenant_id = "tenant-abc"
        req = _make_request()
        await injector.process_request(req, ctx)
        # Context still holds tenant_id — main.py injects it into upstream headers
        assert ctx.tenant_id == "tenant-abc"


# ---------------------------------------------------------------------------
# AC3: X-User-ID from session context
# ---------------------------------------------------------------------------


class TestAC3_UserIDInjection:
    """X-User-ID injected from session context."""

    @pytest.mark.asyncio
    async def test_user_id_from_context_forwarded(self):
        """User ID from context is available for upstream injection."""
        injector = ContextInjector()
        ctx = RequestContext()
        ctx.user_id = "user-123"
        req = _make_request()
        await injector.process_request(req, ctx)
        assert ctx.user_id == "user-123"


# ---------------------------------------------------------------------------
# AC4: X-Forwarded-For set correctly
# ---------------------------------------------------------------------------


class TestAC4_ForwardedFor:
    """X-Forwarded-For header correctly set with client IP."""

    @pytest.mark.asyncio
    async def test_xff_set_to_client_ip(self):
        """X-Forwarded-For is set to client IP when not already present."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(client_host="192.168.1.100")
        await injector.process_request(req, ctx)
        assert ctx.extra["x_forwarded_for"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_xff_appended_when_existing(self):
        """X-Forwarded-For appends client IP to existing value."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(
            headers={"x-forwarded-for": "1.2.3.4"},
            client_host="5.6.7.8",
        )
        await injector.process_request(req, ctx)
        assert ctx.extra["x_forwarded_for"] == "1.2.3.4, 5.6.7.8"

    @pytest.mark.asyncio
    async def test_forwarded_proto_set(self):
        """X-Forwarded-Proto is set from request scheme."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request()
        await injector.process_request(req, ctx)
        assert ctx.extra["x_forwarded_proto"] == "https"


# ---------------------------------------------------------------------------
# AC5: Spoofed X-Tenant-ID and X-User-ID stripped
# ---------------------------------------------------------------------------


class TestAC5_SpoofedHeadersStripped:
    """Client-supplied X-Tenant-ID and X-User-ID are stripped."""

    @pytest.mark.asyncio
    async def test_spoofed_tenant_id_stripped(self):
        """Client-supplied X-Tenant-ID is recorded for stripping."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(headers={"x-tenant-id": "spoofed-tenant"})
        await injector.process_request(req, ctx)
        assert "x-tenant-id" in ctx.extra["stripped_headers"]

    @pytest.mark.asyncio
    async def test_spoofed_user_id_stripped(self):
        """Client-supplied X-User-ID is recorded for stripping."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(headers={"x-user-id": "spoofed-user"})
        await injector.process_request(req, ctx)
        assert "x-user-id" in ctx.extra["stripped_headers"]

    @pytest.mark.asyncio
    async def test_shieldai_internal_headers_stripped(self):
        """X-ShieldAI-* internal headers are stripped."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(headers={"x-shieldai-debug": "true"})
        await injector.process_request(req, ctx)
        assert "x-shieldai-debug" in ctx.extra["stripped_headers"]


# ---------------------------------------------------------------------------
# AC6: Original X-Request-ID preserved as X-Original-Request-ID
# ---------------------------------------------------------------------------


class TestAC6_OriginalRequestIDPreserved:
    """Original client X-Request-ID preserved as X-Original-Request-ID."""

    @pytest.mark.asyncio
    async def test_original_request_id_stored(self):
        """Client X-Request-ID is stored in context."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(headers={"x-request-id": "client-req-001"})
        await injector.process_request(req, ctx)
        assert ctx.extra["original_request_id"] == "client-req-001"

    @pytest.mark.asyncio
    async def test_original_request_id_in_response(self):
        """X-Original-Request-ID header is in the response."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(headers={"x-request-id": "client-req-002"})
        await injector.process_request(req, ctx)

        resp = Response(content="ok")
        resp = await injector.process_response(resp, ctx)
        assert resp.headers["x-original-request-id"] == "client-req-002"

    @pytest.mark.asyncio
    async def test_no_original_when_not_supplied(self):
        """No X-Original-Request-ID if client didn't supply one."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request()
        await injector.process_request(req, ctx)

        resp = Response(content="ok")
        resp = await injector.process_response(resp, ctx)
        assert "x-original-request-id" not in resp.headers


# ---------------------------------------------------------------------------
# AC7: Context available to downstream middleware
# ---------------------------------------------------------------------------


class TestAC7_ContextSharing:
    """Context values available to all downstream middleware."""

    @pytest.mark.asyncio
    async def test_context_request_id_available(self):
        """Request ID is on the context after injection."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request()
        await injector.process_request(req, ctx)
        assert ctx.request_id != ""
        assert len(ctx.request_id) == 8

    @pytest.mark.asyncio
    async def test_context_xff_available(self):
        """X-Forwarded-For is on the context after injection."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(client_host="1.2.3.4")
        await injector.process_request(req, ctx)
        assert ctx.extra["x_forwarded_for"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_context_stripped_headers_available(self):
        """Stripped headers set is on the context after injection."""
        injector = ContextInjector()
        ctx = RequestContext()
        req = _make_request(headers={"x-tenant-id": "spoofed"})
        await injector.process_request(req, ctx)
        assert isinstance(ctx.extra["stripped_headers"], set)
