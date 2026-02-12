"""Context injector header tests."""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from proxy.middleware.context_injector import ContextInjector
from proxy.middleware.pipeline import RequestContext


class _MockHeaders(dict):
    """Dict subclass that supports case-insensitive get like Starlette Headers."""

    def __init__(self, raw: dict[str, str] | None = None):
        super().__init__()
        for k, v in (raw or {}).items():
            self[k.lower()] = v

    def get(self, key, default=None):
        return super().get(key.lower(), default)

    def __iter__(self):
        return super().__iter__()


def _make_request(headers: dict[str, str] | None = None, client_host: str = "127.0.0.1", scheme: str = "http"):
    """Create a mock Starlette Request."""
    request = MagicMock()
    request.headers = _MockHeaders(headers)
    request.client = MagicMock()
    request.client.host = client_host
    request.url = MagicMock()
    request.url.scheme = scheme
    return request


@pytest.mark.asyncio
async def test_generates_request_id():
    """Generates an 8-char hex X-Request-ID."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request()

    await injector.process_request(request, context)

    assert len(context.request_id) == 8
    assert re.match(r"^[0-9a-f]{8}$", context.request_id)


@pytest.mark.asyncio
async def test_unique_request_ids():
    """Each request gets a unique ID."""
    injector = ContextInjector()
    ids = set()
    for _ in range(100):
        context = RequestContext()
        await injector.process_request(_make_request(), context)
        ids.add(context.request_id)
    assert len(ids) == 100


@pytest.mark.asyncio
async def test_preserves_original_request_id():
    """Client X-Request-ID is preserved as X-Original-Request-ID."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(headers={"X-Request-ID": "client-123"})

    await injector.process_request(request, context)

    assert context.extra["original_request_id"] == "client-123"
    assert context.request_id != "client-123"


@pytest.mark.asyncio
async def test_strips_spoofed_tenant_id():
    """X-Tenant-ID from client is stripped."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(headers={"X-Tenant-ID": "spoofed-tenant"})

    await injector.process_request(request, context)

    assert "x-tenant-id" in context.extra["stripped_headers"]


@pytest.mark.asyncio
async def test_strips_spoofed_user_id():
    """X-User-ID from client is stripped."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(headers={"X-User-ID": "spoofed-user"})

    await injector.process_request(request, context)

    assert "x-user-id" in context.extra["stripped_headers"]


@pytest.mark.asyncio
async def test_strips_shieldai_prefixed_headers():
    """X-ShieldAI-* headers from client are stripped."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(headers={"X-ShieldAI-Internal": "spoofed"})

    await injector.process_request(request, context)

    assert "x-shieldai-internal" in context.extra["stripped_headers"]


@pytest.mark.asyncio
async def test_sets_forwarded_for():
    """X-Forwarded-For is set with client IP."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(client_host="192.168.1.100")

    await injector.process_request(request, context)

    assert context.extra["x_forwarded_for"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_appends_forwarded_for():
    """X-Forwarded-For is appended when already present."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(
        headers={"X-Forwarded-For": "10.0.0.1"},
        client_host="192.168.1.100",
    )

    await injector.process_request(request, context)

    assert context.extra["x_forwarded_for"] == "10.0.0.1, 192.168.1.100"


@pytest.mark.asyncio
async def test_sets_forwarded_proto():
    """X-Forwarded-Proto is set from request scheme."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(scheme="https")

    await injector.process_request(request, context)

    assert context.extra["x_forwarded_proto"] == "https"


@pytest.mark.asyncio
async def test_response_includes_request_id():
    """Response has X-Request-ID header."""
    injector = ContextInjector()
    context = RequestContext(request_id="abc12345")

    from starlette.responses import Response
    response = Response(content="ok")
    response = await injector.process_response(response, context)

    assert response.headers["x-request-id"] == "abc12345"


@pytest.mark.asyncio
async def test_response_includes_original_request_id():
    """Response has X-Original-Request-ID when client sent one."""
    injector = ContextInjector()
    context = RequestContext(request_id="abc12345")
    context.extra["original_request_id"] = "client-123"

    from starlette.responses import Response
    response = Response(content="ok")
    response = await injector.process_response(response, context)

    assert response.headers["x-original-request-id"] == "client-123"


# --- Edge cases ---


@pytest.mark.asyncio
async def test_client_is_none():
    """request.client being None uses 'unknown' for XFF."""
    injector = ContextInjector()
    context = RequestContext()
    request = MagicMock()
    request.headers = _MockHeaders()
    request.client = None
    request.url = MagicMock()
    request.url.scheme = "http"

    await injector.process_request(request, context)

    assert context.extra["x_forwarded_for"] == "unknown"


@pytest.mark.asyncio
async def test_ipv6_client_address():
    """IPv6 client address is preserved in XFF."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(client_host="::1")

    await injector.process_request(request, context)

    assert context.extra["x_forwarded_for"] == "::1"


@pytest.mark.asyncio
async def test_no_original_request_id_in_response():
    """Response omits X-Original-Request-ID when client didn't send one."""
    injector = ContextInjector()
    context = RequestContext(request_id="abc12345")
    # No original_request_id in extra

    from starlette.responses import Response
    response = Response(content="ok")
    response = await injector.process_response(response, context)

    assert "x-original-request-id" not in response.headers


@pytest.mark.asyncio
async def test_multiple_shieldai_headers_stripped():
    """Multiple X-ShieldAI-* headers are all stripped."""
    injector = ContextInjector()
    context = RequestContext()
    request = _make_request(headers={
        "X-ShieldAI-One": "a",
        "X-ShieldAI-Two": "b",
        "X-Normal": "keep",
    })

    await injector.process_request(request, context)

    stripped = context.extra["stripped_headers"]
    assert "x-shieldai-one" in stripped
    assert "x-shieldai-two" in stripped
    assert "x-normal" not in stripped
