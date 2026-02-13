"""Middleware pipeline chain order tests."""

from __future__ import annotations

import pytest
from starlette.requests import Request
from starlette.responses import Response
from starlette.testclient import TestClient as StarletteTestClient

from proxy.middleware.pipeline import Middleware, MiddlewarePipeline, RequestContext


class TrackingMiddleware(Middleware):
    """Middleware that records its execution order."""

    def __init__(self, name: str, order_log: list[str]):
        self._name = name
        self._order_log = order_log

    @property
    def name(self) -> str:
        return self._name

    async def process_request(self, request, context):
        self._order_log.append(f"req:{self._name}")
        return None

    async def process_response(self, response, context):
        self._order_log.append(f"resp:{self._name}")
        return response


class ShortCircuitMiddleware(Middleware):
    """Middleware that short-circuits the pipeline."""

    async def process_request(self, request, context):
        return Response(content="blocked", status_code=403)


@pytest.mark.asyncio
async def test_middleware_executes_in_order():
    """Request middleware runs forward, response middleware runs reverse."""
    order_log: list[str] = []
    pipeline = MiddlewarePipeline()
    pipeline.add(TrackingMiddleware("first", order_log))
    pipeline.add(TrackingMiddleware("second", order_log))
    pipeline.add(TrackingMiddleware("third", order_log))

    context = RequestContext()
    mock_request = None  # Tracking middleware doesn't use request

    await pipeline.process_request(mock_request, context)
    assert order_log == ["req:first", "req:second", "req:third"]

    order_log.clear()
    mock_response = Response(content="ok")
    await pipeline.process_response(mock_response, context)
    assert order_log == ["resp:third", "resp:second", "resp:first"]


@pytest.mark.asyncio
async def test_middleware_can_be_disabled():
    """Disabled middleware is skipped."""
    order_log: list[str] = []
    pipeline = MiddlewarePipeline()
    pipeline.add(TrackingMiddleware("first", order_log))
    pipeline.add(TrackingMiddleware("second", order_log), enabled=False)
    pipeline.add(TrackingMiddleware("third", order_log))

    context = RequestContext()
    await pipeline.process_request(None, context)
    assert order_log == ["req:first", "req:third"]


@pytest.mark.asyncio
async def test_middleware_can_be_toggled():
    """Middleware can be enabled/disabled at runtime."""
    order_log: list[str] = []
    pipeline = MiddlewarePipeline()
    pipeline.add(TrackingMiddleware("first", order_log))
    pipeline.add(TrackingMiddleware("second", order_log))

    context = RequestContext()
    await pipeline.process_request(None, context)
    assert len(order_log) == 2

    order_log.clear()
    pipeline.set_enabled("second", False)
    await pipeline.process_request(None, context)
    assert order_log == ["req:first"]


@pytest.mark.asyncio
async def test_short_circuit_stops_pipeline():
    """A middleware returning a Response stops further processing."""
    order_log: list[str] = []
    pipeline = MiddlewarePipeline()
    pipeline.add(TrackingMiddleware("first", order_log))
    pipeline.add(ShortCircuitMiddleware())
    pipeline.add(TrackingMiddleware("third", order_log))

    context = RequestContext()
    result = await pipeline.process_request(None, context)
    assert isinstance(result, Response)
    assert result.status_code == 403
    assert order_log == ["req:first"]  # "third" was not reached


@pytest.mark.asyncio
async def test_request_context_passed_through():
    """Context is shared across all middleware."""

    class ContextWriter(Middleware):
        async def process_request(self, request, context):
            context.tenant_id = "tenant-123"
            return None

    class ContextReader(Middleware):
        async def process_request(self, request, context):
            assert context.tenant_id == "tenant-123"
            return None

    pipeline = MiddlewarePipeline()
    pipeline.add(ContextWriter())
    pipeline.add(ContextReader())

    context = RequestContext()
    await pipeline.process_request(None, context)
    assert context.tenant_id == "tenant-123"


# --- Edge cases ---


@pytest.mark.asyncio
async def test_empty_pipeline():
    """Empty pipeline processes request and response without error."""
    pipeline = MiddlewarePipeline()
    context = RequestContext()

    result = await pipeline.process_request(None, context)
    assert result is None

    response = Response(content="ok")
    result = await pipeline.process_response(response, context)
    assert result is response


@pytest.mark.asyncio
async def test_set_enabled_unknown_name():
    """set_enabled with unknown name is a no-op (doesn't crash)."""
    pipeline = MiddlewarePipeline()
    pipeline.set_enabled("nonexistent", False)  # should not raise


@pytest.mark.asyncio
async def test_request_context_default_values():
    """RequestContext has sensible defaults."""
    ctx = RequestContext()
    assert ctx.tenant_id == ""
    assert ctx.user_id == ""
    assert ctx.customer_config == {}
    assert ctx.extra == {}
    assert len(ctx.request_id) == 8


@pytest.mark.asyncio
async def test_response_middleware_sees_modified_context():
    """Response middleware can read context set during request phase."""

    class RequestSetter(Middleware):
        async def process_request(self, request, context):
            context.extra["flag"] = True
            return None

        async def process_response(self, response, context):
            assert context.extra["flag"] is True
            response.headers["x-flag"] = "true"
            return response

    pipeline = MiddlewarePipeline()
    pipeline.add(RequestSetter())

    context = RequestContext()
    await pipeline.process_request(None, context)
    response = Response(content="ok")
    response = await pipeline.process_response(response, context)
    assert response.headers["x-flag"] == "true"


@pytest.mark.asyncio
async def test_short_circuit_response_not_passed_to_response_pipeline():
    """When request is short-circuited, the response pipeline is not called automatically."""
    order_log: list[str] = []
    pipeline = MiddlewarePipeline()
    pipeline.add(ShortCircuitMiddleware())
    pipeline.add(TrackingMiddleware("after", order_log))

    context = RequestContext()
    result = await pipeline.process_request(None, context)
    assert result.status_code == 403
    assert "req:after" not in order_log


# --- Exception handling tests ---


class CrashingRequestMiddleware(Middleware):
    """Middleware that raises during process_request."""

    async def process_request(self, request, context):
        raise RuntimeError("middleware exploded")


class CrashingResponseMiddleware(Middleware):
    """Middleware that raises during process_response."""

    async def process_request(self, request, context):
        return None

    async def process_response(self, response, context):
        raise RuntimeError("response handler exploded")


@pytest.mark.asyncio
async def test_request_middleware_exception_returns_502():
    """A middleware that raises should return 502, not crash the pipeline."""
    order_log: list[str] = []
    pipeline = MiddlewarePipeline()
    pipeline.add(TrackingMiddleware("before", order_log))
    pipeline.add(CrashingRequestMiddleware())
    pipeline.add(TrackingMiddleware("after", order_log))

    context = RequestContext()
    result = await pipeline.process_request(None, context)

    assert result is not None
    assert result.status_code == 502
    assert order_log == ["req:before"]  # "after" not reached


@pytest.mark.asyncio
async def test_response_middleware_exception_skipped():
    """A middleware that raises during response should be skipped, not crash."""
    order_log: list[str] = []
    pipeline = MiddlewarePipeline()
    pipeline.add(TrackingMiddleware("first", order_log))
    pipeline.add(CrashingResponseMiddleware())
    pipeline.add(TrackingMiddleware("third", order_log))

    context = RequestContext()
    response = Response(content="ok", status_code=200)
    result = await pipeline.process_response(response, context)

    # Response is still returned despite the crash
    assert result.status_code == 200
    # first and third still ran (reverse order: third, crash, first)
    assert "resp:third" in order_log
    assert "resp:first" in order_log


# --- Pipeline build order tests ---


class TestBuildPipelineOrder:
    """Verify _build_pipeline() registers middleware in the correct order."""

    def test_pipeline_order(self):
        """Middleware should be registered in security-critical order."""
        from proxy.main import _build_pipeline

        pipeline = _build_pipeline()
        names = [mw.name for mw in pipeline._middleware]

        assert names == [
            "TenantRouter",
            "ContextInjector",
            "RateLimiter",
            "SessionValidator",
            "RequestSanitizer",
            "ResponseSanitizer",
            "SecurityHeaders",
            "AuditLogger",
            "SessionUpdater",
        ]

    def test_rate_limiter_before_session_validator(self):
        """RateLimiter must come before SessionValidator to reject early."""
        from proxy.main import _build_pipeline

        pipeline = _build_pipeline()
        names = [mw.name for mw in pipeline._middleware]

        rl_idx = names.index("RateLimiter")
        sv_idx = names.index("SessionValidator")
        assert rl_idx < sv_idx

    def test_security_headers_after_response_sanitizer(self):
        """SecurityHeaders must come after ResponseSanitizer to cover all responses."""
        from proxy.main import _build_pipeline

        pipeline = _build_pipeline()
        names = [mw.name for mw in pipeline._middleware]

        sh_idx = names.index("SecurityHeaders")
        rs_idx = names.index("ResponseSanitizer")
        assert sh_idx > rs_idx

    def test_tenant_router_is_first(self):
        """TenantRouter must be first to identify the customer."""
        from proxy.main import _build_pipeline

        pipeline = _build_pipeline()
        assert pipeline._middleware[0].name == "TenantRouter"

    def test_all_middleware_enabled_by_default(self):
        """All middleware should be enabled by default."""
        from proxy.main import _build_pipeline

        pipeline = _build_pipeline()
        for mw in pipeline._middleware:
            assert pipeline._enabled.get(mw.name) is True
