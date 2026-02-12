"""FastAPI reverse proxy application."""

from __future__ import annotations

import asyncio
import signal
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

from proxy.config.loader import get_settings, load_settings, register_reload_handler
from proxy.health import router as health_router
from proxy.logging_config import setup_logging
from proxy.middleware.audit_logger import AuditLogger
from proxy.middleware.context_injector import ContextInjector
from proxy.middleware.pipeline import MiddlewarePipeline, RequestContext
from proxy.middleware.rate_limiter import RateLimiter
from proxy.middleware.request_sanitizer import RequestSanitizer
from proxy.middleware.response_sanitizer import ResponseSanitizer
from proxy.middleware.router import TenantRouter
from proxy.middleware.security_headers import SecurityHeaders
from proxy.middleware.session_updater import SessionUpdater
from proxy.middleware.session_validator import SessionValidator
from proxy.store import redis as redis_store

logger = structlog.get_logger()

_http_client: httpx.AsyncClient | None = None
_pipeline: MiddlewarePipeline | None = None
_shutdown_event = asyncio.Event()


def _build_pipeline() -> MiddlewarePipeline:
    """Build the ordered middleware pipeline."""
    pipeline = MiddlewarePipeline()
    pipeline.add(TenantRouter())
    pipeline.add(ContextInjector())
    pipeline.add(RateLimiter())
    pipeline.add(SessionValidator())
    pipeline.add(RequestSanitizer())
    pipeline.add(ResponseSanitizer())
    pipeline.add(SecurityHeaders())
    pipeline.add(AuditLogger())
    pipeline.add(SessionUpdater())
    return pipeline


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    global _http_client, _pipeline

    settings = load_settings()
    setup_logging(log_level=settings.log_level, json_format=settings.log_json)
    register_reload_handler()

    # Init Redis (non-fatal if unavailable)
    await redis_store.init_redis(settings.redis_url, pool_size=settings.redis_pool_size)

    # Init HTTP client for proxying
    _http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.proxy_timeout),
        follow_redirects=False,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )

    # Build middleware pipeline
    _pipeline = _build_pipeline()

    # Register SIGTERM handler for graceful shutdown
    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, lambda: _shutdown_event.set())
    except (RuntimeError, NotImplementedError):
        pass  # Not in main thread (e.g., during tests)

    logger.info("proxy_started", upstream=settings.upstream_url, port=settings.listen_port)

    yield

    # Shutdown: drain connections
    logger.info("proxy_shutting_down", drain_seconds=settings.shutdown_drain_seconds)
    _shutdown_event.set()

    if _http_client:
        await _http_client.aclose()
    await redis_store.close_redis()

    logger.info("proxy_stopped")


app = FastAPI(title="ShieldAI Security Proxy", lifespan=lifespan)

# Mount health/ready endpoints
app.include_router(health_router)


# Import and mount config API (deferred to avoid circular imports)
from proxy.api.config_routes import router as config_router  # noqa: E402

app.include_router(config_router)


HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
})


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy_request(request: Request, path: str) -> Response:
    """Catch-all reverse proxy handler."""
    if _http_client is None:
        return Response(content="Proxy not initialized", status_code=503)

    settings = get_settings()
    context = RequestContext()

    # Run request through middleware pipeline
    if _pipeline:
        short_circuit = await _pipeline.process_request(request, context)
        if short_circuit is not None:
            return short_circuit

    # Determine upstream URL — use customer config if available, else default
    upstream_base = context.customer_config.get("origin_url", settings.upstream_url)
    upstream_url = f"{upstream_base.rstrip('/')}/{path}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    # Build upstream headers — filter hop-by-hop
    headers = {}
    for key, value in request.headers.items():
        if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host":
            headers[key] = value

    # Inject context headers
    if context.request_id:
        headers["x-request-id"] = context.request_id
    if context.tenant_id:
        headers["x-tenant-id"] = context.tenant_id
    if context.user_id:
        headers["x-user-id"] = context.user_id

    # Read request body
    body = await request.body()

    try:
        upstream_resp = await _http_client.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
        )
    except httpx.TimeoutException:
        logger.error("upstream_timeout", url=upstream_url, request_id=context.request_id)
        return Response(content="Upstream timeout", status_code=504)
    except httpx.ConnectError:
        logger.error("upstream_connect_error", url=upstream_url, request_id=context.request_id)
        return Response(content="Upstream unreachable", status_code=502)
    except httpx.HTTPError as exc:
        logger.error("upstream_error", url=upstream_url, request_id=context.request_id, error=str(exc))
        return Response(content="Upstream error", status_code=502)

    # Build response headers — filter hop-by-hop
    response_headers = {}
    for key, value in upstream_resp.headers.items():
        if key.lower() not in HOP_BY_HOP_HEADERS:
            response_headers[key] = value

    # Always include request ID in response
    response_headers["x-request-id"] = context.request_id

    response = Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=response_headers,
    )

    # Run response through middleware pipeline (reverse order)
    if _pipeline:
        response = await _pipeline.process_response(response, context)

    return response
