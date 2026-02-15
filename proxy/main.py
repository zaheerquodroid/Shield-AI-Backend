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
from proxy.health import close_health_client, router as health_router
from proxy.logging_config import setup_logging
from proxy.config.webhook import close_webhook_client
from proxy.middleware.audit_logger import AuditLogger
from proxy.middleware.audit_retention import run_retention_cleanup
from proxy.middleware.context_injector import ContextInjector
from proxy.middleware.llm_sanitizer import LLMSanitizer
from proxy.middleware.pipeline import MiddlewarePipeline, RequestContext
from proxy.middleware.rate_limiter import RateLimiter
from proxy.middleware.callback_verifier import CallbackVerifier
from proxy.middleware.code_validator import CodeValidatorMiddleware
from proxy.middleware.ssrf_validator import SSRFValidator
from proxy.middleware.response_sanitizer import ResponseSanitizer
from proxy.middleware.router import TenantRouter
from proxy.middleware.security_headers import SecurityHeaders
from proxy.middleware.session_updater import SessionUpdater
from proxy.middleware.session_validator import SessionValidator
from proxy.store import redis as redis_store
from proxy.store import postgres as pg_store

logger = structlog.get_logger()

_http_client: httpx.AsyncClient | None = None
_pipeline: MiddlewarePipeline | None = None
_shutdown_event = asyncio.Event()
_retention_task: asyncio.Task | None = None


def _build_pipeline() -> MiddlewarePipeline:
    """Build the ordered middleware pipeline.

    AuditLogger at position 1 (after TenantRouter):
    - process_request always runs (captures timing even when later middleware short-circuits)
    - process_response runs near last in reverse order (sees final status code)
    """
    pipeline = MiddlewarePipeline()
    pipeline.add(TenantRouter())       # 0: resolve tenant config
    pipeline.add(AuditLogger())        # 1: start timing; log on response
    pipeline.add(ContextInjector())    # 2: request ID, headers
    pipeline.add(RateLimiter())        # 3
    pipeline.add(SessionValidator())   # 4
    pipeline.add(CallbackVerifier())   # 5: HMAC signature verification
    pipeline.add(SSRFValidator())      # 6: SSRF validation on URL-valued fields
    pipeline.add(LLMSanitizer())       # 7
    pipeline.add(ResponseSanitizer())  # 8
    pipeline.add(SecurityHeaders())    # 9
    pipeline.add(SessionUpdater())          # 10
    pipeline.add(CodeValidatorMiddleware())  # 11: AI-generated code validation
    return pipeline


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    global _http_client, _pipeline, _retention_task

    settings = load_settings()
    setup_logging(log_level=settings.log_level, json_format=settings.log_json)
    register_reload_handler()

    # Init Redis (non-fatal if unavailable)
    await redis_store.init_redis(settings.redis_url, pool_size=settings.redis_pool_size)

    # Init PostgreSQL (non-fatal if unavailable)
    await pg_store.init_postgres(
        settings.postgres_url,
        min_size=settings.postgres_pool_min,
        max_size=settings.postgres_pool_max,
    )
    await pg_store.run_migrations()

    # Init HTTP client for proxying
    _http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.proxy_timeout),
        follow_redirects=settings.upstream_follow_redirects,
        limits=httpx.Limits(
            max_connections=settings.upstream_max_connections,
            max_keepalive_connections=settings.upstream_max_keepalive,
        ),
    )

    # Build middleware pipeline
    _pipeline = _build_pipeline()

    # Start audit logger batch flush loop
    _audit_logger = _pipeline.get_middleware(AuditLogger) if _pipeline else None
    if _audit_logger:
        await _audit_logger.start()

    # Start customer config polling
    from proxy.config.customer_config import get_config_service

    config_svc = get_config_service()
    try:
        await config_svc.load_all()
    except Exception:
        logger.warning("customer_config_initial_load_failed")
    await config_svc.start_polling()

    # Start audit log retention cleanup background task
    _retention_task = asyncio.create_task(
        run_retention_cleanup(settings.audit_retention_cleanup_interval)
    )

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

    # Cancel retention cleanup
    if _retention_task and not _retention_task.done():
        _retention_task.cancel()
        try:
            await _retention_task
        except asyncio.CancelledError:
            pass

    # Stop audit logger (drain queue)
    if _audit_logger:
        await _audit_logger.stop()

    # Stop config polling
    await config_svc.stop_polling()

    if _http_client:
        await _http_client.aclose()
    await close_health_client()
    await close_webhook_client()
    await redis_store.close_redis()
    await pg_store.close_postgres()

    logger.info("proxy_stopped")


app = FastAPI(title="ShieldAI Security Proxy", lifespan=lifespan)

# Mount health/ready endpoints
app.include_router(health_router)


# Import and mount config API (deferred to avoid circular imports)
from proxy.api.config_routes import router as config_router  # noqa: E402
from proxy.api.audit_routes import router as audit_router  # noqa: E402
from proxy.api.webhook_routes import router as webhook_router  # noqa: E402
from proxy.api.code_validation_routes import router as code_validation_router  # noqa: E402
from proxy.api.onboarding_routes import router as onboarding_router  # noqa: E402
from proxy.api.well_known_routes import router as well_known_router  # noqa: E402

app.include_router(config_router)
app.include_router(audit_router)
app.include_router(webhook_router)
app.include_router(code_validation_router)
app.include_router(onboarding_router)
app.include_router(well_known_router)


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
            # Short-circuit responses still need response pipeline
            # (security headers, audit logging, response sanitization)
            short_circuit = await _pipeline.process_response(short_circuit, context)
            return short_circuit

    # Determine upstream URL — use customer config if available, else default
    upstream_base = context.customer_config.get("origin_url", settings.upstream_url)
    upstream_url = f"{upstream_base.rstrip('/')}/{path}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    # Build upstream headers — filter hop-by-hop and stripped spoofed headers
    stripped = context.extra.get("stripped_headers", set())
    headers = {}
    for key, value in request.headers.items():
        lower = key.lower()
        if lower in HOP_BY_HOP_HEADERS or lower == "host" or lower in stripped:
            continue
        headers[key] = value

    # Inject context headers
    if context.request_id:
        headers["x-request-id"] = context.request_id
    if context.tenant_id:
        headers["x-tenant-id"] = context.tenant_id
    if context.user_id:
        headers["x-user-id"] = context.user_id

    # Read request body with size limit
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_body_bytes:
                return Response(content="Request body too large", status_code=413)
        except (ValueError, OverflowError):
            return Response(content="Invalid Content-Length", status_code=400)
    body = await request.body()
    if len(body) > settings.max_body_bytes:
        return Response(content="Request body too large", status_code=413)

    # Use modified body if middleware (e.g. LLM sanitizer) rewrote it
    upstream_body = context.extra.get("modified_body", body)

    # Fix Content-Length if body was modified by middleware
    if "modified_body" in context.extra:
        if isinstance(upstream_body, bytes):
            headers["content-length"] = str(len(upstream_body))
        elif isinstance(upstream_body, str):
            headers["content-length"] = str(len(upstream_body.encode()))
        else:
            headers.pop("content-length", None)
            headers.pop("Content-Length", None)

    try:
        upstream_resp = await _http_client.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=upstream_body,
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

    # Check response body size — prevent OOM from malicious/compromised upstream
    resp_content_length = upstream_resp.headers.get("content-length")
    if resp_content_length:
        try:
            if int(resp_content_length) > settings.max_body_bytes:
                logger.error(
                    "upstream_response_too_large",
                    content_length=resp_content_length,
                    max=settings.max_body_bytes,
                    request_id=context.request_id,
                )
                return Response(content="Upstream response too large", status_code=502)
        except (ValueError, OverflowError):
            pass
    # Also check actual content size (Content-Length may be missing or wrong)
    if len(upstream_resp.content) > settings.max_body_bytes:
        logger.error(
            "upstream_response_too_large",
            actual_size=len(upstream_resp.content),
            max=settings.max_body_bytes,
            request_id=context.request_id,
        )
        return Response(content="Upstream response too large", status_code=502)

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
