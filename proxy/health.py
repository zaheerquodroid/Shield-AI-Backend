"""Health and readiness endpoints."""

from __future__ import annotations

import httpx
import structlog
from fastapi import APIRouter

from proxy.config.loader import get_settings
from proxy.store import redis as redis_store

logger = structlog.get_logger()
router = APIRouter()


async def _check_upstream() -> bool:
    """Check if upstream is reachable with a HEAD request."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.head(settings.upstream_url)
            return resp.status_code < 500
    except Exception:
        return False


@router.get("/health")
async def health():
    """Health check — returns status of proxy and dependencies."""
    redis_ok = await redis_store.ping()
    upstream_ok = await _check_upstream()

    return {
        "status": "healthy" if (redis_ok and upstream_ok) else "degraded",
        "proxy": "up",
        "redis": "up" if redis_ok else "down",
        "upstream": "up" if upstream_ok else "down",
    }


@router.get("/ready")
async def ready():
    """Readiness check — returns 200 only when all connections are established."""
    redis_ok = await redis_store.ping()
    upstream_ok = await _check_upstream()

    if redis_ok and upstream_ok:
        return {"status": "ready"}

    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=503,
        content={
            "status": "not_ready",
            "redis": "up" if redis_ok else "down",
            "upstream": "up" if upstream_ok else "down",
        },
    )
