"""Redis async connection pool with retry and graceful degradation."""

from __future__ import annotations

import asyncio
import re

import redis.asyncio as aioredis
import structlog

logger = structlog.get_logger()

# Pattern to redact passwords from Redis URLs
_REDIS_URL_PASSWORD = re.compile(r"(redis://[^:]*:)[^@]+(@)")


def _redact_url(url: str) -> str:
    """Redact password from Redis URL for safe logging."""
    return _REDIS_URL_PASSWORD.sub(r"\1***\2", url)

_pool: aioredis.Redis | None = None
_MAX_RETRIES = 5
_BASE_DELAY = 0.5


async def init_redis(url: str, pool_size: int = 10) -> aioredis.Redis:
    """Initialize Redis connection pool with exponential backoff retry."""
    global _pool
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            _pool = aioredis.from_url(
                url,
                max_connections=pool_size,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            await _pool.ping()
            logger.info("redis_connected", url=_redact_url(url), pool_size=pool_size)
            return _pool
        except (aioredis.ConnectionError, OSError) as exc:
            delay = _BASE_DELAY * (2 ** (attempt - 1))
            logger.warning(
                "redis_connect_retry",
                attempt=attempt,
                max_retries=_MAX_RETRIES,
                delay=delay,
                error=str(exc),
            )
            if attempt == _MAX_RETRIES:
                logger.error("redis_connect_failed", error=str(exc))
                _pool = None
                return None
            await asyncio.sleep(delay)
    return None


def get_redis() -> aioredis.Redis | None:
    """Return the current Redis connection pool, or None if unavailable."""
    return _pool


async def ping() -> bool:
    """Check if Redis is reachable."""
    if _pool is None:
        return False
    try:
        return await _pool.ping()
    except Exception:
        return False


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
        logger.info("redis_closed")
