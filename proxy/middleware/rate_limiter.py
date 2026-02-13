"""Redis sliding-window rate limiter middleware."""

from __future__ import annotations

import time

import structlog
from starlette.requests import Request
from starlette.responses import Response

from proxy.config.loader import get_settings
from proxy.config.rate_limit_defaults import is_auth_endpoint
from proxy.middleware.pipeline import Middleware, RequestContext
from proxy.store.redis import get_redis

logger = structlog.get_logger()

# Redis key prefix
_KEY_PREFIX = "ratelimit"

# Atomic Lua script: cleanup + count + conditional add in one operation.
# Eliminates the TOCTOU race between count check and increment.
# Returns [current_count, was_added (0 or 1)]
_RATE_LIMIT_LUA = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local member = ARGV[4]
local ttl = tonumber(ARGV[5])

-- Phase 1: cleanup expired entries
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

-- Phase 2: count current window
local count = redis.call('ZCARD', key)

-- Phase 3: conditionally add if under limit
if count < max_requests then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, ttl)
    return {count, 1}
end

return {count, 0}
"""


class RateLimiter(Middleware):
    """Sliding-window rate limiter backed by Redis sorted sets.

    - Auth endpoints: lower threshold (default 500/5min)
    - Global: higher threshold (default 2000/5min)
    - Per-customer overrides via settings JSONB
    - Fail-closed when Redis is unavailable (returns 503)
    - Atomic check+increment via Lua script (no TOCTOU race)
    - Injects X-RateLimit-* response headers
    """

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        # Check feature flag
        features = context.customer_config.get("enabled_features", {})
        if not features.get("rate_limiting", True):
            return None

        redis = get_redis()
        if redis is None:
            # Fail-closed: no rate limiting backend = reject requests
            logger.error("rate_limiter_no_redis", action="fail_closed")
            return Response(
                content='{"error": "Service temporarily unavailable"}',
                status_code=503,
                media_type="application/json",
            )

        settings = get_settings()
        path = request.url.path
        is_auth = is_auth_endpoint(path)

        # Determine limits — check per-customer overrides first
        customer_settings = context.customer_config.get("settings", {})
        rate_overrides = customer_settings.get("rate_limits", {})

        if is_auth:
            max_requests = rate_overrides.get("auth_max", settings.rate_limit_auth_max)
            window = rate_overrides.get("window_seconds", settings.rate_limit_window_seconds)
        else:
            max_requests = rate_overrides.get("global_max", settings.rate_limit_global_max)
            window = rate_overrides.get("window_seconds", settings.rate_limit_window_seconds)

        # Build rate-limit key: per-customer + per-type
        tenant_id = context.tenant_id or "global"
        limit_type = "auth" if is_auth else "global"
        key = f"{_KEY_PREFIX}:{tenant_id}:{limit_type}"

        now = time.time()
        window_start = now - window
        member = f"{now}:{context.request_id}"

        # Atomic rate-limit check via Lua script (eliminates TOCTOU race)
        try:
            result = await redis.eval(
                _RATE_LIMIT_LUA,
                1,  # number of keys
                key,
                str(window_start),
                str(now),
                str(max_requests),
                member,
                str(int(window) + 1),
            )
            current_count = int(result[0])
            was_added = int(result[1])
        except Exception as exc:
            # Fail-closed: Redis error = reject requests
            logger.error("rate_limiter_redis_error", error=str(exc), action="fail_closed")
            return Response(
                content='{"error": "Service temporarily unavailable"}',
                status_code=503,
                media_type="application/json",
            )

        if was_added:
            # Request allowed
            remaining = max(0, max_requests - current_count - 1)
            context.extra["rate_limit_max"] = max_requests
            context.extra["rate_limit_remaining"] = remaining
            context.extra["rate_limit_reset"] = int(now + window)
            return None

        # Rate limited
        retry_after = int(window)
        logger.warning(
            "rate_limit_exceeded",
            tenant_id=tenant_id,
            limit_type=limit_type,
            current=current_count,
            max=max_requests,
            request_id=context.request_id,
        )

        context.extra["rate_limit_max"] = max_requests
        context.extra["rate_limit_remaining"] = 0
        context.extra["rate_limit_reset"] = int(now + window)

        return Response(
            content='{"error": "Rate limit exceeded"}',
            status_code=429,
            media_type="application/json",
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(max_requests),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(now + window)),
            },
        )

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        """Inject X-RateLimit-* headers into successful responses."""
        if "rate_limit_max" in context.extra:
            response.headers["X-RateLimit-Limit"] = str(context.extra["rate_limit_max"])
            response.headers["X-RateLimit-Remaining"] = str(context.extra["rate_limit_remaining"])
            response.headers["X-RateLimit-Reset"] = str(context.extra["rate_limit_reset"])
        return response
