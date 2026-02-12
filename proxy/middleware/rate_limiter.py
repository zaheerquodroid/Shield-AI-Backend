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


class RateLimiter(Middleware):
    """Sliding-window rate limiter backed by Redis sorted sets.

    - Auth endpoints: lower threshold (default 500/5min)
    - Global: higher threshold (default 2000/5min)
    - Per-customer overrides via settings JSONB
    - Graceful degradation if Redis is unavailable
    - Injects X-RateLimit-* response headers
    """

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        # Check feature flag
        features = context.customer_config.get("enabled_features", {})
        if not features.get("rate_limiting", True):
            return None

        redis = get_redis()
        if redis is None:
            logger.warning("rate_limiter_no_redis", action="pass_through")
            return None

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

        # Phase 1: cleanup expired entries and count current window
        try:
            pipe = redis.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zcard(key)
            results = await pipe.execute()
            current_count = results[1]
        except Exception as exc:
            logger.warning("rate_limiter_redis_error", error=str(exc), action="pass_through")
            return None

        # Store rate-limit info for response headers
        # current_count is BEFORE adding this request; after adding, remaining decreases by 1
        remaining = max(0, max_requests - current_count - 1)
        context.extra["rate_limit_max"] = max_requests
        context.extra["rate_limit_remaining"] = remaining
        context.extra["rate_limit_reset"] = int(now + window)

        if current_count >= max_requests:
            # Blocked — do NOT add to sorted set (prevents counter inflation)
            retry_after = int(window)
            logger.warning(
                "rate_limit_exceeded",
                tenant_id=tenant_id,
                limit_type=limit_type,
                current=current_count,
                max=max_requests,
                request_id=context.request_id,
            )
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

        # Phase 2: request allowed — record it and set TTL
        try:
            pipe = redis.pipeline()
            pipe.zadd(key, {f"{now}:{context.request_id}": now})
            pipe.expire(key, window + 1)
            await pipe.execute()
        except Exception as exc:
            logger.warning("rate_limiter_track_error", error=str(exc))

        return None

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        """Inject X-RateLimit-* headers into successful responses."""
        if "rate_limit_max" in context.extra:
            response.headers["X-RateLimit-Limit"] = str(context.extra["rate_limit_max"])
            response.headers["X-RateLimit-Remaining"] = str(context.extra["rate_limit_remaining"])
            response.headers["X-RateLimit-Reset"] = str(context.extra["rate_limit_reset"])
        return response
