"""Tests for rate limiter middleware."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.rate_limiter import RateLimiter


def _mock_redis(current_count, phase2_ok=True, phase1_error=None, phase2_error=None):
    """Create a mock Redis for the two-phase rate limiter.

    Phase 1: zremrangebyscore + zcard → [None, current_count]
    Phase 2: zadd + expire → [None, None]  (only called if allowed)
    """
    call_count = 0

    async def _execute():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            if phase1_error:
                raise phase1_error
            return [None, current_count]
        else:
            if phase2_error:
                raise phase2_error
            return [None, None]

    pipe = MagicMock()
    pipe.zremrangebyscore = MagicMock(return_value=pipe)
    pipe.zadd = MagicMock(return_value=pipe)
    pipe.zcard = MagicMock(return_value=pipe)
    pipe.expire = MagicMock(return_value=pipe)
    pipe.execute = AsyncMock(side_effect=_execute)

    mock = MagicMock()
    mock.pipeline = MagicMock(return_value=pipe)
    return mock


def _make_request(path: str = "/api/data", client_host: str = "127.0.0.1") -> Request:
    """Build a minimal Starlette Request."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [],
        "root_path": "",
        "server": ("localhost", 8080),
        "client": (client_host, 12345),
    }
    return Request(scope)


def _make_context(
    tenant_id: str = "tenant-1",
    rate_limiting: bool = True,
    rate_overrides: dict | None = None,
) -> RequestContext:
    ctx = RequestContext(tenant_id=tenant_id)
    ctx.customer_config = {
        "enabled_features": {"rate_limiting": rate_limiting},
        "settings": {"rate_limits": rate_overrides} if rate_overrides else {},
    }
    return ctx


class TestRateLimiterUnderLimit:
    @pytest.mark.asyncio
    async def test_allows_request_under_limit(self):
        """Requests under the limit should pass through."""
        limiter = RateLimiter()
        ctx = _make_context()
        # 9 existing requests → allowed (9 < 2000), remaining = 2000 - 9 - 1 = 1990
        redis = _mock_redis(current_count=9)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None
        assert ctx.extra["rate_limit_remaining"] == 1990

    @pytest.mark.asyncio
    async def test_injects_rate_limit_headers_on_response(self):
        """Response should have X-RateLimit-* headers."""
        limiter = RateLimiter()
        ctx = _make_context()
        ctx.extra["rate_limit_max"] = 2000
        ctx.extra["rate_limit_remaining"] = 1990
        ctx.extra["rate_limit_reset"] = 1700000000

        response = Response(content="ok", status_code=200)
        result = await limiter.process_response(response, ctx)

        assert result.headers["X-RateLimit-Limit"] == "2000"
        assert result.headers["X-RateLimit-Remaining"] == "1990"
        assert result.headers["X-RateLimit-Reset"] == "1700000000"


class TestRateLimiterOverLimit:
    @pytest.mark.asyncio
    async def test_returns_429_when_exceeded(self):
        """Should return 429 when rate limit is exceeded."""
        limiter = RateLimiter()
        ctx = _make_context()
        # 2001 existing → 2001 >= 2000 → blocked
        redis = _mock_redis(current_count=2001)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is not None
        assert result.status_code == 429
        assert "Retry-After" in result.headers
        assert result.headers["X-RateLimit-Remaining"] == "0"

    @pytest.mark.asyncio
    async def test_allows_at_exact_limit_minus_one(self):
        """1999 existing requests (this is the 2000th) should pass."""
        limiter = RateLimiter()
        ctx = _make_context()
        # 1999 existing → 1999 >= 2000 = false → allowed
        redis = _mock_redis(current_count=1999)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_blocks_at_exact_limit(self):
        """2000 existing requests → 2000 >= 2000 = blocked."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=2000)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is not None
        assert result.status_code == 429

    @pytest.mark.asyncio
    async def test_429_response_body_is_json(self):
        """429 response should have JSON body."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=2001)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert b"Rate limit exceeded" in result.body

    @pytest.mark.asyncio
    async def test_blocked_request_does_not_zadd(self):
        """Blocked requests should NOT be added to the sorted set."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=2000)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result.status_code == 429
        pipe = redis.pipeline()
        # Phase 2 (zadd) should never be called — only 1 execute call (phase 1)
        assert pipe.execute.call_count == 1


class TestRateLimiterAuthDetection:
    @pytest.mark.asyncio
    async def test_auth_endpoint_uses_lower_limit(self):
        """Auth endpoints should use the lower auth limit (500)."""
        limiter = RateLimiter()
        ctx = _make_context()
        # 500 existing → 500 >= 500 → blocked
        redis = _mock_redis(current_count=500)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request("/auth/login"), ctx)

        assert result is not None
        assert result.status_code == 429

    @pytest.mark.asyncio
    async def test_non_auth_endpoint_allows_higher_count(self):
        """Non-auth endpoints should allow up to the global limit."""
        limiter = RateLimiter()
        ctx = _make_context()
        # 500 existing → 500 >= 2000 = false → allowed
        redis = _mock_redis(current_count=500)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request("/api/data"), ctx)

        assert result is None  # allowed


class TestRateLimiterCustomerOverride:
    @pytest.mark.asyncio
    async def test_customer_override_respected(self):
        """Per-customer rate limit overrides should be applied."""
        limiter = RateLimiter()
        ctx = _make_context(rate_overrides={"global_max": 100})
        # 100 existing → 100 >= 100 → blocked
        redis = _mock_redis(current_count=100)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is not None
        assert result.status_code == 429


class TestRateLimiterGraceful:
    @pytest.mark.asyncio
    async def test_redis_unavailable_passes_through(self):
        """When Redis is down, requests should pass through."""
        limiter = RateLimiter()
        ctx = _make_context()

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=None):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_redis_error_passes_through(self):
        """When Redis raises an error on phase 1, requests should pass through."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=0, phase1_error=ConnectionError("Redis down"))

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_phase2_error_still_allows_request(self):
        """If phase 2 (zadd) fails, request was already allowed — no 429."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=5, phase2_error=ConnectionError("Redis flap"))

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None


class TestRateLimiterFeatureFlag:
    @pytest.mark.asyncio
    async def test_disabled_via_feature_flag(self):
        """When rate_limiting is disabled, middleware should be skipped."""
        limiter = RateLimiter()
        ctx = _make_context(rate_limiting=False)

        # Should not even touch Redis
        with patch("proxy.middleware.rate_limiter.get_redis") as mock_get:
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None
        mock_get.assert_not_called()
