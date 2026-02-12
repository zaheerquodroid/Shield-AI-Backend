"""Tests for rate limiter middleware."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.rate_limiter import RateLimiter


def _mock_redis(execute_return=None, execute_side_effect=None):
    """Create a mock Redis whose pipeline methods are sync (like real redis-py)."""
    pipe = MagicMock()
    pipe.zremrangebyscore = MagicMock(return_value=pipe)
    pipe.zadd = MagicMock(return_value=pipe)
    pipe.zcard = MagicMock(return_value=pipe)
    pipe.expire = MagicMock(return_value=pipe)
    if execute_side_effect:
        pipe.execute = AsyncMock(side_effect=execute_side_effect)
    else:
        pipe.execute = AsyncMock(return_value=execute_return)

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
        redis = _mock_redis(execute_return=[None, None, 10, None])

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None
        assert ctx.extra["rate_limit_remaining"] == 1990  # 2000 - 10

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
        redis = _mock_redis(execute_return=[None, None, 2001, None])

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is not None
        assert result.status_code == 429
        assert "Retry-After" in result.headers
        assert result.headers["X-RateLimit-Remaining"] == "0"

    @pytest.mark.asyncio
    async def test_429_response_body_is_json(self):
        """429 response should have JSON body."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(execute_return=[None, None, 2001, None])

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert b"Rate limit exceeded" in result.body


class TestRateLimiterAuthDetection:
    @pytest.mark.asyncio
    async def test_auth_endpoint_uses_lower_limit(self):
        """Auth endpoints should use the lower auth limit."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(execute_return=[None, None, 501, None])

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request("/auth/login"), ctx)

        assert result is not None
        assert result.status_code == 429

    @pytest.mark.asyncio
    async def test_non_auth_endpoint_allows_higher_count(self):
        """Non-auth endpoints should allow up to the global limit."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(execute_return=[None, None, 501, None])

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request("/api/data"), ctx)

        assert result is None  # allowed


class TestRateLimiterCustomerOverride:
    @pytest.mark.asyncio
    async def test_customer_override_respected(self):
        """Per-customer rate limit overrides should be applied."""
        limiter = RateLimiter()
        ctx = _make_context(rate_overrides={"global_max": 100})
        redis = _mock_redis(execute_return=[None, None, 101, None])

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
        """When Redis raises an error, requests should pass through."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(execute_side_effect=ConnectionError("Redis down"))

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
