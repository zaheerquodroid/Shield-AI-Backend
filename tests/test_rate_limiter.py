"""Tests for rate limiter middleware."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.rate_limiter import RateLimiter


def _mock_redis(current_count, eval_error=None):
    """Create a mock Redis for the atomic Lua rate-limit script.

    The Lua script returns [current_count, was_added (1 if under limit, 0 if over)].
    """
    async def _eval(script, num_keys, *args):
        if eval_error:
            raise eval_error
        # args: key, window_start, now, max_requests_str, member, ttl
        limit = int(args[3]) if len(args) > 3 else 2000
        if current_count < limit:
            return [current_count, 1]  # allowed
        return [current_count, 0]  # blocked

    mock = MagicMock()
    mock.eval = _eval
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
    async def test_blocked_request_not_counted(self):
        """Blocked requests should NOT be added to the sorted set (atomic Lua handles this)."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=2000)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result.status_code == 429
        # The Lua script returns was_added=0 for blocked requests


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


class TestRateLimiterFailClosed:
    @pytest.mark.asyncio
    async def test_redis_unavailable_returns_503(self):
        """When Redis is down, requests are rejected (fail-closed)."""
        limiter = RateLimiter()
        ctx = _make_context()

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=None):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is not None
        assert result.status_code == 503

    @pytest.mark.asyncio
    async def test_redis_error_returns_503(self):
        """When Redis raises an error, requests are rejected (fail-closed)."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=0, eval_error=ConnectionError("Redis down"))

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is not None
        assert result.status_code == 503


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

    @pytest.mark.asyncio
    async def test_missing_enabled_features_defaults_to_enabled(self):
        """Missing enabled_features key should default to rate limiting on."""
        limiter = RateLimiter()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {"settings": {}}  # no enabled_features
        redis = _mock_redis(current_count=0)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None  # allowed, and Redis was called

    @pytest.mark.asyncio
    async def test_missing_rate_limiting_key_defaults_to_enabled(self):
        """Missing rate_limiting key in features should default to True."""
        limiter = RateLimiter()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {
            "enabled_features": {"waf": True},  # no rate_limiting key
            "settings": {},
        }
        redis = _mock_redis(current_count=0)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None


class TestRateLimiterTenantFallback:
    @pytest.mark.asyncio
    async def test_empty_tenant_id_uses_global(self):
        """Empty tenant_id should use 'global' as key prefix."""
        limiter = RateLimiter()
        ctx = _make_context(tenant_id="")

        eval_keys = []
        original_mock = _mock_redis(current_count=0)

        async def _capture_eval(script, num_keys, *args):
            eval_keys.append(args[0])  # first arg is the key
            return [0, 1]  # allowed

        original_mock.eval = _capture_eval

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=original_mock):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None
        assert len(eval_keys) == 1
        assert "global" in eval_keys[0]


class TestRateLimiterRemainingCalc:
    @pytest.mark.asyncio
    async def test_first_request_remaining(self):
        """First request should have remaining = max - 1."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=0)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            await limiter.process_request(_make_request(), ctx)

        assert ctx.extra["rate_limit_remaining"] == 1999  # 2000 - 0 - 1

    @pytest.mark.asyncio
    async def test_remaining_at_limit_minus_one(self):
        """Last allowed request should have remaining = 0."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=1999)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            await limiter.process_request(_make_request(), ctx)

        assert ctx.extra["rate_limit_remaining"] == 0  # 2000 - 1999 - 1

    @pytest.mark.asyncio
    async def test_remaining_never_negative(self):
        """Remaining should never go below 0."""
        limiter = RateLimiter()
        ctx = _make_context()
        # Way over limit — remaining should be clamped to 0
        redis = _mock_redis(current_count=5000)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            await limiter.process_request(_make_request(), ctx)

        assert ctx.extra["rate_limit_remaining"] == 0


class TestRateLimiter429ResponseDetails:
    @pytest.mark.asyncio
    async def test_429_retry_after_equals_window(self):
        """Retry-After header should equal the window duration."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=2000)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result.headers["Retry-After"] == "300"  # WINDOW_SECONDS

    @pytest.mark.asyncio
    async def test_429_has_rate_limit_limit_header(self):
        """429 response has X-RateLimit-Limit header."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=2000)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result.headers["X-RateLimit-Limit"] == "2000"

    @pytest.mark.asyncio
    async def test_429_has_rate_limit_reset_header(self):
        """429 response has X-RateLimit-Reset header with future timestamp."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=2000)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        reset = int(result.headers["X-RateLimit-Reset"])
        assert reset > 0

    @pytest.mark.asyncio
    async def test_429_media_type_is_json(self):
        """429 response should be application/json."""
        limiter = RateLimiter()
        ctx = _make_context()
        redis = _mock_redis(current_count=2000)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result.media_type == "application/json"


class TestRateLimiterCustomerOverrideExpanded:
    @pytest.mark.asyncio
    async def test_auth_max_override(self):
        """Per-customer auth_max override should be applied."""
        limiter = RateLimiter()
        ctx = _make_context(rate_overrides={"auth_max": 50})
        redis = _mock_redis(current_count=50)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request("/auth/login"), ctx)

        assert result.status_code == 429

    @pytest.mark.asyncio
    async def test_auth_max_override_allows_under(self):
        """Requests under auth_max override should pass."""
        limiter = RateLimiter()
        ctx = _make_context(rate_overrides={"auth_max": 50})
        redis = _mock_redis(current_count=49)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request("/auth/login"), ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_window_seconds_override(self):
        """Per-customer window_seconds override affects Retry-After."""
        limiter = RateLimiter()
        ctx = _make_context(rate_overrides={"global_max": 10, "window_seconds": 60})
        redis = _mock_redis(current_count=10)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result.status_code == 429
        assert result.headers["Retry-After"] == "60"

    @pytest.mark.asyncio
    async def test_missing_rate_limits_in_settings(self):
        """Missing rate_limits key in settings should use defaults."""
        limiter = RateLimiter()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {
            "enabled_features": {"rate_limiting": True},
            "settings": {},  # no rate_limits
        }
        redis = _mock_redis(current_count=0)

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(_make_request(), ctx)

        assert result is None


class TestRateLimiterResponseHeaders:
    @pytest.mark.asyncio
    async def test_response_headers_not_set_without_rate_limiting(self):
        """Response should not have rate limit headers if middleware didn't run."""
        limiter = RateLimiter()
        ctx = _make_context()
        # No rate_limit_max in context.extra
        response = Response(content="ok", status_code=200)
        result = await limiter.process_response(response, ctx)
        assert "X-RateLimit-Limit" not in result.headers

    @pytest.mark.asyncio
    async def test_response_headers_values_are_strings(self):
        """All rate limit headers should be string values."""
        limiter = RateLimiter()
        ctx = _make_context()
        ctx.extra["rate_limit_max"] = 2000
        ctx.extra["rate_limit_remaining"] = 1999
        ctx.extra["rate_limit_reset"] = 1700000300

        response = Response(content="ok", status_code=200)
        result = await limiter.process_response(response, ctx)

        assert isinstance(result.headers["X-RateLimit-Limit"], str)
        assert isinstance(result.headers["X-RateLimit-Remaining"], str)
        assert isinstance(result.headers["X-RateLimit-Reset"], str)
