"""SHIELD-14 — Add rate limiting rules.

Acceptance Criteria:
  AC1: Auth endpoints (/api/auth/*, /auth/*, /login*) limited to 500 req/5min per IP.
  AC2: Global rate limit of 2000 req/5min per IP.
  AC3: Rate-limited requests return 429 Too Many Requests.
  AC4: Rate limit thresholds are configurable per customer in the dashboard.
  AC5: Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After) included in responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from starlette.responses import Response

from proxy.config.rate_limit_defaults import (
    AUTH_RATE_LIMIT,
    GLOBAL_RATE_LIMIT,
    WINDOW_SECONDS,
    is_auth_endpoint,
)
from proxy.middleware.pipeline import RequestContext
from proxy.middleware.rate_limiter import RateLimiter


def _make_request(path: str = "/") -> MagicMock:
    """Build a mock Starlette request."""
    req = MagicMock()
    req.url = MagicMock()
    req.url.path = path
    return req


def _make_context(
    tenant_id: str = "tenant-1",
    rate_limiting: bool = True,
    rate_overrides: dict | None = None,
) -> RequestContext:
    """Build a RequestContext with customer config."""
    ctx = RequestContext()
    ctx.tenant_id = tenant_id
    ctx.customer_config = {
        "enabled_features": {"rate_limiting": rate_limiting},
        "settings": {},
    }
    if rate_overrides:
        ctx.customer_config["settings"]["rate_limits"] = rate_overrides
    return ctx


def _mock_redis(current_count: int = 0, max_requests: int | None = None):
    """Create a mock Redis that simulates the atomic Lua rate-limit script.

    The Lua script returns [current_count, was_added (1 if under limit, 0 if over)].
    """
    async def _eval(script, num_keys, *args):
        # args: key, window_start, now, max_requests_str, member, ttl
        limit = int(args[3]) if len(args) > 3 else (max_requests or 2000)
        if current_count < limit:
            return [current_count, 1]  # allowed
        return [current_count, 0]  # blocked

    redis = MagicMock()
    redis.eval = _eval
    return redis


# ---------------------------------------------------------------------------
# AC1: Auth endpoints limited to 500 req/5min
# ---------------------------------------------------------------------------


class TestAC1_AuthEndpointRateLimiting:
    """Auth endpoints are detected and rate-limited at 500 req/5min."""

    def test_auth_default_threshold_is_500(self):
        """Default auth rate limit is 500 requests."""
        assert AUTH_RATE_LIMIT == 500

    def test_default_window_is_5_minutes(self):
        """Default window is 300 seconds (5 minutes)."""
        assert WINDOW_SECONDS == 300

    @pytest.mark.parametrize("path", [
        "/auth/login",
        "/api/auth/token",
        "/login",
        "/api/login",
        "/signup",
        "/register",
        "/token",
        "/oauth/callback",
        "/password/reset",
        "/session/create",
    ])
    def test_auth_endpoints_detected(self, path: str):
        """All auth URL patterns are correctly identified."""
        assert is_auth_endpoint(path) is True

    @pytest.mark.parametrize("path", [
        "/",
        "/api/users",
        "/health",
        "/api/data/export",
        "/dashboard",
    ])
    def test_non_auth_endpoints_not_flagged(self, path: str):
        """Regular endpoints are not flagged as auth."""
        assert is_auth_endpoint(path) is False

    @pytest.mark.asyncio
    async def test_auth_endpoint_under_limit_passes(self):
        """Auth endpoint with count < 500 is allowed."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=499)
        ctx = _make_context()
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result is None  # allowed

    @pytest.mark.asyncio
    async def test_auth_endpoint_at_limit_blocked(self):
        """Auth endpoint with count >= 500 is blocked."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=500)
        ctx = _make_context()
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result is not None
        assert result.status_code == 429


# ---------------------------------------------------------------------------
# AC2: Global rate limit of 2000 req/5min
# ---------------------------------------------------------------------------


class TestAC2_GlobalRateLimit:
    """Global rate limit is 2000 req/5min."""

    def test_global_default_threshold_is_2000(self):
        """Default global rate limit is 2000 requests."""
        assert GLOBAL_RATE_LIMIT == 2000

    @pytest.mark.asyncio
    async def test_global_under_limit_passes(self):
        """Regular endpoint with count < 2000 is allowed."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=1999)
        ctx = _make_context()
        req = _make_request("/api/users")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_global_at_limit_blocked(self):
        """Regular endpoint with count >= 2000 is blocked."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=2000)
        ctx = _make_context()
        req = _make_request("/api/users")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result is not None
        assert result.status_code == 429


# ---------------------------------------------------------------------------
# AC3: Rate-limited requests return 429 Too Many Requests
# ---------------------------------------------------------------------------


class TestAC3_429Response:
    """Blocked requests return 429 with correct body and headers."""

    @pytest.mark.asyncio
    async def test_429_status_code(self):
        """Blocked request returns HTTP 429."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=500)
        ctx = _make_context()
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result.status_code == 429

    @pytest.mark.asyncio
    async def test_429_json_body(self):
        """429 response has JSON error body."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=500)
        ctx = _make_context()
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result.media_type == "application/json"
        assert b"Rate limit exceeded" in result.body

    @pytest.mark.asyncio
    async def test_429_retry_after_header(self):
        """429 response includes Retry-After header equal to window."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=500)
        ctx = _make_context()
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result.headers["Retry-After"] == "300"

    @pytest.mark.asyncio
    async def test_redis_down_fails_closed(self):
        """When Redis is unavailable, requests are rejected (fail-closed)."""
        limiter = RateLimiter()
        ctx = _make_context()
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=None):
            result = await limiter.process_request(req, ctx)

        assert result is not None
        assert result.status_code == 503

    @pytest.mark.asyncio
    async def test_feature_flag_off_skips_rate_limiting(self):
        """Rate limiting disabled via feature flag → request passes without touching Redis."""
        limiter = RateLimiter()
        ctx = _make_context(rate_limiting=False)
        req = _make_request("/auth/login")
        mock_get_redis = MagicMock(return_value=MagicMock())

        with patch("proxy.middleware.rate_limiter.get_redis", mock_get_redis):
            result = await limiter.process_request(req, ctx)

        assert result is None
        mock_get_redis.assert_not_called()  # Redis should never be touched


# ---------------------------------------------------------------------------
# AC4: Per-customer configurable thresholds
# ---------------------------------------------------------------------------


class TestAC4_PerCustomerThresholds:
    """Rate limit thresholds are configurable per customer."""

    @pytest.mark.asyncio
    async def test_customer_auth_max_override(self):
        """Customer with auth_max=100 is blocked at 100, not 500."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=100)
        ctx = _make_context(rate_overrides={"auth_max": 100})
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result is not None
        assert result.status_code == 429

    @pytest.mark.asyncio
    async def test_customer_auth_max_under_custom_limit_passes(self):
        """Customer with auth_max=100 allows requests under 100."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=50)
        ctx = _make_context(rate_overrides={"auth_max": 100})
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_customer_global_max_override(self):
        """Customer with global_max=500 is blocked at 500, not 2000."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=500)
        ctx = _make_context(rate_overrides={"global_max": 500})
        req = _make_request("/api/users")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert result is not None
        assert result.status_code == 429

    @pytest.mark.asyncio
    async def test_customer_window_override(self):
        """Customer with window_seconds=60 uses 60s window."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=500)
        ctx = _make_context(rate_overrides={"window_seconds": 60})
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        # Retry-After should be 60 (from custom window), not 300
        assert result.headers["Retry-After"] == "60"

    def test_rate_limits_api_endpoint(self):
        """PUT /apps/{id}/rate-limits merges into existing settings."""
        import proxy.main as main_module
        main_module._pipeline = None
        main_module._http_client = None

        from proxy.main import app

        aid = uuid4()
        mock_app = {"id": str(aid), "settings": {"rate_limits": {"global_max": 500}}}
        mock_updated = {**mock_app, "settings": {"rate_limits": {"global_max": 500, "auth_max": 100}}}

        with TestClient(app, raise_server_exceptions=False) as c:
            mock_update = AsyncMock(return_value=mock_updated)
            with (
                patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=mock_app),
                patch("proxy.api.config_routes.pg_store.update_app", mock_update),
            ):
                resp = c.put(
                    f"/api/config/apps/{aid}/rate-limits",
                    json={"auth_max": 100},
                    headers={"Authorization": "Bearer test-api-key"},
                )
                assert resp.status_code == 200
                # Verify update_app was called with merged settings
                call_kwargs = mock_update.call_args
                settings_arg = call_kwargs.kwargs.get("settings") or call_kwargs[1].get("settings")
                assert settings_arg["rate_limits"]["global_max"] == 500  # preserved
                assert settings_arg["rate_limits"]["auth_max"] == 100  # added


# ---------------------------------------------------------------------------
# AC5: Rate limit headers in responses
# ---------------------------------------------------------------------------


class TestAC5_RateLimitHeaders:
    """Rate limit headers are included in all proxied responses."""

    @pytest.mark.asyncio
    async def test_response_includes_rate_limit_limit(self):
        """X-RateLimit-Limit header is set."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=10)
        ctx = _make_context()
        req = _make_request("/api/users")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            await limiter.process_request(req, ctx)

        resp = Response(content="ok", status_code=200)
        resp = await limiter.process_response(resp, ctx)
        assert resp.headers["X-RateLimit-Limit"] == "2000"

    @pytest.mark.asyncio
    async def test_response_includes_rate_limit_remaining(self):
        """X-RateLimit-Remaining header is set with correct value."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=10)
        ctx = _make_context()
        req = _make_request("/api/users")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            await limiter.process_request(req, ctx)

        resp = Response(content="ok", status_code=200)
        resp = await limiter.process_response(resp, ctx)
        # remaining = max(0, 2000 - 10 - 1) = 1989
        assert resp.headers["X-RateLimit-Remaining"] == "1989"

    @pytest.mark.asyncio
    async def test_response_includes_rate_limit_reset(self):
        """X-RateLimit-Reset header is set."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=10)
        ctx = _make_context()
        req = _make_request("/api/users")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            await limiter.process_request(req, ctx)

        resp = Response(content="ok", status_code=200)
        resp = await limiter.process_response(resp, ctx)
        assert "X-RateLimit-Reset" in resp.headers
        # Reset should be a timestamp (integer string)
        int(resp.headers["X-RateLimit-Reset"])

    @pytest.mark.asyncio
    async def test_429_includes_all_rate_limit_headers(self):
        """429 response includes all three rate limit headers."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=2000)
        ctx = _make_context()
        req = _make_request("/api/users")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            result = await limiter.process_request(req, ctx)

        assert "Retry-After" in result.headers
        assert "X-RateLimit-Limit" in result.headers
        assert "X-RateLimit-Remaining" in result.headers
        assert result.headers["X-RateLimit-Remaining"] == "0"

    @pytest.mark.asyncio
    async def test_headers_not_added_when_rate_limiting_disabled(self):
        """No rate limit headers when feature flag is off — Redis never touched."""
        limiter = RateLimiter()
        ctx = _make_context(rate_limiting=False)
        req = _make_request("/api/users")
        mock_get_redis = MagicMock(return_value=MagicMock())

        with patch("proxy.middleware.rate_limiter.get_redis", mock_get_redis):
            await limiter.process_request(req, ctx)

        mock_get_redis.assert_not_called()

        resp = Response(content="ok", status_code=200)
        resp = await limiter.process_response(resp, ctx)
        assert "X-RateLimit-Limit" not in resp.headers
        assert "X-RateLimit-Remaining" not in resp.headers
        assert "X-RateLimit-Reset" not in resp.headers

    @pytest.mark.asyncio
    async def test_auth_endpoint_shows_auth_limit_in_header(self):
        """Auth endpoint shows 500 (auth limit) in X-RateLimit-Limit, not 2000."""
        limiter = RateLimiter()
        redis = _mock_redis(current_count=10)
        ctx = _make_context()
        req = _make_request("/auth/login")

        with patch("proxy.middleware.rate_limiter.get_redis", return_value=redis):
            await limiter.process_request(req, ctx)

        resp = Response(content="ok", status_code=200)
        resp = await limiter.process_response(resp, ctx)
        assert resp.headers["X-RateLimit-Limit"] == "500"
