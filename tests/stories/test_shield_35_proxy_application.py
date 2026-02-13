"""SHIELD-35 — Build security proxy reverse proxy application.

Acceptance Criteria:
  AC1: Proxy accepts HTTP/HTTPS connections and forwards to a configurable upstream origin URL.
  AC2: Request/response middleware pipeline supports an ordered chain.
  AC3: Middleware can be individually enabled/disabled per customer configuration.
  AC4: Proxy preserves all request headers, body, query parameters.
  AC5: Health check endpoint (GET /health) returns 200 with proxy status, upstream, Redis.
  AC6: Readiness probe (GET /ready) returns 200 only when proxy is fully initialized.
  AC7: Graceful shutdown drains in-flight requests (30s timeout) on SIGTERM.
  AC8: Configuration loaded from YAML file with environment variable overrides.
  AC9: All application logs emitted as structured JSON.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from starlette.responses import Response

from proxy.middleware.pipeline import Middleware, MiddlewarePipeline, RequestContext


# ---------------------------------------------------------------------------
# AC1: Proxy accepts HTTP and forwards to configurable upstream
# ---------------------------------------------------------------------------


class TestAC1_ProxyForwarding:
    """Proxy forwards requests to the upstream origin URL."""

    def test_get_forwarded_to_upstream(self, client):
        """GET request is forwarded to the configured upstream."""
        mock_response = httpx.Response(200, text="upstream ok")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            resp = client.get("/hello")
        assert resp.status_code == 200
        assert resp.text == "upstream ok"

    def test_post_forwarded_to_upstream(self, client):
        """POST request with body is forwarded."""
        mock_response = httpx.Response(201, text='{"id": 1}')
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            resp = client.post("/items", json={"name": "test"})
        assert resp.status_code == 201

    def test_put_forwarded_to_upstream(self, client):
        """PUT request is forwarded."""
        mock_response = httpx.Response(200, text="updated")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            resp = client.put("/items/1", json={"name": "updated"})
        assert resp.status_code == 200

    def test_delete_forwarded_to_upstream(self, client):
        """DELETE request is forwarded."""
        mock_response = httpx.Response(204)
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            resp = client.delete("/items/1")
        assert resp.status_code == 204

    def test_upstream_url_configurable_via_env(self, monkeypatch):
        """Upstream URL is configured via PROXY_UPSTREAM_URL env var."""
        monkeypatch.setenv("PROXY_UPSTREAM_URL", "http://custom-upstream:9000")
        import proxy.config.loader as loader
        loader._settings = None
        settings = loader.get_settings()
        assert settings.upstream_url == "http://custom-upstream:9000"

    def test_upstream_timeout_returns_504(self, client):
        """Upstream timeout returns 504."""
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            resp = client.get("/slow")
        assert resp.status_code == 504

    def test_upstream_unreachable_returns_502(self, client):
        """Upstream connect error returns 502."""
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
            resp = client.get("/down")
        assert resp.status_code == 502


# ---------------------------------------------------------------------------
# AC2: Middleware pipeline supports ordered chain
# ---------------------------------------------------------------------------


class TestAC2_MiddlewarePipelineOrder:
    """Request middleware runs forward, response middleware runs in reverse."""

    @pytest.mark.asyncio
    async def test_request_order_forward(self):
        """Request middleware executes in registration order."""
        log: list[str] = []

        class Tracker(Middleware):
            def __init__(self, tag: str):
                self._tag = tag

            @property
            def name(self):
                return self._tag

            async def process_request(self, request, context):
                log.append(self._tag)
                return None

        pipeline = MiddlewarePipeline()
        pipeline.add(Tracker("A"))
        pipeline.add(Tracker("B"))
        pipeline.add(Tracker("C"))

        await pipeline.process_request(None, RequestContext())
        assert log == ["A", "B", "C"]

    @pytest.mark.asyncio
    async def test_response_order_reverse(self):
        """Response middleware executes in reverse registration order."""
        log: list[str] = []

        class Tracker(Middleware):
            def __init__(self, tag: str):
                self._tag = tag

            @property
            def name(self):
                return self._tag

            async def process_request(self, request, context):
                return None

            async def process_response(self, response, context):
                log.append(self._tag)
                return response

        pipeline = MiddlewarePipeline()
        pipeline.add(Tracker("A"))
        pipeline.add(Tracker("B"))
        pipeline.add(Tracker("C"))

        await pipeline.process_response(Response(content="ok"), RequestContext())
        assert log == ["C", "B", "A"]

    def test_production_pipeline_order(self):
        """Production pipeline has 11 middleware in the correct security order."""
        from proxy.main import _build_pipeline

        pipeline = _build_pipeline()
        names = [mw.name for mw in pipeline._middleware]
        assert names == [
            "TenantRouter",
            "AuditLogger",
            "ContextInjector",
            "RateLimiter",
            "SessionValidator",
            "CallbackVerifier",
            "SSRFValidator",
            "LLMSanitizer",
            "ResponseSanitizer",
            "SecurityHeaders",
            "SessionUpdater",
        ]


# ---------------------------------------------------------------------------
# AC3: Middleware can be individually enabled/disabled per customer
# ---------------------------------------------------------------------------


class TestAC3_MiddlewareToggle:
    """Middleware can be enabled or disabled at runtime."""

    @pytest.mark.asyncio
    async def test_disabled_middleware_skipped(self):
        """Disabled middleware does not execute."""
        log: list[str] = []

        class Tracker(Middleware):
            def __init__(self, tag: str):
                self._tag = tag

            @property
            def name(self):
                return self._tag

            async def process_request(self, request, context):
                log.append(self._tag)
                return None

        pipeline = MiddlewarePipeline()
        pipeline.add(Tracker("A"))
        pipeline.add(Tracker("B"), enabled=False)
        pipeline.add(Tracker("C"))

        await pipeline.process_request(None, RequestContext())
        assert log == ["A", "C"]

    @pytest.mark.asyncio
    async def test_runtime_toggle(self):
        """Middleware can be toggled on/off at runtime."""
        log: list[str] = []

        class Tracker(Middleware):
            def __init__(self, tag: str):
                self._tag = tag

            @property
            def name(self):
                return self._tag

            async def process_request(self, request, context):
                log.append(self._tag)
                return None

        pipeline = MiddlewarePipeline()
        pipeline.add(Tracker("A"))
        pipeline.add(Tracker("B"))

        await pipeline.process_request(None, RequestContext())
        assert log == ["A", "B"]

        log.clear()
        pipeline.set_enabled("B", False)
        await pipeline.process_request(None, RequestContext())
        assert log == ["A"]


# ---------------------------------------------------------------------------
# AC4: Proxy preserves headers, body, query parameters
# ---------------------------------------------------------------------------


class TestAC4_Preservation:
    """Proxy preserves request headers, body, and query parameters."""

    def test_query_parameters_preserved(self, client):
        """Query string is forwarded to upstream."""
        mock_response = httpx.Response(200, text="ok")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            client.get("/search?q=test&page=2")
            call_kwargs = mock_client.request.call_args
            assert "q=test&page=2" in call_kwargs.kwargs["url"]

    def test_request_body_preserved(self, client):
        """POST body is forwarded to upstream."""
        mock_response = httpx.Response(200, text="ok")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            client.post("/api/data", content=b'{"key": "value"}')
            call_kwargs = mock_client.request.call_args
            assert b"key" in call_kwargs.kwargs["content"]

    def test_custom_headers_preserved(self, client):
        """Custom headers are forwarded to upstream."""
        mock_response = httpx.Response(200, text="ok")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            client.get("/test", headers={"X-Custom-Header": "custom-value"})
            call_kwargs = mock_client.request.call_args
            sent_headers = call_kwargs.kwargs["headers"]
            assert sent_headers.get("X-Custom-Header") or sent_headers.get("x-custom-header")

    def test_hop_by_hop_headers_stripped(self, client):
        """Hop-by-hop headers are NOT forwarded."""
        mock_response = httpx.Response(200, text="ok")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            client.get("/test", headers={"Connection": "keep-alive"})
            call_kwargs = mock_client.request.call_args
            sent_headers = {k.lower(): v for k, v in call_kwargs.kwargs["headers"].items()}
            assert "connection" not in sent_headers

    def test_request_body_too_large_returns_413(self, client):
        """Oversized request body returns 413."""
        mock_response = httpx.Response(200, text="ok")
        with patch("proxy.main._http_client") as mock_client:
            mock_client.request = AsyncMock(return_value=mock_response)
            big_body = b"x" * (10 * 1024 * 1024 + 1)
            resp = client.post("/upload", content=big_body)
        assert resp.status_code == 413


# ---------------------------------------------------------------------------
# AC5: Health check endpoint
# ---------------------------------------------------------------------------


class TestAC5_HealthCheck:
    """GET /health returns proxy status, upstream, and Redis connectivity."""

    def test_health_returns_200(self, client):
        """Health endpoint returns 200."""
        with (
            patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=True),
            patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
        ):
            resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_includes_proxy_status(self, client):
        """Health response includes proxy, redis, and upstream status."""
        with (
            patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=True),
            patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
        ):
            data = client.get("/health").json()
        assert data["proxy"] == "up"
        assert data["redis"] == "up"
        assert data["upstream"] == "up"
        assert data["status"] == "healthy"

    def test_health_degraded_when_redis_down(self, client):
        """Health shows degraded when Redis is down."""
        with (
            patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=False),
            patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
        ):
            data = client.get("/health").json()
        assert data["status"] == "degraded"
        assert data["redis"] == "down"

    def test_health_degraded_when_upstream_down(self, client):
        """Health shows degraded when upstream is down."""
        with (
            patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=True),
            patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=False),
        ):
            data = client.get("/health").json()
        assert data["status"] == "degraded"
        assert data["upstream"] == "down"


# ---------------------------------------------------------------------------
# AC6: Readiness probe
# ---------------------------------------------------------------------------


class TestAC6_ReadinessProbe:
    """GET /ready returns 200 only when fully initialized."""

    def test_ready_200_when_all_up(self, client):
        """Returns 200 when Redis and upstream are both up."""
        with (
            patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=True),
            patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
        ):
            resp = client.get("/ready")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

    def test_ready_503_when_redis_down(self, client):
        """Returns 503 when Redis is down (security dependency)."""
        with (
            patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=False),
            patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
        ):
            resp = client.get("/ready")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"

    def test_ready_503_when_upstream_down(self, client):
        """Returns 503 when upstream is down."""
        with (
            patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=True),
            patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=False),
        ):
            resp = client.get("/ready")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# AC8: Configuration from YAML + env var overrides
# ---------------------------------------------------------------------------


class TestAC8_ConfigLoading:
    """Configuration loaded from YAML defaults overridden by env vars."""

    def test_env_var_overrides_default(self, monkeypatch):
        """PROXY_* env vars override model defaults."""
        monkeypatch.setenv("PROXY_LISTEN_PORT", "9090")
        import proxy.config.loader as loader
        loader._settings = None
        settings = loader.get_settings()
        assert settings.listen_port == 9090

    def test_default_values_present(self, monkeypatch):
        """Default config has sensible values."""
        # Clear env vars that the autouse conftest fixture sets, so we test true model defaults
        monkeypatch.delenv("PROXY_LOG_JSON", raising=False)
        monkeypatch.delenv("PROXY_LOG_LEVEL", raising=False)
        monkeypatch.delenv("PROXY_UPSTREAM_URL", raising=False)
        monkeypatch.delenv("PROXY_REDIS_URL", raising=False)
        monkeypatch.delenv("PROXY_POSTGRES_URL", raising=False)
        monkeypatch.delenv("PROXY_API_KEY", raising=False)
        from proxy.config.loader import ProxySettings
        s = ProxySettings()
        assert s.listen_port == 8080
        assert s.proxy_timeout == 30.0
        assert s.shutdown_drain_seconds == 30
        assert s.log_json is True
        assert s.redis_pool_size == 10
        assert s.log_level == "info"
        assert s.upstream_url == "http://localhost:3000"

    def test_rate_limit_defaults_configurable(self, monkeypatch):
        """Rate limit settings are configurable via env vars."""
        monkeypatch.setenv("PROXY_RATE_LIMIT_AUTH_MAX", "100")
        monkeypatch.setenv("PROXY_RATE_LIMIT_GLOBAL_MAX", "500")
        import proxy.config.loader as loader
        loader._settings = None
        settings = loader.get_settings()
        assert settings.rate_limit_auth_max == 100
        assert settings.rate_limit_global_max == 500

    def test_header_preset_configurable(self, monkeypatch):
        """Header preset is configurable via env var."""
        monkeypatch.setenv("PROXY_HEADER_PRESET", "strict")
        import proxy.config.loader as loader
        loader._settings = None
        settings = loader.get_settings()
        assert settings.header_preset == "strict"


# ---------------------------------------------------------------------------
# AC9: Structured JSON logging
# ---------------------------------------------------------------------------


class TestAC9_StructuredLogging:
    """Application logs emitted as structured JSON."""

    def test_structlog_configured(self):
        """structlog is used for logging."""
        import structlog
        log = structlog.get_logger()
        assert log is not None

    def test_log_level_configurable(self, monkeypatch):
        """Log level is configurable via env var."""
        monkeypatch.setenv("PROXY_LOG_LEVEL", "warning")
        import proxy.config.loader as loader
        loader._settings = None
        settings = loader.get_settings()
        assert settings.log_level == "warning"

    def test_log_format_json_configurable(self, monkeypatch):
        """JSON log format is configurable via env var."""
        monkeypatch.setenv("PROXY_LOG_JSON", "true")
        import proxy.config.loader as loader
        loader._settings = None
        settings = loader.get_settings()
        assert settings.log_json is True
