"""Cross-cutting security hardening — attack simulation tests.

Validates 22 fixes from the cross-cutting security audit across
the middleware pipeline, proxy handler, API routes, store layer,
validators, config system, webhook dispatch, and audit infrastructure.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import MappingProxyType
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from proxy.middleware.pipeline import RequestContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(
    method: str = "GET",
    path: str = "/api/data",
    client_ip: str = "10.0.0.1",
    user_agent: str = "TestAgent/1.0",
    host: str = "app.example.com",
    headers: dict | None = None,
) -> MagicMock:
    """Build a mock Starlette request."""
    extra_headers = headers or {}
    req = MagicMock()
    req.method = method
    req.url = MagicMock()
    req.url.path = path
    req.client = MagicMock()
    req.client.host = client_ip

    all_headers = {"user-agent": user_agent, "host": host}
    all_headers.update(extra_headers)

    req.headers = MagicMock()
    req.headers.get = lambda key, default="": all_headers.get(key, default)
    req.headers.items = lambda: list(all_headers.items())
    return req


def _make_context(
    tenant_id: str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    audit_logging: bool = True,
    request_id: str = "req-12345",
    user_id: str = "",
    customer_config: dict | None = None,
) -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = tenant_id
    ctx.request_id = request_id
    ctx.user_id = user_id
    if customer_config is not None:
        ctx.customer_config = customer_config
    else:
        ctx.customer_config = {
            "enabled_features": {"audit_logging": audit_logging},
            "customer_id": "cust-1",
        }
    return ctx


def _make_pool_mock():
    """Build a mock pool with async context managers for transactions."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetchval = AsyncMock(return_value=None)
    mock_conn.fetch = AsyncMock(return_value=[])

    mock_tx = AsyncMock()
    mock_tx.__aenter__ = AsyncMock(return_value=None)
    mock_tx.__aexit__ = AsyncMock(return_value=False)
    mock_conn.transaction = MagicMock(return_value=mock_tx)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_pool = MagicMock()
    mock_pool.acquire = MagicMock(return_value=mock_ctx)
    return mock_pool, mock_conn


# =========================================================================
# A. Error Response Pipeline
# =========================================================================


class TestErrorResponsePipeline:
    """All error paths in proxy_request must go through process_response."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        import proxy.main as main_module
        self._main = main_module

    @pytest.mark.asyncio
    async def test_error_response_helper_calls_pipeline(self):
        """_error_response runs the response through the pipeline."""
        from proxy.main import _error_response

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(
            side_effect=lambda resp, ctx: resp
        )
        ctx = _make_context()

        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response("test error", 500, ctx)

        assert resp.status_code == 500
        mock_pipeline.process_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_error_response_without_pipeline(self):
        """_error_response works when pipeline is None (fallback)."""
        from proxy.main import _error_response

        ctx = _make_context()
        with patch.object(self._main, "_pipeline", None):
            resp = await _error_response("test", 500, ctx)
        assert resp.status_code == 500

    @pytest.mark.asyncio
    async def test_content_length_error_gets_pipeline(self):
        """413 from content-length check goes through pipeline."""
        from proxy.main import _error_response

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(
            side_effect=lambda resp, ctx: resp
        )
        ctx = _make_context()
        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response("Request body too large", 413, ctx)
        assert resp.status_code == 413
        mock_pipeline.process_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_invalid_content_length_gets_pipeline(self):
        """400 from invalid content-length goes through pipeline."""
        from proxy.main import _error_response

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(
            side_effect=lambda resp, ctx: resp
        )
        ctx = _make_context()
        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response("Invalid Content-Length", 400, ctx)
        assert resp.status_code == 400
        mock_pipeline.process_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_upstream_timeout_gets_pipeline(self):
        """504 from upstream timeout goes through pipeline."""
        from proxy.main import _error_response

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(
            side_effect=lambda resp, ctx: resp
        )
        ctx = _make_context()
        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response("Upstream timeout", 504, ctx)
        assert resp.status_code == 504
        mock_pipeline.process_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_upstream_unreachable_gets_pipeline(self):
        """502 from upstream connect error goes through pipeline."""
        from proxy.main import _error_response

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(
            side_effect=lambda resp, ctx: resp
        )
        ctx = _make_context()
        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response("Upstream unreachable", 502, ctx)
        assert resp.status_code == 502
        mock_pipeline.process_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_upstream_error_gets_pipeline(self):
        """502 from upstream HTTP error goes through pipeline."""
        from proxy.main import _error_response

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(
            side_effect=lambda resp, ctx: resp
        )
        ctx = _make_context()
        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response("Upstream error", 502, ctx)
        assert resp.status_code == 502
        mock_pipeline.process_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_upstream_response_too_large_gets_pipeline(self):
        """502 from oversized upstream response goes through pipeline."""
        from proxy.main import _error_response

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(
            side_effect=lambda resp, ctx: resp
        )
        ctx = _make_context()
        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response(
                "Upstream response too large", 502, ctx
            )
        assert resp.status_code == 502
        mock_pipeline.process_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_body_too_large_gets_pipeline(self):
        """413 from actual body size check goes through pipeline."""
        from proxy.main import _error_response

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(
            side_effect=lambda resp, ctx: resp
        )
        ctx = _make_context()
        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response("Request body too large", 413, ctx)
        assert resp.status_code == 413
        mock_pipeline.process_response.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_pipeline_can_add_headers(self):
        """Pipeline can inject security headers into error responses."""
        from proxy.main import _error_response

        async def _add_header(resp, ctx):
            resp.headers["x-security-test"] = "applied"
            return resp

        mock_pipeline = MagicMock()
        mock_pipeline.process_response = AsyncMock(side_effect=_add_header)
        ctx = _make_context()
        with patch.object(self._main, "_pipeline", mock_pipeline):
            resp = await _error_response("test", 500, ctx)
        assert resp.headers.get("x-security-test") == "applied"

    def test_error_response_function_exists(self):
        """_error_response is importable from proxy.main."""
        from proxy.main import _error_response
        assert callable(_error_response)

    def test_error_response_is_async(self):
        """_error_response is a coroutine function."""
        from proxy.main import _error_response
        assert asyncio.iscoroutinefunction(_error_response)


# =========================================================================
# A. Pipeline Null Guard
# =========================================================================


class TestPipelineNullGuard:
    """_pipeline=None must return 503, never pass unprotected."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        import proxy.main as main_module
        self._main = main_module

    def test_null_pipeline_returns_503(self):
        """Proxy returns 503 when pipeline is None."""
        import httpx
        from fastapi.testclient import TestClient
        from proxy.main import app

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(
            return_value=httpx.Response(200, content=b"ok")
        )

        with TestClient(app, raise_server_exceptions=False) as c:
            self._main._http_client = mock_http
            self._main._pipeline = None
            resp = c.get("/test-path")
        assert resp.status_code == 503
        assert "pipeline" in resp.text.lower() or "Security" in resp.text

    def test_null_pipeline_no_upstream_call(self):
        """When pipeline is None, upstream is never called."""
        import httpx
        from fastapi.testclient import TestClient
        from proxy.main import app

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(
            return_value=httpx.Response(200, content=b"ok")
        )

        with TestClient(app, raise_server_exceptions=False) as c:
            self._main._http_client = mock_http
            self._main._pipeline = None
            c.get("/test")
        mock_http.request.assert_not_awaited()

    def test_null_pipeline_message_content(self):
        """503 body mentions security pipeline."""
        import httpx
        from fastapi.testclient import TestClient
        from proxy.main import app

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(
            return_value=httpx.Response(200, content=b"ok")
        )

        with TestClient(app, raise_server_exceptions=False) as c:
            self._main._http_client = mock_http
            self._main._pipeline = None
            resp = c.get("/foo")
        assert "Security pipeline not initialized" in resp.text

    def test_http_client_none_still_503(self):
        """Even if HTTP client is None, we get 503."""
        from fastapi.testclient import TestClient
        from proxy.main import app

        with TestClient(app, raise_server_exceptions=False) as c:
            self._main._http_client = None
            self._main._pipeline = None
            resp = c.get("/bar")
        assert resp.status_code == 503

    def test_pipeline_set_works_normally(self):
        """When pipeline is set, proxy functions normally."""
        import httpx
        from fastapi.testclient import TestClient
        from proxy.main import _build_pipeline, app

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(
            return_value=httpx.Response(200, content=b"ok")
        )

        with TestClient(app, raise_server_exceptions=False) as c:
            self._main._http_client = mock_http
            self._main._pipeline = _build_pipeline()
            resp = c.get("/health-check-path")
        # Should not be 503 (pipeline is set)
        assert resp.status_code != 503 or "pipeline" not in resp.text.lower()


# =========================================================================
# B. PostgreSQL Timeout
# =========================================================================


class TestPostgresTimeout:
    """Pool must be created with command_timeout."""

    @pytest.mark.asyncio
    async def test_command_timeout_passed(self):
        """asyncpg.create_pool is called with command_timeout=30."""
        from proxy.store import postgres as pg

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(side_effect=Exception("stop"))

        with patch.object(pg, "asyncpg") as mock_asyncpg:
            mock_asyncpg.create_pool = AsyncMock(return_value=mock_pool)
            await pg.init_postgres("postgresql://test@localhost/test")
            call_kwargs = mock_asyncpg.create_pool.call_args
            assert call_kwargs.kwargs.get("command_timeout") == 30 or \
                (len(call_kwargs.args) > 0 and "command_timeout" in str(call_kwargs))

    @pytest.mark.asyncio
    async def test_command_timeout_is_30(self):
        """command_timeout is exactly 30 seconds."""
        from proxy.store import postgres as pg

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(side_effect=Exception("stop"))

        with patch.object(pg, "asyncpg") as mock_asyncpg:
            mock_asyncpg.create_pool = AsyncMock(return_value=mock_pool)
            await pg.init_postgres("postgresql://test@localhost/test")
            _, kwargs = mock_asyncpg.create_pool.call_args
            assert kwargs.get("command_timeout") == 30

    @pytest.mark.asyncio
    async def test_timeout_with_custom_pool_size(self):
        """command_timeout is set regardless of pool size params."""
        from proxy.store import postgres as pg

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(side_effect=Exception("stop"))

        with patch.object(pg, "asyncpg") as mock_asyncpg:
            mock_asyncpg.create_pool = AsyncMock(return_value=mock_pool)
            await pg.init_postgres("postgresql://x@localhost/x", min_size=5, max_size=20)
            _, kwargs = mock_asyncpg.create_pool.call_args
            assert kwargs["command_timeout"] == 30
            assert kwargs["min_size"] == 5
            assert kwargs["max_size"] == 20

    @pytest.mark.asyncio
    async def test_pool_min_max_preserved(self):
        """min_size and max_size are preserved alongside command_timeout."""
        from proxy.store import postgres as pg

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(side_effect=Exception("stop"))

        with patch.object(pg, "asyncpg") as mock_asyncpg:
            mock_asyncpg.create_pool = AsyncMock(return_value=mock_pool)
            await pg.init_postgres("postgresql://x@localhost/x", min_size=1, max_size=5)
            _, kwargs = mock_asyncpg.create_pool.call_args
            assert kwargs["min_size"] == 1
            assert kwargs["max_size"] == 5

    def test_init_postgres_is_async(self):
        """init_postgres is a coroutine function."""
        from proxy.store.postgres import init_postgres
        assert asyncio.iscoroutinefunction(init_postgres)

    @pytest.mark.asyncio
    async def test_pool_creation_includes_all_required_params(self):
        """Pool creation call includes url, min_size, max_size, command_timeout."""
        from proxy.store import postgres as pg

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(side_effect=Exception("stop"))

        with patch.object(pg, "asyncpg") as mock_asyncpg:
            mock_asyncpg.create_pool = AsyncMock(return_value=mock_pool)
            await pg.init_postgres("postgresql://x@localhost/x")
            args, kwargs = mock_asyncpg.create_pool.call_args
            assert "command_timeout" in kwargs
            assert "min_size" in kwargs
            assert "max_size" in kwargs


# =========================================================================
# B. Redis Timeout
# =========================================================================


class TestRedisTimeout:
    """Redis pool must have socket_timeout."""

    @pytest.mark.asyncio
    async def test_socket_timeout_passed(self):
        """aioredis.from_url is called with socket_timeout."""
        import redis.asyncio as aioredis
        from proxy.store import redis as redis_mod

        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(return_value=True)

        with patch.object(aioredis, "from_url", return_value=mock_pool) as mock_from_url:
            original = redis_mod._pool
            await redis_mod.init_redis("redis://localhost:6379")
            _, kwargs = mock_from_url.call_args
            assert "socket_timeout" in kwargs
            redis_mod._pool = original

    @pytest.mark.asyncio
    async def test_socket_timeout_is_5(self):
        """socket_timeout is exactly 5 seconds."""
        import redis.asyncio as aioredis
        from proxy.store import redis as redis_mod

        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(return_value=True)

        with patch.object(aioredis, "from_url", return_value=mock_pool) as mock_from_url:
            original = redis_mod._pool
            await redis_mod.init_redis("redis://localhost:6379")
            _, kwargs = mock_from_url.call_args
            assert kwargs["socket_timeout"] == 5
            redis_mod._pool = original

    @pytest.mark.asyncio
    async def test_socket_connect_timeout_preserved(self):
        """socket_connect_timeout is still 5 alongside socket_timeout."""
        import redis.asyncio as aioredis
        from proxy.store import redis as redis_mod

        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(return_value=True)

        with patch.object(aioredis, "from_url", return_value=mock_pool) as mock_from_url:
            original = redis_mod._pool
            await redis_mod.init_redis("redis://localhost:6379")
            _, kwargs = mock_from_url.call_args
            assert kwargs["socket_connect_timeout"] == 5
            assert kwargs["socket_timeout"] == 5
            redis_mod._pool = original

    @pytest.mark.asyncio
    async def test_decode_responses_preserved(self):
        """decode_responses=True preserved with socket_timeout."""
        import redis.asyncio as aioredis
        from proxy.store import redis as redis_mod

        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(return_value=True)

        with patch.object(aioredis, "from_url", return_value=mock_pool) as mock_from_url:
            original = redis_mod._pool
            await redis_mod.init_redis("redis://localhost:6379")
            _, kwargs = mock_from_url.call_args
            assert kwargs["decode_responses"] is True
            redis_mod._pool = original

    @pytest.mark.asyncio
    async def test_pool_size_preserved(self):
        """max_connections preserved with socket_timeout."""
        import redis.asyncio as aioredis
        from proxy.store import redis as redis_mod

        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(return_value=True)

        with patch.object(aioredis, "from_url", return_value=mock_pool) as mock_from_url:
            original = redis_mod._pool
            await redis_mod.init_redis("redis://localhost:6379", pool_size=20)
            _, kwargs = mock_from_url.call_args
            assert kwargs["max_connections"] == 20
            redis_mod._pool = original

    @pytest.mark.asyncio
    async def test_all_params_present(self):
        """All required params present in from_url call."""
        import redis.asyncio as aioredis
        from proxy.store import redis as redis_mod

        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(return_value=True)

        with patch.object(aioredis, "from_url", return_value=mock_pool) as mock_from_url:
            original = redis_mod._pool
            await redis_mod.init_redis("redis://localhost:6379")
            _, kwargs = mock_from_url.call_args
            for key in ("max_connections", "decode_responses", "socket_connect_timeout", "socket_timeout"):
                assert key in kwargs, f"Missing {key}"
            redis_mod._pool = original


# =========================================================================
# C. Webhook Async DNS
# =========================================================================


class TestWebhookAsyncDNS:
    """_validate_webhook_url must be async and run DNS in thread pool."""

    def test_validate_webhook_url_is_async(self):
        """_validate_webhook_url is a coroutine function."""
        from proxy.config.webhook import _validate_webhook_url
        assert asyncio.iscoroutinefunction(_validate_webhook_url)

    @pytest.mark.asyncio
    async def test_validate_calls_to_thread(self):
        """_validate_webhook_url uses asyncio.to_thread."""
        with patch("proxy.config.webhook.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = None
            from proxy.config.webhook import _validate_webhook_url
            await _validate_webhook_url("https://example.com/webhook")
            mock_thread.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_validate_passes_strict_dns(self):
        """strict_dns=True passed to validate_origin_url."""
        with patch("proxy.config.webhook.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = None
            from proxy.config.webhook import _validate_webhook_url
            await _validate_webhook_url("https://example.com/hook")
            args, kwargs = mock_thread.call_args
            # asyncio.to_thread(validate_origin_url, url, strict_dns=True)
            # strict_dns may be positional or keyword
            assert kwargs.get("strict_dns") is True or (len(args) >= 3 and args[2] is True)

    @pytest.mark.asyncio
    async def test_validate_returns_error(self):
        """Error message from validate_origin_url is returned."""
        with patch("proxy.config.webhook.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = "blocked: private IP"
            from proxy.config.webhook import _validate_webhook_url
            result = await _validate_webhook_url("http://169.254.169.254/")
            assert result == "blocked: private IP"

    @pytest.mark.asyncio
    async def test_validate_returns_none_for_valid(self):
        """None returned for valid URLs."""
        with patch("proxy.config.webhook.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = None
            from proxy.config.webhook import _validate_webhook_url
            result = await _validate_webhook_url("https://example.com")
            assert result is None


# =========================================================================
# C. Logger Exception Leaks
# =========================================================================


class TestLoggerExceptionLeaks:
    """audit_routes and webhook use logger.error, not .exception."""

    def test_audit_routes_uses_logger_error(self):
        """audit_routes.py does not use logger.exception for query errors."""
        import inspect
        from proxy.api import audit_routes

        source = inspect.getsource(audit_routes.get_audit_logs)
        assert "logger.exception" not in source
        assert "logger.error" in source

    def test_webhook_dispatch_uses_logger_error(self):
        """webhook.py dispatch loop uses logger.error, not .exception."""
        import inspect
        from proxy.config import webhook

        source = inspect.getsource(webhook.dispatch_webhook_event)
        # The inner except should use .error not .exception
        # (the outer webhook_fetch_failed is still .exception since it has no secret)
        lines = source.split("\n")
        dispatch_section = False
        for line in lines:
            if "webhook_dispatch_failed" in line:
                dispatch_section = True
            if dispatch_section and "logger." in line:
                assert "logger.error" in line or "logger.exception" not in line
                break

    def test_audit_routes_no_traceback_leak(self):
        """DB query errors don't leak connection strings via traceback."""
        import inspect
        from proxy.api import audit_routes

        source = inspect.getsource(audit_routes)
        # Count occurrences — should have exactly 0 logger.exception
        assert source.count("logger.exception") == 0

    def test_webhook_dispatch_failed_no_exception(self):
        """webhook_dispatch_failed uses logger.error."""
        import inspect
        from proxy.config import webhook

        source = inspect.getsource(webhook.dispatch_webhook_event)
        # Find the line with webhook_dispatch_failed
        for i, line in enumerate(source.split("\n")):
            if "webhook_dispatch_failed" in line:
                # Previous line should have logger.error
                prev_line = source.split("\n")[i - 1] if i > 0 else line
                assert "logger.error" in prev_line or "logger.error" in line
                break

    def test_webhook_fetch_still_logs(self):
        """webhook_fetch_failed still uses logger.exception (no secret in that path)."""
        import inspect
        from proxy.config import webhook

        source = inspect.getsource(webhook.dispatch_webhook_event)
        assert "webhook_fetch_failed" in source

    def test_code_validation_uses_logger_error(self):
        """code_validation_routes error handler uses logger.error (not .exception)."""
        import inspect
        from proxy.api import code_validation_routes

        source = inspect.getsource(code_validation_routes.validate_code)
        # Count actual calls (not comments mentioning logger.exception)
        import re
        actual_calls = re.findall(r"^\s+logger\.exception\(", source, re.MULTILINE)
        assert len(actual_calls) == 0, f"Found logger.exception calls: {actual_calls}"


# =========================================================================
# D. getattr Dynamic Attribute Bypass
# =========================================================================


class TestGetAttrDynamicBypass:
    """getattr with non-constant second arg must be flagged."""

    @pytest.fixture
    def validator(self):
        from proxy.validation.python_validator import PythonValidator
        return PythonValidator()

    def test_string_concat_bypass(self, validator):
        """getattr(obj, '__' + 'import' + '__') flagged."""
        code = 'getattr(builtins, "__" + "import" + "__")'
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" in rule_ids

    def test_chr_concat_bypass(self, validator):
        """getattr(obj, chr(95)*2 + 'import' + chr(95)*2) flagged."""
        code = 'getattr(builtins, chr(95)*2 + "import" + chr(95)*2)'
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" in rule_ids

    def test_variable_attr_bypass(self, validator):
        """getattr(obj, attr_name) with variable flagged."""
        code = 'attr = "__import__"\ngetattr(builtins, attr)'
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" in rule_ids

    def test_fstring_bypass(self, validator):
        """getattr(obj, f'__import__') flagged (JoinedStr is not Constant)."""
        code = 'getattr(builtins, f"__import__")'
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" in rule_ids

    def test_constant_string_still_works(self, validator):
        """getattr(obj, '__import__') still caught as py-getattr-bypass."""
        code = 'getattr(builtins, "__import__")'
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-bypass" in rule_ids

    def test_safe_constant_not_flagged(self, validator):
        """getattr(obj, 'name') not flagged (safe constant string)."""
        code = 'getattr(obj, "name")'
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" not in rule_ids
        assert "py-getattr-bypass" not in rule_ids

    def test_integer_constant_not_flagged(self, validator):
        """getattr(obj, 42) — integer constant, not dynamic string."""
        code = "getattr(obj, 42)"
        findings = validator.validate(code)
        # Integer constant is a Constant but not a string — should not trigger
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" not in rule_ids

    def test_dynamic_attr_severity_is_high(self, validator):
        """Dynamic attr finding has severity HIGH."""
        code = 'getattr(builtins, "__" + "import" + "__")'
        findings = validator.validate(code)
        dynamic = [f for f in findings if f.rule_id == "py-getattr-dynamic-attr"]
        assert len(dynamic) >= 1
        assert dynamic[0].severity.value == "high"

    def test_bytes_decode_bypass(self, validator):
        """getattr(obj, b'__import__'.decode()) flagged."""
        code = "getattr(builtins, b'__import__'.decode())"
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" in rule_ids

    def test_list_index_bypass(self, validator):
        """getattr(obj, ['__import__'][0]) flagged."""
        code = "getattr(builtins, ['__import__'][0])"
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" in rule_ids

    def test_single_arg_getattr_ignored(self, validator):
        """getattr(obj) with one arg — no crash, no flag."""
        code = "getattr(builtins)"
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" not in rule_ids

    def test_format_string_bypass(self, validator):
        """getattr(obj, '{}'.format('__import__')) flagged."""
        code = "getattr(builtins, '{}'.format('__import__'))"
        findings = validator.validate(code)
        rule_ids = [f.rule_id for f in findings]
        assert "py-getattr-dynamic-attr" in rule_ids


# =========================================================================
# D. Never-Allowed Imports
# =========================================================================


class TestNeverAllowedImports:
    """os/subprocess/ctypes cannot be whitelisted via API."""

    def test_never_allowed_list_exists(self):
        """_NEVER_ALLOWED_IMPORTS is defined."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert isinstance(_NEVER_ALLOWED_IMPORTS, frozenset)
        assert len(_NEVER_ALLOWED_IMPORTS) >= 10

    def test_os_in_never_allowed(self):
        """'os' is in the never-allowed set."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert "os" in _NEVER_ALLOWED_IMPORTS

    def test_subprocess_in_never_allowed(self):
        """'subprocess' is in the never-allowed set."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert "subprocess" in _NEVER_ALLOWED_IMPORTS

    def test_ctypes_in_never_allowed(self):
        """'ctypes' is in the never-allowed set."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert "ctypes" in _NEVER_ALLOWED_IMPORTS

    def test_pickle_in_never_allowed(self):
        """'pickle' is in the never-allowed set."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert "pickle" in _NEVER_ALLOWED_IMPORTS

    def test_pty_in_never_allowed(self):
        """'pty' is in the never-allowed set."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert "pty" in _NEVER_ALLOWED_IMPORTS

    def test_marshal_in_never_allowed(self):
        """'marshal' is in the never-allowed set."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert "marshal" in _NEVER_ALLOWED_IMPORTS

    def test_json_not_in_never_allowed(self):
        """'json' is NOT in never-allowed (safe module)."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert "json" not in _NEVER_ALLOWED_IMPORTS

    def test_math_not_in_never_allowed(self):
        """'math' is NOT in never-allowed (safe module)."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        assert "math" not in _NEVER_ALLOWED_IMPORTS

    def test_stripping_works(self):
        """Stripping never-allowed from allowed_imports works correctly."""
        from proxy.api.code_validation_routes import _NEVER_ALLOWED_IMPORTS
        allowed = {"os", "json", "subprocess", "math"}
        safe = allowed - _NEVER_ALLOWED_IMPORTS
        assert "os" not in safe
        assert "subprocess" not in safe
        assert "json" in safe
        assert "math" in safe


# =========================================================================
# E. App CRUD IDOR
# =========================================================================


class TestAppCRUDIDOR:
    """App GET/PUT/DELETE must be customer-scoped."""

    @pytest.mark.asyncio
    async def test_get_app_accepts_customer_id(self):
        """get_app store function accepts customer_id kwarg."""
        from proxy.store import postgres as pg

        mock_pool, mock_conn = _make_pool_mock()
        app_id = uuid4()
        customer_id = uuid4()
        original = pg._pool
        pg._pool = mock_pool
        try:
            await pg.get_app(app_id, customer_id=customer_id)
        finally:
            pg._pool = original
        # Verify the query includes customer_id
        query = mock_conn.fetchrow.call_args[0][0]
        assert "customer_id" in query

    @pytest.mark.asyncio
    async def test_get_app_without_customer_id_no_filter(self):
        """get_app without customer_id has no customer_id in WHERE clause."""
        from proxy.store import postgres as pg

        mock_pool, mock_conn = _make_pool_mock()
        app_id = uuid4()
        original = pg._pool
        pg._pool = mock_pool
        try:
            await pg.get_app(app_id)
        finally:
            pg._pool = original
        query = mock_conn.fetchrow.call_args[0][0]
        # customer_id appears in SELECT columns but NOT in WHERE clause
        where_part = query.split("WHERE")[1] if "WHERE" in query else ""
        assert "customer_id" not in where_part

    @pytest.mark.asyncio
    async def test_delete_app_accepts_customer_id(self):
        """delete_app store function accepts customer_id kwarg."""
        from proxy.store import postgres as pg

        mock_pool, mock_conn = _make_pool_mock()
        mock_conn.execute = AsyncMock(return_value="DELETE 1")
        app_id = uuid4()
        customer_id = uuid4()
        original = pg._pool
        pg._pool = mock_pool
        try:
            await pg.delete_app(app_id, customer_id=customer_id)
        finally:
            pg._pool = original
        query = mock_conn.execute.call_args[0][0]
        assert "customer_id" in query

    @pytest.mark.asyncio
    async def test_update_app_accepts_customer_id(self):
        """update_app store function accepts customer_id kwarg."""
        from proxy.store import postgres as pg

        mock_pool, mock_conn = _make_pool_mock()
        app_id = uuid4()
        customer_id = uuid4()
        original = pg._pool
        pg._pool = mock_pool
        try:
            await pg.update_app(app_id, customer_id=customer_id, name="new-name")
        finally:
            pg._pool = original
        query = mock_conn.fetchrow.call_args[0][0]
        assert "customer_id" in query

    @pytest.mark.asyncio
    async def test_get_app_wrong_customer_returns_none(self):
        """get_app with non-matching customer_id returns None."""
        from proxy.store import postgres as pg

        mock_pool, mock_conn = _make_pool_mock()
        mock_conn.fetchrow = AsyncMock(return_value=None)
        app_id = uuid4()
        customer_id = uuid4()
        original = pg._pool
        pg._pool = mock_pool
        try:
            result = await pg.get_app(app_id, customer_id=customer_id)
        finally:
            pg._pool = original
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_app_wrong_customer_returns_false(self):
        """delete_app with non-matching customer_id returns False."""
        from proxy.store import postgres as pg

        mock_pool, mock_conn = _make_pool_mock()
        mock_conn.execute = AsyncMock(return_value="DELETE 0")
        app_id = uuid4()
        customer_id = uuid4()
        original = pg._pool
        pg._pool = mock_pool
        try:
            result = await pg.delete_app(app_id, customer_id=customer_id)
        finally:
            pg._pool = original
        assert result is False

    def test_config_route_get_app_has_customer_id(self):
        """GET app route includes customer_id in path."""
        from proxy.api.config_routes import router
        paths = [route.path for route in router.routes]
        # Should have /customers/{customer_id}/apps/{app_id} pattern
        assert any("customer_id" in p and "app_id" in p and "apps" in p
                    for p in paths)

    def test_config_route_put_app_has_customer_id(self):
        """PUT app route includes customer_id in path."""
        from proxy.api.config_routes import router
        paths = [r.path for r in router.routes]
        app_routes = [p for p in paths if "app_id" in p and "customer_id" in p]
        assert len(app_routes) >= 1

    def test_config_route_delete_app_has_customer_id(self):
        """DELETE app route includes customer_id in path."""
        from proxy.api.config_routes import router
        paths = [r.path for r in router.routes]
        app_routes = [p for p in paths if "app_id" in p and "customer_id" in p]
        assert len(app_routes) >= 1

    @pytest.mark.asyncio
    async def test_update_app_no_customer_still_works(self):
        """update_app without customer_id has no customer_id in WHERE."""
        from proxy.store import postgres as pg

        mock_pool, mock_conn = _make_pool_mock()
        app_id = uuid4()
        original = pg._pool
        pg._pool = mock_pool
        try:
            await pg.update_app(app_id, name="test")
        finally:
            pg._pool = original
        query = mock_conn.fetchrow.call_args[0][0]
        # customer_id appears in RETURNING columns but NOT in WHERE
        where_part = query.split("WHERE")[1] if "WHERE" in query else ""
        assert "customer_id" not in where_part.split("RETURNING")[0]


# =========================================================================
# E. ValueError Info Leak
# =========================================================================


class TestValueErrorInfoLeak:
    """ValueError messages must be generic, not reflecting column names."""

    def test_config_routes_customer_update_generic(self):
        """Customer update ValueError uses generic message."""
        import inspect
        from proxy.api import config_routes

        source = inspect.getsource(config_routes.update_customer)
        # Should NOT have detail=str(exc) for ValueError
        assert 'detail=str(exc)' not in source

    def test_config_routes_app_update_generic(self):
        """App update ValueError uses generic message."""
        import inspect
        from proxy.api import config_routes

        source = inspect.getsource(config_routes.update_app)
        assert 'detail=str(exc)' not in source

    def test_webhook_routes_update_generic(self):
        """Webhook update ValueError uses generic message."""
        import inspect
        from proxy.api import webhook_routes

        source = inspect.getsource(webhook_routes.update_webhook)
        assert 'detail=str(exc)' not in source

    def test_generic_message_text(self):
        """Generic error message is 'Invalid field in request body'."""
        import inspect
        from proxy.api import config_routes

        source = inspect.getsource(config_routes.update_app)
        assert "Invalid field in request body" in source


# =========================================================================
# E. Onboarding Enumeration
# =========================================================================


class TestOnboardingEnumeration:
    """409 responses must not contain the domain."""

    def test_409_no_domain_in_existing_check(self):
        """First 409 path (existing check) has no domain."""
        import inspect
        from proxy.api import onboarding_routes

        source = inspect.getsource(onboarding_routes.create_onboarding)
        lines = source.split("\n")
        for line in lines:
            if "409" in line and "detail" in line:
                # The domain variable should not appear in the detail
                assert "body.customer_domain" not in line or "Domain already has" in source

    def test_409_no_domain_in_duplicate(self):
        """TOCTOU 409 path has no domain."""
        import inspect
        from proxy.api import onboarding_routes

        source = inspect.getsource(onboarding_routes.create_onboarding)
        # No f-string with body.customer_domain in 409 detail
        assert 'f"Domain {body.customer_domain}' not in source

    def test_409_message_is_generic(self):
        """409 detail is generic 'Domain already has an active onboarding'."""
        import inspect
        from proxy.api import onboarding_routes

        source = inspect.getsource(onboarding_routes.create_onboarding)
        assert '"Domain already has an active onboarding"' in source

    def test_cert_arn_redacted_in_logs(self):
        """_safe_cert_id extracts only UUID from ARN."""
        from proxy.api.onboarding_routes import _safe_cert_id
        arn = "arn:aws:acm:us-east-1:123456789012:certificate/abc-def-123"
        assert _safe_cert_id(arn) == "abc-def-123"
        assert "123456789012" not in _safe_cert_id(arn)


# =========================================================================
# F. Callback Timing Channel
# =========================================================================


class TestCallbackTimingChannel:
    """All secrets must be iterated (no early return) for constant-time."""

    @pytest.mark.asyncio
    async def test_all_secrets_checked_on_match(self):
        """Even when first secret matches, all secrets are hashed."""
        from proxy.middleware.callback_verifier import CallbackVerifier

        verifier = CallbackVerifier()
        ts = str(int(time.time()))
        body = b"test body"
        signing_input = f"{ts}.".encode() + body

        secrets = ["secret-1", "secret-2", "secret-3"]
        sig = "sha256=" + hmac.new(
            secrets[0].encode("utf-8"), signing_input, hashlib.sha256
        ).hexdigest()

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/webhooks/stripe"
        request.method = "POST"
        request.headers = MagicMock()
        request.headers.get = lambda k, d="": {
            "x-signature": sig, "x-timestamp": ts
        }.get(k, d)
        request.body = AsyncMock(return_value=body)

        ctx = _make_context(customer_config={
            "enabled_features": {"callback_verifier": True},
            "settings": {
                "callback_verifier": {
                    "endpoints": [
                        {"pattern": "/webhooks/*", "secrets": secrets}
                    ],
                    "mode": "block",
                },
            },
        })

        with patch("proxy.middleware.callback_verifier.hmac.new", wraps=hmac.new) as mock_hmac:
            result = await verifier.process_request(request, ctx)
        # Should be valid (None = pass through)
        assert result is None
        # ALL secrets should have been hashed (constant-time iteration)
        assert mock_hmac.call_count == len(secrets)

    @pytest.mark.asyncio
    async def test_all_secrets_checked_on_invalid(self):
        """When no secret matches, all secrets are still hashed."""
        from proxy.middleware.callback_verifier import CallbackVerifier

        verifier = CallbackVerifier()
        ts = str(int(time.time()))
        body = b"test body"

        secrets = ["secret-1", "secret-2", "secret-3"]
        sig = "sha256=invalid_signature_value"

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/webhooks/stripe"
        request.method = "POST"
        request.headers = MagicMock()
        request.headers.get = lambda k, d="": {
            "x-signature": sig, "x-timestamp": ts
        }.get(k, d)
        request.body = AsyncMock(return_value=body)

        ctx = _make_context(customer_config={
            "enabled_features": {"callback_verifier": True},
            "settings": {
                "callback_verifier": {
                    "endpoints": [
                        {"pattern": "/webhooks/*", "secrets": secrets}
                    ],
                    "mode": "block",
                },
            },
        })

        with patch("proxy.middleware.callback_verifier.hmac.new", wraps=hmac.new) as mock_hmac:
            result = await verifier.process_request(request, ctx)
        # Should be rejected (401)
        assert result is not None
        assert result.status_code == 401
        assert mock_hmac.call_count == len(secrets)

    @pytest.mark.asyncio
    async def test_last_secret_matches(self):
        """When only the last secret matches, result is still valid."""
        from proxy.middleware.callback_verifier import CallbackVerifier

        verifier = CallbackVerifier()
        ts = str(int(time.time()))
        body = b"test body"
        signing_input = f"{ts}.".encode() + body

        secrets = ["wrong-1", "wrong-2", "correct-secret"]
        sig = "sha256=" + hmac.new(
            secrets[2].encode("utf-8"), signing_input, hashlib.sha256
        ).hexdigest()

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/webhooks/stripe"
        request.method = "POST"
        request.headers = MagicMock()
        request.headers.get = lambda k, d="": {
            "x-signature": sig, "x-timestamp": ts
        }.get(k, d)
        request.body = AsyncMock(return_value=body)

        ctx = _make_context(customer_config={
            "enabled_features": {"callback_verifier": True},
            "settings": {
                "callback_verifier": {
                    "endpoints": [
                        {"pattern": "/webhooks/*", "secrets": secrets}
                    ],
                    "mode": "block",
                },
            },
        })

        result = await verifier.process_request(request, ctx)
        assert result is None  # Valid

    @pytest.mark.asyncio
    async def test_middle_secret_matches(self):
        """When middle secret matches, all secrets still checked."""
        from proxy.middleware.callback_verifier import CallbackVerifier

        verifier = CallbackVerifier()
        ts = str(int(time.time()))
        body = b"test body"
        signing_input = f"{ts}.".encode() + body

        secrets = ["wrong-1", "correct-secret", "wrong-3"]
        sig = "sha256=" + hmac.new(
            secrets[1].encode("utf-8"), signing_input, hashlib.sha256
        ).hexdigest()

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/webhooks/stripe"
        request.method = "POST"
        request.headers = MagicMock()
        request.headers.get = lambda k, d="": {
            "x-signature": sig, "x-timestamp": ts
        }.get(k, d)
        request.body = AsyncMock(return_value=body)

        ctx = _make_context(customer_config={
            "enabled_features": {"callback_verifier": True},
            "settings": {
                "callback_verifier": {
                    "endpoints": [
                        {"pattern": "/webhooks/*", "secrets": secrets}
                    ],
                    "mode": "block",
                },
            },
        })

        with patch("proxy.middleware.callback_verifier.hmac.new", wraps=hmac.new) as mock_hmac:
            result = await verifier.process_request(request, ctx)
        assert result is None  # Valid
        assert mock_hmac.call_count == len(secrets)  # All checked

    def test_no_early_return_in_source(self):
        """Source code does not break/return inside the secret loop."""
        import inspect
        from proxy.middleware import callback_verifier

        source = inspect.getsource(callback_verifier.CallbackVerifier.process_request)
        # Find the secret iteration loop
        in_secret_loop = False
        for line in source.split("\n"):
            stripped = line.strip()
            if "for secret in secrets:" in stripped:
                in_secret_loop = True
                continue
            if in_secret_loop:
                if stripped.startswith("if matched"):
                    in_secret_loop = False
                    break
                # Should NOT have return or break inside the loop
                assert "return" not in stripped, f"Early return in secret loop: {stripped}"
                assert stripped != "break", f"Break in secret loop: {stripped}"

    @pytest.mark.asyncio
    async def test_single_secret_still_works(self):
        """Single-secret configuration still validates correctly."""
        from proxy.middleware.callback_verifier import CallbackVerifier

        verifier = CallbackVerifier()
        ts = str(int(time.time()))
        body = b"payload"
        signing_input = f"{ts}.".encode() + body

        secret = "only-secret"
        sig = "sha256=" + hmac.new(
            secret.encode("utf-8"), signing_input, hashlib.sha256
        ).hexdigest()

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/webhooks/test"
        request.method = "POST"
        request.headers = MagicMock()
        request.headers.get = lambda k, d="": {
            "x-signature": sig, "x-timestamp": ts
        }.get(k, d)
        request.body = AsyncMock(return_value=body)

        ctx = _make_context(customer_config={
            "enabled_features": {"callback_verifier": True},
            "settings": {
                "callback_verifier": {
                    "endpoints": [
                        {"pattern": "/webhooks/*", "secrets": [secret]}
                    ],
                },
            },
        })

        result = await verifier.process_request(request, ctx)
        assert result is None


# =========================================================================
# F. Audit Drop Counter
# =========================================================================


class TestAuditDropCounter:
    """Audit logger tracks dropped entries and logs periodically."""

    def test_drop_counter_initialized(self):
        """_entries_dropped starts at 0."""
        from proxy.middleware.audit_logger import AuditLogger
        al = AuditLogger()
        assert al._entries_dropped == 0

    @pytest.mark.asyncio
    async def test_drop_counter_increments_on_full_queue(self):
        """Counter increments when queue is full."""
        from proxy.middleware.audit_logger import AuditLogger, _MAX_AUDIT_QUEUE_SIZE

        al = AuditLogger()
        # Fill the queue
        for _ in range(_MAX_AUDIT_QUEUE_SIZE):
            al._queue.put_nowait(("dummy",))

        ctx = _make_context()
        req = _make_request()

        # Process request to set up metadata
        await al.process_request(req, ctx)

        # Process response — should trigger QueueFull
        from starlette.responses import Response
        resp = Response(content="ok", status_code=200)
        with patch("proxy.middleware.audit_logger.logger") as mock_logger:
            await al.process_response(resp, ctx)
        assert al._entries_dropped >= 1

    @pytest.mark.asyncio
    async def test_drop_counter_logs_on_first_drop(self):
        """First drop triggers an error log."""
        from proxy.middleware.audit_logger import AuditLogger, _MAX_AUDIT_QUEUE_SIZE

        al = AuditLogger()
        for _ in range(_MAX_AUDIT_QUEUE_SIZE):
            al._queue.put_nowait(("dummy",))

        ctx = _make_context()
        req = _make_request()
        await al.process_request(req, ctx)

        from starlette.responses import Response
        resp = Response(content="ok", status_code=200)
        with patch("proxy.middleware.audit_logger.logger") as mock_logger:
            await al.process_response(resp, ctx)
        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_drop_counter_resets_after_flush(self):
        """Counter resets to 0 after successful flush."""
        from proxy.middleware.audit_logger import AuditLogger

        al = AuditLogger()
        al._entries_dropped = 50

        # Put one real row in the queue
        al._queue.put_nowait(("row",))

        with patch("proxy.middleware.audit_logger.batch_insert_audit_logs", new_callable=AsyncMock):
            await al._flush_batch()

        assert al._entries_dropped == 0

    @pytest.mark.asyncio
    async def test_drop_counter_stays_on_failed_flush(self):
        """Counter stays non-zero if flush fails."""
        from proxy.middleware.audit_logger import AuditLogger

        al = AuditLogger()
        al._entries_dropped = 50

        al._queue.put_nowait(("row",))
        with patch("proxy.middleware.audit_logger.batch_insert_audit_logs",
                    new_callable=AsyncMock, side_effect=Exception("db down")):
            await al._flush_batch()

        # Counter should stay at 50 (not reset)
        assert al._entries_dropped == 50

    @pytest.mark.asyncio
    async def test_multiple_drops_increment(self):
        """Multiple drops increment the counter each time."""
        from proxy.middleware.audit_logger import AuditLogger, _MAX_AUDIT_QUEUE_SIZE

        al = AuditLogger()
        for _ in range(_MAX_AUDIT_QUEUE_SIZE):
            al._queue.put_nowait(("dummy",))

        for i in range(5):
            ctx = _make_context()
            req = _make_request()
            await al.process_request(req, ctx)
            from starlette.responses import Response
            resp = Response(content="ok", status_code=200)
            with patch("proxy.middleware.audit_logger.logger"):
                await al.process_response(resp, ctx)

        assert al._entries_dropped >= 5

    def test_drop_counter_attribute_exists(self):
        """AuditLogger has _entries_dropped attribute."""
        from proxy.middleware.audit_logger import AuditLogger
        al = AuditLogger()
        assert hasattr(al, "_entries_dropped")

    @pytest.mark.asyncio
    async def test_periodic_logging_at_100(self):
        """Error logged every 100 drops."""
        from proxy.middleware.audit_logger import AuditLogger

        al = AuditLogger()
        # Simulate 100 drops
        al._entries_dropped = 99

        # Fill queue
        while not al._queue.full():
            al._queue.put_nowait(("dummy",))

        ctx = _make_context()
        req = _make_request()
        await al.process_request(req, ctx)
        from starlette.responses import Response
        resp = Response(content="ok", status_code=200)
        with patch("proxy.middleware.audit_logger.logger") as mock_logger:
            await al.process_response(resp, ctx)
        # Should log at drop 100 (100 % 100 == 0)
        mock_logger.error.assert_called()


# =========================================================================
# F. Audit Timestamp
# =========================================================================


class TestAuditTimestamp:
    """Timestamp reflects request arrival, not response time."""

    @pytest.mark.asyncio
    async def test_timestamp_set_in_process_request(self):
        """process_request stores _audit_timestamp in context."""
        from proxy.middleware.audit_logger import AuditLogger

        al = AuditLogger()
        ctx = _make_context()
        req = _make_request()

        before = datetime.now(timezone.utc)
        await al.process_request(req, ctx)
        after = datetime.now(timezone.utc)

        ts = ctx.extra.get("_audit_timestamp")
        assert ts is not None
        assert isinstance(ts, datetime)
        assert before <= ts <= after

    @pytest.mark.asyncio
    async def test_timestamp_used_in_row(self):
        """process_response uses _audit_timestamp from context, not now()."""
        from proxy.middleware.audit_logger import AuditLogger
        from starlette.responses import Response

        al = AuditLogger()
        ctx = _make_context()
        req = _make_request()

        await al.process_request(req, ctx)
        ts_before = ctx.extra["_audit_timestamp"]

        # Simulate delay
        import time
        time.sleep(0.01)

        resp = Response(content="ok", status_code=200)
        with patch("proxy.middleware.audit_logger.batch_insert_audit_logs", new_callable=AsyncMock):
            await al.process_response(resp, ctx)

        # The queued row's timestamp should match the request arrival
        if not al._queue.empty():
            row = al._queue.get_nowait()
            # Timestamp is at index 3 in the row tuple
            assert row[3] == ts_before

    @pytest.mark.asyncio
    async def test_timestamp_is_utc(self):
        """Stored timestamp is UTC."""
        from proxy.middleware.audit_logger import AuditLogger

        al = AuditLogger()
        ctx = _make_context()
        req = _make_request()
        await al.process_request(req, ctx)

        ts = ctx.extra["_audit_timestamp"]
        assert ts.tzinfo is not None
        assert ts.tzinfo == timezone.utc

    @pytest.mark.asyncio
    async def test_timestamp_fallback(self):
        """If _audit_timestamp is missing, falls back to now()."""
        from proxy.middleware.audit_logger import AuditLogger
        from starlette.responses import Response
        import time as time_mod

        al = AuditLogger()
        ctx = _make_context()

        # Manually set start time without timestamp
        ctx.extra["_audit_start"] = time_mod.monotonic()
        ctx.extra["_audit_method"] = "GET"
        ctx.extra["_audit_path"] = "/test"
        ctx.extra["_audit_direct_ip"] = "10.0.0.1"
        ctx.extra["_audit_user_agent"] = "Test"

        resp = Response(content="ok", status_code=200)
        await al.process_response(resp, ctx)

        if not al._queue.empty():
            row = al._queue.get_nowait()
            assert isinstance(row[3], datetime)

    @pytest.mark.asyncio
    async def test_audit_start_still_set(self):
        """_audit_start (monotonic) is still set for duration calculation."""
        from proxy.middleware.audit_logger import AuditLogger

        al = AuditLogger()
        ctx = _make_context()
        req = _make_request()
        await al.process_request(req, ctx)
        assert "_audit_start" in ctx.extra
        assert isinstance(ctx.extra["_audit_start"], float)

    @pytest.mark.asyncio
    async def test_both_timestamps_set(self):
        """Both _audit_start and _audit_timestamp set in process_request."""
        from proxy.middleware.audit_logger import AuditLogger

        al = AuditLogger()
        ctx = _make_context()
        req = _make_request()
        await al.process_request(req, ctx)
        assert "_audit_start" in ctx.extra
        assert "_audit_timestamp" in ctx.extra


# =========================================================================
# G. Dead Code Cleanup
# =========================================================================


class TestDeadCodeCleanup:
    """_check_duplicate_keys removed from ssrf_validator."""

    def test_function_removed(self):
        """_check_duplicate_keys is not defined in ssrf_validator."""
        from proxy.middleware import ssrf_validator
        assert not hasattr(ssrf_validator, "_check_duplicate_keys")

    def test_inline_duplicate_check_preserved(self):
        """Inline duplicate key detection via _pairs_hook is still present."""
        import inspect
        from proxy.middleware import ssrf_validator

        source = inspect.getsource(ssrf_validator.SSRFValidator)
        assert "_pairs_hook" in source
        assert "has_dupes" in source


# =========================================================================
# G. Tenant ID Sanitization
# =========================================================================


class TestTenantIdSanitization:
    """Oversized/control chars truncated in tenant_id error messages."""

    def test_oversized_tenant_id_truncated(self):
        """Very long tenant_id is truncated to 50 chars in error."""
        from proxy.store.rls import validate_tenant_id

        long_id = "x" * 200
        with pytest.raises(ValueError) as exc_info:
            validate_tenant_id(long_id)
        # Error message should not contain the full 200-char string
        assert len(str(exc_info.value)) < 200

    def test_truncated_to_50(self):
        """Truncation limit is 50 characters."""
        from proxy.store.rls import validate_tenant_id

        long_id = "a" * 100
        with pytest.raises(ValueError) as exc_info:
            validate_tenant_id(long_id)
        msg = str(exc_info.value)
        # The safe_id portion should be at most 50 chars of the input
        assert "a" * 51 not in msg

    def test_control_chars_replaced(self):
        """Control characters replaced with ? in error."""
        from proxy.store.rls import validate_tenant_id

        nasty = "bad\x00\x01\x02tenant"
        with pytest.raises(ValueError) as exc_info:
            validate_tenant_id(nasty)
        msg = str(exc_info.value)
        assert "\x00" not in msg
        assert "\x01" not in msg

    def test_unicode_replaced(self):
        """Non-ASCII characters replaced with ? in error."""
        from proxy.store.rls import validate_tenant_id

        nasty = "tenant-\u2028\u2029\ufeff-id"
        with pytest.raises(ValueError) as exc_info:
            validate_tenant_id(nasty)
        msg = str(exc_info.value)
        # Non-ASCII should be replaced
        assert "\u2028" not in msg

    def test_valid_uuid_still_passes(self):
        """Valid UUID passes validation unchanged."""
        from proxy.store.rls import validate_tenant_id

        valid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        result = validate_tenant_id(valid)
        assert result == valid

    def test_normal_invalid_uuid_error(self):
        """Normal-length invalid UUID still gets clear error."""
        from proxy.store.rls import validate_tenant_id

        with pytest.raises(ValueError, match="not a valid UUID"):
            validate_tenant_id("not-a-uuid")
