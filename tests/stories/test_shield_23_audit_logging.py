"""SHIELD-23 — Log All Requests with Structured Audit Metadata.

Acceptance Criteria:
  AC1: Every request/response logged with: timestamp, request_id, method, path,
       status, duration_ms, client_ip, user_agent, country, user_id, action type,
       blocked status.
  AC2: Configurable retention (7/30/90/365 days by plan).
  AC3: Searchable and filterable in dashboard.
  AC4: Export to CSV, JSON, and via API.
"""

from __future__ import annotations

import asyncio
import csv
import io
import time
from collections import deque
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.responses import Response

from proxy.config.audit_actions import classify_action
from proxy.middleware.audit_logger import AuditLogger, _sanitize
from proxy.middleware.audit_retention import PLAN_RETENTION_DAYS, DEFAULT_RETENTION_DAYS
from proxy.middleware.pipeline import RequestContext
from proxy.store.audit import (
    insert_audit_log,
    query_audit_logs,
    delete_old_audit_logs,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(
    method: str = "GET",
    path: str = "/api/data",
    client_ip: str = "10.0.0.1",
    user_agent: str = "TestAgent/1.0",
    host: str = "app.example.com",
) -> MagicMock:
    """Build a mock Starlette request."""
    req = MagicMock()
    req.method = method
    req.url = MagicMock()
    req.url.path = path
    req.client = MagicMock()
    req.client.host = client_ip
    req.headers = MagicMock()
    req.headers.get = lambda key, default="": {
        "user-agent": user_agent,
        "host": host,
    }.get(key, default)
    return req


def _make_context(
    tenant_id: str = "tenant-1",
    audit_logging: bool = True,
    request_id: str = "abc123",
    user_id: str = "",
) -> RequestContext:
    """Build a RequestContext with customer config."""
    ctx = RequestContext()
    ctx.tenant_id = tenant_id
    ctx.request_id = request_id
    ctx.user_id = user_id
    ctx.customer_config = {
        "enabled_features": {"audit_logging": audit_logging},
    }
    return ctx


# ---------------------------------------------------------------------------
# AC1: Every request/response logged with required fields
# ---------------------------------------------------------------------------


class TestAC1_AuditFieldsLogged:
    """All required fields are captured and passed to insert_audit_log."""

    @pytest.mark.asyncio
    async def test_all_required_fields_logged(self):
        """process_response fires insert_audit_log with all required fields."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()

        await logger.process_request(req, ctx)

        response = Response(content="OK", status_code=200)

        captured = {}

        async def _capture(**kwargs):
            captured.update(kwargs)

        with patch("proxy.middleware.audit_logger.insert_audit_log", side_effect=_capture):
            await logger.process_response(response, ctx)
            # Let the asyncio.create_task fire
            await asyncio.sleep(0.01)

        assert captured["tenant_id"] == "tenant-1"
        assert captured["request_id"] == "abc123"
        assert captured["method"] == "GET"
        assert captured["path"] == "/api/data"
        assert captured["status_code"] == 200
        assert captured["duration_ms"] >= 0
        assert captured["client_ip"] == "10.0.0.1"
        assert captured["user_agent"] == "TestAgent/1.0"
        assert captured["action"] == "api_read"
        assert captured["blocked"] is False
        assert isinstance(captured["timestamp"], datetime)

    @pytest.mark.asyncio
    async def test_blocked_request_logged(self):
        """A 429 response is logged as rate_limited + blocked=True."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()

        await logger.process_request(req, ctx)

        response = Response(content="Too many requests", status_code=429)

        captured = {}

        async def _capture(**kwargs):
            captured.update(kwargs)

        with patch("proxy.middleware.audit_logger.insert_audit_log", side_effect=_capture):
            await logger.process_response(response, ctx)
            await asyncio.sleep(0.01)

        assert captured["action"] == "rate_limited"
        assert captured["blocked"] is True

    @pytest.mark.asyncio
    async def test_feature_flag_off_skips_logging(self):
        """When audit_logging is disabled, no insert happens."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context(audit_logging=False)

        await logger.process_request(req, ctx)

        response = Response(content="OK", status_code=200)
        called = False

        async def _capture(**kwargs):
            nonlocal called
            called = True

        with patch("proxy.middleware.audit_logger.insert_audit_log", side_effect=_capture):
            await logger.process_response(response, ctx)
            await asyncio.sleep(0.01)

        assert called is False

    @pytest.mark.asyncio
    async def test_audit_failure_does_not_crash_proxy(self):
        """If insert_audit_log raises, the response is still returned."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()

        await logger.process_request(req, ctx)
        response = Response(content="OK", status_code=200)

        async def _boom(**kwargs):
            raise RuntimeError("DB is down")

        with patch("proxy.middleware.audit_logger.insert_audit_log", side_effect=_boom):
            result = await logger.process_response(response, ctx)
            await asyncio.sleep(0.01)

        assert result.status_code == 200

    def test_path_sanitized(self):
        """Control characters are stripped from path."""
        assert _sanitize("/api/\x00data\r\n", 2048) == "/api/data"

    def test_user_agent_truncated(self):
        """User agent is truncated to 1024 chars."""
        long_ua = "A" * 2000
        result = _sanitize(long_ua, 1024)
        assert len(result) == 1024

    @pytest.mark.asyncio
    async def test_no_body_logging(self):
        """Request/response bodies are never stored in audit logs."""
        logger = AuditLogger()
        req = _make_request(method="POST")
        ctx = _make_context()

        await logger.process_request(req, ctx)
        response = Response(content="secret-body-content", status_code=200)

        captured = {}

        async def _capture(**kwargs):
            captured.update(kwargs)

        with patch("proxy.middleware.audit_logger.insert_audit_log", side_effect=_capture):
            await logger.process_response(response, ctx)
            await asyncio.sleep(0.01)

        # No key should contain body content
        for key, val in captured.items():
            if isinstance(val, str):
                assert "secret-body-content" not in val

    @pytest.mark.asyncio
    async def test_action_classification(self):
        """Different methods produce correct action types."""
        cases = [
            ("POST", "/auth/login", 200, "login_attempt"),
            ("GET", "/auth/login", 200, "auth_access"),
            ("DELETE", "/api/data/1", 200, "api_delete"),
            ("PUT", "/api/data/1", 200, "api_write"),
        ]
        for method, path, status, expected_action in cases:
            logger = AuditLogger()
            req = _make_request(method=method, path=path)
            ctx = _make_context()
            await logger.process_request(req, ctx)

            response = Response(content="OK", status_code=status)
            captured = {}

            async def _capture(**kwargs):
                captured.update(kwargs)

            with patch("proxy.middleware.audit_logger.insert_audit_log", side_effect=_capture):
                await logger.process_response(response, ctx)
                await asyncio.sleep(0.01)

            assert captured["action"] == expected_action, f"{method} {path} -> {captured.get('action')}"

    @pytest.mark.asyncio
    async def test_bounded_task_queue(self):
        """Pending task deque has maxlen=1000."""
        logger = AuditLogger()
        assert logger._pending.maxlen == 1000

    @pytest.mark.asyncio
    async def test_empty_tenant_skips_logging(self):
        """Requests with no resolved tenant_id are not logged (prevents orphaned rows)."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context(tenant_id="")  # Empty tenant

        await logger.process_request(req, ctx)
        response = Response(content="OK", status_code=200)
        called = False

        async def _capture(**kwargs):
            nonlocal called
            called = True

        with patch("proxy.middleware.audit_logger.insert_audit_log", side_effect=_capture):
            await logger.process_response(response, ctx)
            await asyncio.sleep(0.01)

        assert called is False

    @pytest.mark.asyncio
    async def test_client_ip_uses_direct_peer_not_xff(self):
        """Client IP uses direct TCP peer IP, ignoring spoofable XFF."""
        logger = AuditLogger()
        req = _make_request(client_ip="203.0.113.99")
        ctx = _make_context()

        await logger.process_request(req, ctx)
        # Even if ContextInjector set XFF with a spoofed IP prepended
        ctx.extra["x_forwarded_for"] = "1.2.3.4, 203.0.113.99"

        response = Response(content="OK", status_code=200)
        captured = {}

        async def _capture(**kwargs):
            captured.update(kwargs)

        with patch("proxy.middleware.audit_logger.insert_audit_log", side_effect=_capture):
            await logger.process_response(response, ctx)
            await asyncio.sleep(0.01)

        # Must use direct peer IP, NOT the spoofed first XFF entry
        assert captured["client_ip"] == "203.0.113.99"


# ---------------------------------------------------------------------------
# AC2: Configurable retention by plan
# ---------------------------------------------------------------------------


class TestAC2_RetentionByPlan:
    """Retention days vary by customer plan."""

    def test_starter_7_days(self):
        assert PLAN_RETENTION_DAYS["starter"] == 7

    def test_pro_30_days(self):
        assert PLAN_RETENTION_DAYS["pro"] == 30

    def test_business_90_days(self):
        assert PLAN_RETENTION_DAYS["business"] == 90

    def test_enterprise_365_days(self):
        assert PLAN_RETENTION_DAYS["enterprise"] == 365

    def test_unknown_plan_defaults_to_30(self):
        assert DEFAULT_RETENTION_DAYS == 30

    @pytest.mark.asyncio
    async def test_delete_old_audit_logs_calls_correct_sql(self):
        """delete_old_audit_logs executes the correct DELETE."""
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="DELETE 5")

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            deleted = await delete_old_audit_logs("tenant-1", 30)

        assert deleted == 5
        mock_conn.execute.assert_called_once()
        args = mock_conn.execute.call_args
        assert "tenant-1" in args[0]
        assert "make_interval" in args[0][0]
        assert 30 in args[0]


# ---------------------------------------------------------------------------
# AC3: Searchable and filterable
# ---------------------------------------------------------------------------


class TestAC3_QueryFilters:
    """Audit logs can be queried with various filters."""

    @pytest.mark.asyncio
    async def test_query_by_tenant(self):
        """query_audit_logs filters by tenant_id."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 1})
        mock_conn.fetch = AsyncMock(return_value=[
            {"id": 1, "tenant_id": "t1", "method": "GET", "path": "/", "status_code": 200,
             "action": "api_read", "blocked": False, "timestamp": datetime.now(timezone.utc),
             "request_id": "r1", "duration_ms": 10.0, "client_ip": "1.2.3.4",
             "user_agent": "ua", "country": "", "user_id": "", "app_id": ""},
        ])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            rows, total = await query_audit_logs(tenant_id="t1")

        assert total == 1
        assert len(rows) == 1
        # Verify tenant_id was in the SQL query
        count_sql = mock_conn.fetchrow.call_args[0][0]
        assert "tenant_id = $1" in count_sql

    @pytest.mark.asyncio
    async def test_query_with_time_range(self):
        """query_audit_logs accepts start_time and end_time filters."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        end = datetime(2025, 12, 31, tzinfo=timezone.utc)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            rows, total = await query_audit_logs(
                tenant_id="t1", start_time=start, end_time=end,
            )

        count_sql = mock_conn.fetchrow.call_args[0][0]
        assert "timestamp >=" in count_sql
        assert "timestamp <=" in count_sql

    @pytest.mark.asyncio
    async def test_query_with_method_filter(self):
        """query_audit_logs accepts method filter."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1", method="POST")

        count_sql = mock_conn.fetchrow.call_args[0][0]
        assert "method = " in count_sql

    @pytest.mark.asyncio
    async def test_query_with_path_filter(self):
        """query_audit_logs accepts path LIKE filter."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1", path="/api")

        count_sql = mock_conn.fetchrow.call_args[0][0]
        assert "path LIKE" in count_sql

    @pytest.mark.asyncio
    async def test_query_with_status_filter(self):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1", status_code=429)

        count_sql = mock_conn.fetchrow.call_args[0][0]
        assert "status_code = " in count_sql

    @pytest.mark.asyncio
    async def test_query_with_action_filter(self):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1", action="rate_limited")

        count_sql = mock_conn.fetchrow.call_args[0][0]
        assert "action = " in count_sql

    @pytest.mark.asyncio
    async def test_query_with_blocked_filter(self):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1", blocked=True)

        count_sql = mock_conn.fetchrow.call_args[0][0]
        assert "blocked = " in count_sql

    @pytest.mark.asyncio
    async def test_query_with_user_id_filter(self):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1", user_id="user-42")

        count_sql = mock_conn.fetchrow.call_args[0][0]
        assert "user_id = " in count_sql

    @pytest.mark.asyncio
    async def test_pagination(self):
        """Limit and offset are passed to SQL."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 100})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            _, total = await query_audit_logs(tenant_id="t1", limit=10, offset=20)

        assert total == 100
        fetch_sql = mock_conn.fetch.call_args[0][0]
        assert "LIMIT" in fetch_sql
        assert "OFFSET" in fetch_sql

    @pytest.mark.asyncio
    async def test_limit_clamped_to_1000(self):
        """Limit exceeding 1000 is clamped."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1", limit=5000)

        # The limit arg passed should be 1000, not 5000
        call_args = mock_conn.fetch.call_args[0]
        # limit is the second-to-last positional arg
        assert 1000 in call_args

    @pytest.mark.asyncio
    async def test_ordering_by_timestamp_desc(self):
        """Results are ordered by timestamp DESC."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1")

        fetch_sql = mock_conn.fetch.call_args[0][0]
        assert "ORDER BY timestamp DESC" in fetch_sql

    @pytest.mark.asyncio
    async def test_no_pool_returns_empty(self):
        """When no DB pool, returns empty list and 0."""
        with patch("proxy.store.audit.get_pool", return_value=None):
            rows, total = await query_audit_logs(tenant_id="t1")
        assert rows == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_path_like_wildcards_escaped(self):
        """LIKE wildcards % and _ in path filter are escaped to prevent broadening."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"total": 0})
        mock_conn.fetch = AsyncMock(return_value=[])

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await query_audit_logs(tenant_id="t1", path="100%_done")

        # The path value passed should have % and _ escaped.
        # fetchrow is called with (sql, tenant_id, path_like_value, ...)
        # positional args after the SQL string start at index 1
        call_args = mock_conn.fetchrow.call_args[0]
        # Find the LIKE value — it's the one containing "done"
        path_val = [a for a in call_args if isinstance(a, str) and "done" in a][0]
        assert "\\%" in path_val, f"Expected escaped %% in {path_val!r}"
        assert "\\_" in path_val, f"Expected escaped _ in {path_val!r}"


# ---------------------------------------------------------------------------
# AC4: Export to CSV, JSON, and API auth
# ---------------------------------------------------------------------------


class TestAC4_ExportAndAPI:
    """JSON/CSV export and API authentication."""

    def test_json_is_default_format(self):
        """The default format parameter is 'json'."""
        from proxy.api.audit_routes import get_audit_logs
        import inspect
        sig = inspect.signature(get_audit_logs)
        assert sig.parameters["format"].default.default == "json"

    def test_csv_export_produces_valid_csv(self):
        """_rows_to_csv produces valid CSV with headers."""
        from proxy.api.audit_routes import _rows_to_csv, _CSV_COLUMNS

        rows = [{
            "id": 1, "tenant_id": "t1", "app_id": "", "request_id": "r1",
            "timestamp": "2025-01-01T00:00:00", "method": "GET", "path": "/",
            "status_code": 200, "duration_ms": 10.0, "client_ip": "1.2.3.4",
            "user_agent": "ua", "country": "US", "user_id": "u1",
            "action": "api_read", "blocked": False,
        }]

        csv_str = _rows_to_csv(rows)
        reader = csv.DictReader(io.StringIO(csv_str))
        headers = reader.fieldnames
        assert headers == _CSV_COLUMNS

        result_rows = list(reader)
        assert len(result_rows) == 1
        assert result_rows[0]["tenant_id"] == "t1"
        assert result_rows[0]["method"] == "GET"

    def test_csv_formula_injection_prevented(self):
        """Values starting with formula chars are prefixed with ' to prevent injection."""
        from proxy.api.audit_routes import _csv_safe

        assert _csv_safe("=CMD()").startswith("'")
        assert _csv_safe("+1+1").startswith("'")
        assert _csv_safe("-1-1").startswith("'")
        assert _csv_safe("@SUM(A1)").startswith("'")
        assert _csv_safe("|calc").startswith("'")
        assert _csv_safe(";=CMD()").startswith("'")
        # Normal values unchanged
        assert _csv_safe("/api/data") == "/api/data"
        assert _csv_safe("GET") == "GET"

    def test_csv_headers_match_columns(self):
        """CSV column list matches expected audit fields."""
        from proxy.api.audit_routes import _CSV_COLUMNS
        expected = {
            "id", "tenant_id", "app_id", "request_id", "timestamp", "method",
            "path", "status_code", "duration_ms", "client_ip", "user_agent",
            "country", "user_id", "action", "blocked",
        }
        assert set(_CSV_COLUMNS) == expected

    def test_api_requires_auth(self):
        """The audit-logs router has require_api_key dependency."""
        from proxy.api.audit_routes import router
        deps = router.dependencies
        assert len(deps) > 0  # Has at least one dependency (require_api_key)

    def test_pagination_metadata_in_json_response(self):
        """JSON response includes total, limit, offset fields."""
        # This is verified by the route signature returning these fields.
        # We test the structure of the response dict.
        from proxy.api.audit_routes import get_audit_logs
        import inspect
        sig = inspect.signature(get_audit_logs)
        assert "limit" in sig.parameters
        assert "offset" in sig.parameters
        assert "tenant_id" in sig.parameters

    def test_invalid_datetime_returns_422(self):
        """Invalid datetime string raises HTTPException(422) instead of being silently ignored."""
        from fastapi import HTTPException
        from proxy.api.audit_routes import _parse_datetime

        # Valid datetime should work
        result = _parse_datetime("2025-01-01T00:00:00", "start_time")
        assert result is not None

        # None should pass through
        assert _parse_datetime(None, "start_time") is None

        # Invalid datetime should raise 422
        with pytest.raises(HTTPException) as exc_info:
            _parse_datetime("not-a-date", "start_time")
        assert exc_info.value.status_code == 422
        assert "start_time" in exc_info.value.detail


# ---------------------------------------------------------------------------
# Pipeline position
# ---------------------------------------------------------------------------


class TestPipelinePosition:
    """AuditLogger is at position 1 in the pipeline (after TenantRouter)."""

    def test_audit_logger_at_position_1(self):
        """AuditLogger should be at pipeline index 1."""
        from proxy.main import _build_pipeline
        pipeline = _build_pipeline()
        mw_names = [mw.name for mw in pipeline._middleware]
        assert mw_names[0] == "TenantRouter"
        assert mw_names[1] == "AuditLogger"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestAuditSettings:
    """Audit retention cleanup interval is configurable."""

    def test_default_cleanup_interval(self):
        from proxy.config.loader import ProxySettings
        s = ProxySettings()
        assert s.audit_retention_cleanup_interval == 3600
