"""Tests for response sanitizer middleware."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from starlette.responses import JSONResponse, Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.response_sanitizer import (
    ResponseSanitizer,
    _SENSITIVE_PATTERNS,
    _STATUS_MESSAGES,
    _STRIP_HEADERS_EXACT,
    _build_error_response,
    detect_sensitive_content,
)


def _make_context(
    response_sanitizer: bool = True,
    sanitizer_mode: str | None = None,
) -> RequestContext:
    ctx = RequestContext(tenant_id="tenant-1")
    settings: dict = {}
    if sanitizer_mode:
        settings["response_sanitizer_mode"] = sanitizer_mode
    ctx.customer_config = {
        "enabled_features": {"response_sanitizer": response_sanitizer},
        "settings": settings,
    }
    return ctx


# ── Pattern detection — Python ────────────────────────────────────────


class TestDetectPythonTracebacks:
    def test_full_traceback(self):
        body = (
            'Traceback (most recent call last):\n'
            '  File "/app/server.py", line 42, in handler\n'
            '    raise ValueError("bad input")\n'
            'ValueError: bad input'
        )
        matches = detect_sensitive_content(body)
        assert "python_traceback" in matches
        assert "python_file_path" in matches
        assert "python_raise" in matches
        assert "value_error" in matches

    def test_traceback_case_insensitive(self):
        body = "traceback (most recent call last):"
        matches = detect_sensitive_content(body)
        assert "python_traceback" in matches

    def test_windows_python_path(self):
        body = 'File "C:\\Users\\dev\\app.py", line 10'
        matches = detect_sensitive_content(body)
        assert "python_file_path_windows" in matches

    def test_standalone_raise(self):
        body = "  raise RuntimeError('failed')"
        matches = detect_sensitive_content(body)
        assert "python_raise" in matches


# ── Pattern detection — Node.js ───────────────────────────────────────


class TestDetectNodejsStacks:
    def test_object_anonymous(self):
        body = "at Object.<anonymous> (/app/server.js:1:1)"
        matches = detect_sensitive_content(body)
        assert "nodejs_stack" in matches

    def test_module_compile(self):
        body = "at Module._compile (internal/modules/cjs/loader.js:999:30)"
        matches = detect_sensitive_content(body)
        assert "nodejs_module" in matches

    def test_function_module_load(self):
        body = "at Function.Module._load (internal/modules/cjs/loader.js:735:27)"
        matches = detect_sensitive_content(body)
        assert "nodejs_module_load" in matches

    def test_stack_frame_unix(self):
        body = "at processTicksAndRejections (/app/node_modules/express/lib/router/index.js:45:12)"
        matches = detect_sensitive_content(body)
        assert "nodejs_stack_frame" in matches

    def test_stack_frame_windows(self):
        body = "at Server.listen (C:\\Projects\\app\\server.js:10:5)"
        matches = detect_sensitive_content(body)
        assert "nodejs_stack_frame_windows" in matches


# ── Pattern detection — Java ──────────────────────────────────────────


class TestDetectJavaStacks:
    def test_java_stack_trace(self):
        body = "at com.example.MyClass.method(MyClass.java:42)"
        matches = detect_sensitive_content(body)
        assert "java_stack" in matches
        assert "java_file_ref" in matches

    def test_exception_in_thread(self):
        body = 'Exception in thread "main" java.lang.NullPointerException'
        matches = detect_sensitive_content(body)
        assert "java_exception_thread" in matches
        assert "null_pointer" in matches

    def test_caused_by(self):
        body = "Caused by: java.io.IOException"
        matches = detect_sensitive_content(body)
        assert "java_caused_by" in matches

    def test_org_package(self):
        body = "at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)"
        matches = detect_sensitive_content(body)
        assert "java_stack" in matches


# ── Pattern detection — Ruby/Rails ────────────────────────────────────


class TestDetectRubyStacks:
    def test_ruby_stack_frame(self):
        body = "from /usr/lib/ruby/2.7.0/net/http.rb:942:in `connect'"
        matches = detect_sensitive_content(body)
        assert "ruby_stack" in matches

    def test_rails_controller(self):
        body = "app/controllers/users_controller.rb:15:in `create'"
        matches = detect_sensitive_content(body)
        assert "rails_controller" in matches

    def test_rails_model(self):
        body = "app/models/user.rb:22:in `validate_email'"
        matches = detect_sensitive_content(body)
        assert "rails_model" in matches


# ── Pattern detection — .NET ──────────────────────────────────────────


class TestDetectDotnetStacks:
    def test_dotnet_stack_trace(self):
        body = "at MyApp.Controllers.HomeController.Index() in /src/Controllers/HomeController.cs:line 42"
        matches = detect_sensitive_content(body)
        assert "dotnet_stack" in matches

    def test_system_exception(self):
        body = "System.NullReferenceException: Object reference not set"
        matches = detect_sensitive_content(body)
        assert "dotnet_exception" in matches

    def test_system_io_exception(self):
        body = "System.IOFileException: Could not find file"
        matches = detect_sensitive_content(body)
        assert "dotnet_exception" in matches


# ── Pattern detection — Go ────────────────────────────────────────────


class TestDetectGoStacks:
    def test_goroutine(self):
        body = "goroutine 1 [running]:"
        matches = detect_sensitive_content(body)
        assert "go_goroutine" in matches

    def test_go_file_ref(self):
        body = "main.go:42 +0x1a4"
        matches = detect_sensitive_content(body)
        assert "go_file_ref" in matches


# ── Pattern detection — PHP ───────────────────────────────────────────


class TestDetectPhpStacks:
    def test_php_stack_trace(self):
        body = "Stack trace:\n#0 /var/www/html/index.php(42)"
        matches = detect_sensitive_content(body)
        assert "php_stack" in matches

    def test_php_fatal_error(self):
        body = "PHP Fatal error: Uncaught Error"
        matches = detect_sensitive_content(body)
        assert "php_error" in matches

    def test_php_warning(self):
        body = "PHP Warning: file_get_contents()"
        matches = detect_sensitive_content(body)
        assert "php_error" in matches

    def test_php_notice(self):
        body = "PHP Notice: Undefined variable"
        matches = detect_sensitive_content(body)
        assert "php_error" in matches


# ── Pattern detection — Database errors ───────────────────────────────


class TestDetectDatabaseErrors:
    def test_psycopg2_error(self):
        body = "psycopg2.OperationalError: connection refused"
        matches = detect_sensitive_content(body)
        assert "postgres_driver_error" in matches

    def test_asyncpg_error(self):
        body = "asyncpg.PostgresError: syntax error"
        matches = detect_sensitive_content(body)
        assert "postgres_driver_error" in matches

    def test_mysql_error(self):
        body = "mysql.ConnectorError: Access denied"
        matches = detect_sensitive_content(body)
        assert "mysql_driver_error" in matches

    def test_sqlstate(self):
        body = "SQLSTATE[42601]: syntax error at position 10"
        matches = detect_sensitive_content(body)
        assert "sqlstate_error" in matches

    def test_operational_error(self):
        body = "OperationalError: database is locked"
        matches = detect_sensitive_content(body)
        assert "operational_error" in matches

    def test_programming_error(self):
        body = "ProgrammingError: column does not exist"
        matches = detect_sensitive_content(body)
        assert "programming_error" in matches

    def test_integrity_error(self):
        body = "IntegrityError: duplicate key value"
        matches = detect_sensitive_content(body)
        assert "integrity_error" in matches


# ── Pattern detection — Generic errors ────────────────────────────────


class TestDetectGenericErrors:
    def test_syntax_error(self):
        assert "syntax_error" in detect_sensitive_content("SyntaxError: invalid syntax")

    def test_type_error(self):
        assert "type_error" in detect_sensitive_content("TypeError: 'NoneType' object")

    def test_name_error(self):
        assert "name_error" in detect_sensitive_content("NameError: name 'x' is not defined")

    def test_attribute_error(self):
        assert "attribute_error" in detect_sensitive_content("AttributeError: 'dict' object has no attribute 'foo'")

    def test_key_error(self):
        assert "key_error" in detect_sensitive_content("KeyError: 'missing_key'")

    def test_import_error(self):
        assert "import_error" in detect_sensitive_content("ImportError: No module named 'foo'")

    def test_module_not_found(self):
        assert "module_not_found_error" in detect_sensitive_content("ModuleNotFoundError: No module named 'bar'")

    def test_runtime_error(self):
        assert "runtime_error" in detect_sensitive_content("RuntimeError: maximum recursion depth")

    def test_null_pointer(self):
        assert "null_pointer" in detect_sensitive_content("NullPointerException")

    def test_class_not_found(self):
        assert "class_not_found" in detect_sensitive_content("ClassNotFoundException: com.example.Foo")

    def test_segfault(self):
        assert "segfault" in detect_sensitive_content("Segmentation fault (core dumped)")

    def test_segfault_case_insensitive(self):
        assert "segfault" in detect_sensitive_content("SEGMENTATION FAULT")


# ── Pattern detection — File paths ────────────────────────────────────


class TestDetectFilePaths:
    def test_unix_home_path(self):
        assert "unix_file_path" in detect_sensitive_content("/home/user/app/secret.conf")

    def test_unix_var_path(self):
        assert "unix_file_path" in detect_sensitive_content("/var/log/app/error.log")

    def test_unix_app_path(self):
        assert "unix_file_path" in detect_sensitive_content("/app/config/database.yml")

    def test_unix_etc_path(self):
        assert "unix_file_path" in detect_sensitive_content("/etc/passwd")

    def test_unix_tmp_path(self):
        assert "unix_file_path" in detect_sensitive_content("/tmp/debug_output.log")

    def test_windows_users_path(self):
        assert "windows_file_path" in detect_sensitive_content("C:\\Users\\admin\\Desktop\\app.exe")

    def test_windows_program_files(self):
        assert "windows_file_path" in detect_sensitive_content("C:\\Program Files\\MyApp\\config.ini")

    def test_windows_inetpub(self):
        assert "windows_file_path" in detect_sensitive_content("C:\\inetpub\\wwwroot\\web.config")


# ── Pattern detection — Network/secrets ───────────────────────────────


class TestDetectNetworkAndSecrets:
    def test_ip_address(self):
        assert "ip_address" in detect_sensitive_content("Connection refused to 192.168.1.100:5432")

    def test_ip_address_no_port(self):
        assert "ip_address" in detect_sensitive_content("Server at 10.0.0.1")

    def test_postgresql_connection_string(self):
        assert "connection_string" in detect_sensitive_content(
            "postgresql://user:password@db.example.com:5432/mydb"
        )

    def test_redis_connection_string(self):
        assert "connection_string" in detect_sensitive_content("redis://default:secret@redis.host:6379")

    def test_mongodb_connection_string(self):
        assert "connection_string" in detect_sensitive_content("mongodb://user:pass@mongo:27017/db")

    def test_env_var_database_url(self):
        assert "env_var_leak" in detect_sensitive_content("DATABASE_URL = postgresql://localhost/db")

    def test_env_var_secret_key(self):
        assert "env_var_leak" in detect_sensitive_content("SECRET_KEY=super-secret-value-123")

    def test_env_var_api_key(self):
        assert "env_var_leak" in detect_sensitive_content("API_KEY=sk-12345abcdef")

    def test_env_var_aws_key(self):
        assert "env_var_leak" in detect_sensitive_content("AWS_ACCESS_KEY = AKIAIOSFODNN7EXAMPLE")

    def test_sql_select_from(self):
        assert "sql_query_leak" in detect_sensitive_content(
            "SELECT id, email FROM users WHERE deleted = false"
        )

    def test_sql_insert_into(self):
        assert "sql_query_leak" in detect_sensitive_content(
            "INSERT INTO users (name, email) VALUES ('test', 'test@x.com')"
        )

    def test_sql_delete_from(self):
        assert "sql_query_leak" in detect_sensitive_content(
            "DELETE FROM sessions WHERE expired = true"
        )

    def test_sql_drop_table(self):
        assert "sql_query_leak" in detect_sensitive_content(
            "DROP TABLE users WHERE 1=1"
        )


# ── Pattern detection — Debug markers ─────────────────────────────────


class TestDetectDebugMarkers:
    def test_debug_true(self):
        assert "debug_mode_enabled" in detect_sensitive_content("DEBUG = True")

    def test_debug_true_case_insensitive(self):
        assert "debug_mode_enabled" in detect_sensitive_content("debug=true")

    def test_django_settings_module(self):
        assert "django_settings_leak" in detect_sensitive_content(
            "DJANGO_SETTINGS_MODULE=myapp.settings"
        )

    def test_settings_py(self):
        assert "settings_file_ref" in detect_sensitive_content("Error in settings.py at line 42")


# ── Pattern detection — No false positives ────────────────────────────


class TestDetectNoFalsePositives:
    def test_clean_json_body(self):
        body = '{"status": "ok", "data": {"id": 1, "name": "test"}}'
        matches = detect_sensitive_content(body)
        assert matches == []

    def test_clean_html(self):
        body = "<html><body><h1>Not Found</h1></body></html>"
        matches = detect_sensitive_content(body)
        assert matches == []

    def test_clean_error_message(self):
        body = '{"error": "Item not found", "code": 404}'
        matches = detect_sensitive_content(body)
        assert matches == []

    def test_normal_text_without_errors(self):
        body = "The user profile has been updated successfully."
        matches = detect_sensitive_content(body)
        assert matches == []


# ── Error response builder ────────────────────────────────────────────


class TestBuildErrorResponse:
    def test_known_status_code(self):
        resp = _build_error_response(500, "abc12345")
        assert resp.status_code == 500
        assert resp.body is not None
        body = resp.body.decode()
        assert '"error":true' in body
        assert '"status":500' in body
        assert "An internal error occurred. Please try again later." in body
        assert "abc12345" in body

    def test_all_known_status_codes_have_messages(self):
        """Every status code in _STATUS_MESSAGES produces a correct response."""
        for code, expected_msg in _STATUS_MESSAGES.items():
            resp = _build_error_response(code, "test123")
            assert resp.status_code == code
            body = resp.body.decode()
            assert expected_msg in body

    def test_unknown_status_code_uses_default(self):
        resp = _build_error_response(418, "teapot01")
        body = resp.body.decode()
        assert "An error occurred while processing your request." in body
        assert "teapot01" in body

    def test_response_is_json_content_type(self):
        resp = _build_error_response(500, "test")
        assert "application/json" in resp.headers.get("content-type", "")

    def test_no_sensitive_data_in_response(self):
        """Error response must not contain any patterns that would trigger detection."""
        resp = _build_error_response(500, "ref12345")
        body = resp.body.decode()
        matches = detect_sensitive_content(body)
        assert matches == [], f"Error response itself triggered patterns: {matches}"


# ── ResponseSanitizer middleware — sanitize mode ──────────────────────


class TestSanitizeModeBasic:
    @pytest.mark.asyncio
    async def test_error_with_traceback_is_sanitized(self):
        """500 response with Python traceback must be replaced with clean JSON."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = (
            'Traceback (most recent call last):\n'
            '  File "/app/main.py", line 10, in handler\n'
            '    raise ValueError("oops")\n'
            'ValueError: oops'
        )
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        assert result.status_code == 500
        result_body = result.body.decode()
        assert "Traceback" not in result_body
        assert "/app/main.py" not in result_body
        assert "ValueError" not in result_body
        assert '"error":true' in result_body
        assert '"error_id":' in result_body

    @pytest.mark.asyncio
    async def test_error_with_nodejs_stack_is_sanitized(self):
        """500 with Node.js stack trace must be sanitized."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "Error: Cannot find module 'express'\nat Module._compile (/app/node_modules/loader.js:1:1)"
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "Module._compile" not in result_body
        assert "node_modules" not in result_body
        assert '"error":true' in result_body

    @pytest.mark.asyncio
    async def test_error_with_java_stack_is_sanitized(self):
        """500 with Java stack trace must be sanitized."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = (
            "Exception in thread \"main\" java.lang.NullPointerException\n"
            "  at com.example.MyService.process(MyService.java:42)"
        )
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "NullPointerException" not in result_body
        assert "com.example" not in result_body
        assert '"error":true' in result_body

    @pytest.mark.asyncio
    async def test_error_with_connection_string_is_sanitized(self):
        """Error exposing database connection string must be sanitized."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "OperationalError: could not connect to postgresql://admin:s3cret@db.prod.internal:5432/app"
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "postgresql://" not in result_body
        assert "s3cret" not in result_body
        assert "db.prod.internal" not in result_body

    @pytest.mark.asyncio
    async def test_error_with_env_var_leak_is_sanitized(self):
        """Error leaking environment variables must be sanitized."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = 'Configuration error: SECRET_KEY = my-super-secret-key-12345'
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "my-super-secret-key" not in result_body
        assert "SECRET_KEY" not in result_body

    @pytest.mark.asyncio
    async def test_error_with_sql_leak_is_sanitized(self):
        """Error leaking SQL queries must be sanitized."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "ProgrammingError: SELECT email, password_hash FROM users WHERE id = 1"
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "password_hash" not in result_body
        assert "SELECT" not in result_body
        assert "FROM users" not in result_body

    @pytest.mark.asyncio
    async def test_400_with_sensitive_content_is_sanitized(self):
        """4xx error responses with sensitive content are also sanitized."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "TypeError: argument must be str, not NoneType"
        response = Response(content=body, status_code=400)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "TypeError" not in result_body
        assert '"status":400' in result_body


# ── ResponseSanitizer middleware — 2xx not touched ────────────────────


class TestSanitizeModePassesSuccessful:
    @pytest.mark.asyncio
    async def test_200_not_scanned(self):
        """2xx responses should never be modified, even with sensitive-looking content."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = 'Traceback (most recent call last):\n  File "/app/test.py", line 1'
        response = Response(content=body, status_code=200)

        result = await mw.process_response(response, ctx)

        # Body should be unchanged — 200s pass through
        assert result.body.decode() == body

    @pytest.mark.asyncio
    async def test_201_not_scanned(self):
        """201 responses pass through even with error-like content."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = '{"message": "Created", "debug": "OperationalError test"}'
        response = Response(content=body, status_code=201)

        result = await mw.process_response(response, ctx)

        assert result.body.decode() == body

    @pytest.mark.asyncio
    async def test_301_not_scanned(self):
        """3xx responses pass through."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        response = Response(content="", status_code=301)

        result = await mw.process_response(response, ctx)

        assert result.status_code == 301


# ── ResponseSanitizer middleware — log_only mode ──────────────────────


class TestLogOnlyMode:
    @pytest.mark.asyncio
    async def test_log_only_passes_body_through(self):
        """In log_only mode, sensitive content is detected but NOT replaced."""
        mw = ResponseSanitizer()
        ctx = _make_context(sanitizer_mode="log_only")
        body = 'Traceback (most recent call last):\n  File "/app/main.py", line 10'
        response = Response(content=body, status_code=500)

        with patch("proxy.middleware.response_sanitizer.logger") as mock_logger:
            result = await mw.process_response(response, ctx)

        # Body is unchanged in log_only mode
        assert result.body.decode() == body
        # But it was logged
        mock_logger.warning.assert_called_once()
        call_kwargs = mock_logger.warning.call_args
        assert call_kwargs[0][0] == "sensitive_content_detected"

    @pytest.mark.asyncio
    async def test_log_only_still_strips_headers(self):
        """log_only mode still strips sensitive headers."""
        mw = ResponseSanitizer()
        ctx = _make_context(sanitizer_mode="log_only")
        response = Response(
            content="Internal error",
            status_code=500,
            headers={"server": "nginx/1.24", "x-powered-by": "Express"},
        )

        result = await mw.process_response(response, ctx)

        assert "server" not in result.headers
        assert "x-powered-by" not in result.headers


# ── ResponseSanitizer middleware — passthrough mode ───────────────────


class TestPassthroughMode:
    @pytest.mark.asyncio
    async def test_passthrough_no_scanning(self):
        """In passthrough mode, no scanning occurs and body is untouched."""
        mw = ResponseSanitizer()
        ctx = _make_context(sanitizer_mode="passthrough")
        body = 'Traceback (most recent call last):\n  File "/app/main.py", line 10'
        response = Response(content=body, status_code=500)

        with patch("proxy.middleware.response_sanitizer.logger") as mock_logger:
            result = await mw.process_response(response, ctx)

        assert result.body.decode() == body
        mock_logger.warning.assert_not_called()

    @pytest.mark.asyncio
    async def test_passthrough_still_strips_headers(self):
        """Even passthrough mode strips sensitive headers."""
        mw = ResponseSanitizer()
        ctx = _make_context(sanitizer_mode="passthrough")
        response = Response(
            content="ok",
            status_code=200,
            headers={"server": "Apache/2.4", "x-aspnet-version": "4.0"},
        )

        result = await mw.process_response(response, ctx)

        assert "server" not in result.headers
        assert "x-aspnet-version" not in result.headers


# ── ResponseSanitizer — header stripping ──────────────────────────────


class TestHeaderStripping:
    @pytest.mark.asyncio
    async def test_strips_all_exact_headers(self):
        """All headers in the exact strip list must be removed."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        headers = {
            "x-aspnet-version": "4.0.30319",
            "x-aspnetmvc-version": "5.2",
            "x-powered-by": "ASP.NET",
            "server": "Microsoft-IIS/10.0",
            "x-runtime": "0.123456",
            "x-generated-by": "MyFramework",
            "x-sourcefiles": "=?UTF-8?B?...",
            "x-custom-safe": "keep-me",
        }
        response = Response(content="ok", status_code=200, headers=headers)

        result = await mw.process_response(response, ctx)

        for h in _STRIP_HEADERS_EXACT:
            assert h not in result.headers, f"Header {h} should have been stripped"
        assert result.headers.get("x-custom-safe") == "keep-me"

    @pytest.mark.asyncio
    async def test_strips_debug_prefixed_headers(self):
        """Headers starting with x-debug- must be stripped."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        response = Response(
            content="ok",
            status_code=200,
            headers={
                "x-debug-query-count": "42",
                "x-debug-time": "0.5s",
                "x-request-id": "keep-this",
            },
        )

        result = await mw.process_response(response, ctx)

        assert "x-debug-query-count" not in result.headers
        assert "x-debug-time" not in result.headers
        assert result.headers.get("x-request-id") == "keep-this"

    @pytest.mark.asyncio
    async def test_header_stripping_on_2xx_responses(self):
        """Sensitive headers are stripped even from successful responses."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        response = Response(
            content='{"ok": true}',
            status_code=200,
            headers={"server": "nginx", "content-type": "application/json"},
        )

        result = await mw.process_response(response, ctx)

        assert "server" not in result.headers
        # content-type should be preserved
        assert "application/json" in result.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_header_stripping_case_insensitive(self):
        """Header name matching is case-insensitive."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        response = Response(
            content="ok",
            status_code=200,
            headers={"Server": "nginx", "X-Powered-By": "Express"},
        )

        result = await mw.process_response(response, ctx)

        # Starlette lowercases header names internally
        assert "server" not in result.headers


# ── ResponseSanitizer — feature flag ──────────────────────────────────


class TestFeatureFlag:
    @pytest.mark.asyncio
    async def test_disabled_skips_scanning(self):
        """When response_sanitizer feature is disabled, body is not scanned."""
        mw = ResponseSanitizer()
        ctx = _make_context(response_sanitizer=False)
        body = 'Traceback (most recent call last):\n  File "/app/main.py", line 10'
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        # Body unchanged because feature is disabled
        assert result.body.decode() == body

    @pytest.mark.asyncio
    async def test_disabled_still_strips_headers(self):
        """Even when scanning is disabled, headers are still stripped."""
        mw = ResponseSanitizer()
        ctx = _make_context(response_sanitizer=False)
        response = Response(
            content="error",
            status_code=500,
            headers={"server": "nginx"},
        )

        result = await mw.process_response(response, ctx)

        assert "server" not in result.headers

    @pytest.mark.asyncio
    async def test_missing_enabled_features_defaults_to_enabled(self):
        """Missing enabled_features key defaults to scanning enabled."""
        mw = ResponseSanitizer()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {"settings": {}}  # no enabled_features
        body = 'Traceback (most recent call last):\n  File "/app/main.py", line 10'
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        # Should be sanitized (default enabled)
        result_body = result.body.decode()
        assert "Traceback" not in result_body

    @pytest.mark.asyncio
    async def test_missing_response_sanitizer_flag_defaults_to_enabled(self):
        """Missing response_sanitizer flag defaults to True."""
        mw = ResponseSanitizer()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {
            "enabled_features": {"waf": True},  # no response_sanitizer key
            "settings": {},
        }
        body = "OperationalError: connection refused"
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "OperationalError" not in result_body


# ── ResponseSanitizer — mode resolution ───────────────────────────────


class TestModeResolution:
    @pytest.mark.asyncio
    async def test_customer_mode_overrides_global(self):
        """Per-customer mode should override global setting."""
        mw = ResponseSanitizer()
        ctx = _make_context(sanitizer_mode="passthrough")
        body = "Traceback (most recent call last):"
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        # passthrough mode: body untouched
        assert result.body.decode() == body

    @pytest.mark.asyncio
    async def test_invalid_customer_mode_falls_back_to_global(self):
        """Invalid customer mode falls back to global setting."""
        mw = ResponseSanitizer()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {
            "enabled_features": {"response_sanitizer": True},
            "settings": {"response_sanitizer_mode": "invalid_mode"},
        }
        body = "Traceback (most recent call last):"
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        # Falls back to global default "sanitize" mode
        result_body = result.body.decode()
        assert "Traceback" not in result_body

    @pytest.mark.asyncio
    async def test_no_customer_mode_uses_global(self):
        """No customer mode setting uses global default."""
        mw = ResponseSanitizer()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {
            "enabled_features": {"response_sanitizer": True},
            "settings": {},  # no mode setting
        }
        body = "asyncpg.PostgresError: relation does not exist"
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "asyncpg" not in result_body


# ── ResponseSanitizer — error ID and logging ──────────────────────────


class TestErrorIdAndLogging:
    @pytest.mark.asyncio
    async def test_error_id_in_sanitized_response(self):
        """Sanitized response contains an error_id for support reference."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "Traceback (most recent call last):"
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert '"error_id":' in result_body

    @pytest.mark.asyncio
    async def test_error_id_logged_with_original_body(self):
        """Logger receives the error_id and original body for debugging."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "Traceback (most recent call last):\n  raise ValueError"
        response = Response(content=body, status_code=500)

        with patch("proxy.middleware.response_sanitizer.logger") as mock_logger:
            result = await mw.process_response(response, ctx)

        mock_logger.warning.assert_called_once()
        call_kwargs = mock_logger.warning.call_args[1]
        assert "error_id" in call_kwargs
        assert "original_body" in call_kwargs
        assert "Traceback" in call_kwargs["original_body"]
        assert "patterns" in call_kwargs
        assert "python_traceback" in call_kwargs["patterns"]

    @pytest.mark.asyncio
    async def test_original_body_capped_at_2kb(self):
        """Logged original body is capped at 2000 chars."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "Traceback (most recent call last):\n" + "x" * 3000
        response = Response(content=body, status_code=500)

        with patch("proxy.middleware.response_sanitizer.logger") as mock_logger:
            await mw.process_response(response, ctx)

        call_kwargs = mock_logger.warning.call_args[1]
        assert len(call_kwargs["original_body"]) <= 2000


# ── ResponseSanitizer — sanitized response preserves safe headers ─────


class TestSanitizedResponseHeaders:
    @pytest.mark.asyncio
    async def test_preserves_safe_headers(self):
        """Non-sensitive headers from original response are preserved."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "Traceback (most recent call last):"
        response = Response(
            content=body,
            status_code=500,
            headers={
                "x-request-id": "req-123",
                "x-correlation-id": "corr-456",
                "cache-control": "no-store",
            },
        )

        result = await mw.process_response(response, ctx)

        assert result.headers.get("x-request-id") == "req-123"
        assert result.headers.get("x-correlation-id") == "corr-456"
        assert result.headers.get("cache-control") == "no-store"

    @pytest.mark.asyncio
    async def test_does_not_preserve_sensitive_headers(self):
        """Sensitive headers from original are NOT copied to sanitized response."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "Traceback (most recent call last):"
        response = Response(
            content=body,
            status_code=500,
            headers={
                "server": "nginx/1.24",
                "x-powered-by": "Express",
                "x-debug-time": "0.5",
                "x-request-id": "keep",
            },
        )

        result = await mw.process_response(response, ctx)

        assert "server" not in result.headers
        assert "x-powered-by" not in result.headers
        assert "x-debug-time" not in result.headers
        assert result.headers.get("x-request-id") == "keep"

    @pytest.mark.asyncio
    async def test_sanitized_response_has_json_content_type(self):
        """Sanitized response has application/json content-type."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "Traceback (most recent call last):"
        response = Response(
            content=body,
            status_code=500,
            headers={"content-type": "text/html"},
        )

        result = await mw.process_response(response, ctx)

        assert "application/json" in result.headers.get("content-type", "")


# ── ResponseSanitizer — edge cases ────────────────────────────────────


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_body_passes_through(self):
        """Empty body should pass through without error."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        response = Response(content="", status_code=500)

        result = await mw.process_response(response, ctx)

        assert result.status_code == 500

    @pytest.mark.asyncio
    async def test_clean_error_body_passes_through(self):
        """Error with clean body (no patterns matched) passes through unchanged."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = '{"error": "Resource not found", "code": 404}'
        response = Response(content=body, status_code=404)

        result = await mw.process_response(response, ctx)

        # No sensitive patterns matched, so body is unchanged
        assert result.body.decode() == body

    @pytest.mark.asyncio
    async def test_non_utf8_body_handled_gracefully(self):
        """Binary/non-UTF-8 body should not crash the middleware."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        # Create response with binary content that's invalid UTF-8
        response = Response(content=b"\xff\xfe\x00\x01", status_code=500)

        # Should not raise
        result = await mw.process_response(response, ctx)
        assert result.status_code == 500

    @pytest.mark.asyncio
    async def test_very_large_body_is_processed(self):
        """Large error bodies are still scanned and sanitized."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        # Large body with traceback buried in the middle
        body = "A" * 5000 + "\nTraceback (most recent call last):\n" + "B" * 5000
        response = Response(content=body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        assert "Traceback" not in result_body
        assert '"error":true' in result_body

    @pytest.mark.asyncio
    async def test_process_request_returns_none(self):
        """process_request should always return None (noop)."""
        from starlette.requests import Request

        mw = ResponseSanitizer()
        ctx = _make_context()
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [],
            "root_path": "",
            "server": ("localhost", 8080),
            "client": ("127.0.0.1", 12345),
        }
        request = Request(scope)
        result = await mw.process_request(request, ctx)
        assert result is None


# ── ResponseSanitizer — status code preservation ──────────────────────


class TestStatusCodePreservation:
    @pytest.mark.asyncio
    async def test_preserves_original_status_code(self):
        """Sanitized response should keep the original HTTP status code."""
        mw = ResponseSanitizer()
        ctx = _make_context()

        for code in [400, 401, 403, 404, 500, 502, 503]:
            body = "Traceback (most recent call last):"
            response = Response(content=body, status_code=code)
            result = await mw.process_response(response, ctx)
            assert result.status_code == code, f"Status {code} was not preserved"

    @pytest.mark.asyncio
    async def test_unknown_4xx_status_preserved(self):
        """Unusual 4xx status codes are preserved."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = "OperationalError: connection failed"
        response = Response(content=body, status_code=451)

        result = await mw.process_response(response, ctx)

        assert result.status_code == 451


# ── ResponseSanitizer — multi-pattern detection ───────────────────────


class TestMultiPatternDetection:
    @pytest.mark.asyncio
    async def test_multiple_patterns_all_logged(self):
        """When multiple patterns match, all are logged."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        body = (
            "Traceback (most recent call last):\n"
            '  File "/app/db.py", line 10\n'
            "asyncpg.PostgresError: SELECT * FROM users WHERE id = 1\n"
            "DATABASE_URL = postgresql://admin:secret@db:5432/prod\n"
        )
        response = Response(content=body, status_code=500)

        with patch("proxy.middleware.response_sanitizer.logger") as mock_logger:
            result = await mw.process_response(response, ctx)

        call_kwargs = mock_logger.warning.call_args[1]
        patterns = call_kwargs["patterns"]
        assert "python_traceback" in patterns
        assert "postgres_driver_error" in patterns
        assert "connection_string" in patterns
        assert "env_var_leak" in patterns

        # Sanitized body must not contain ANY of the original content
        result_body = result.body.decode()
        assert "Traceback" not in result_body
        assert "asyncpg" not in result_body
        assert "postgresql://" not in result_body
        assert "DATABASE_URL" not in result_body


# ── ResponseSanitizer — security guarantees ───────────────────────────


class TestSecurityGuarantees:
    @pytest.mark.asyncio
    async def test_sanitized_body_never_leaks_original_content(self):
        """The sanitized JSON response must contain ZERO content from the original body."""
        mw = ResponseSanitizer()
        ctx = _make_context()
        sensitive_body = (
            "CRITICAL ERROR at com.corp.internal.SecretHandler.handle(SecretHandler.java:99)\n"
            "Caused by: java.sql.SQLException\n"
            "SELECT password_hash, ssn FROM customers WHERE email = 'admin@corp.com'\n"
            "API_KEY = sk-live-abc123xyz789\n"
            "postgresql://root:p4$$w0rd@10.0.0.50:5432/production\n"
            "AWS_ACCESS_KEY = AKIAIOSFODNN7EXAMPLE\n"
        )
        response = Response(content=sensitive_body, status_code=500)

        result = await mw.process_response(response, ctx)

        result_body = result.body.decode()
        # None of these sensitive strings should appear in the sanitized output
        assert "SecretHandler" not in result_body
        assert "password_hash" not in result_body
        assert "ssn" not in result_body
        assert "admin@corp.com" not in result_body
        assert "sk-live-abc123" not in result_body
        assert "p4$$w0rd" not in result_body
        assert "10.0.0.50" not in result_body
        assert "AKIAIOSFODNN7EXAMPLE" not in result_body

    @pytest.mark.asyncio
    async def test_header_stripping_cannot_be_bypassed_by_mode(self):
        """Header stripping happens regardless of sanitizer mode."""
        mw = ResponseSanitizer()
        for mode in ["sanitize", "log_only", "passthrough"]:
            ctx = _make_context(sanitizer_mode=mode)
            response = Response(
                content="ok",
                status_code=200,
                headers={"server": "Apache", "x-powered-by": "PHP"},
            )
            result = await mw.process_response(response, ctx)
            assert "server" not in result.headers, f"server header leaked in {mode} mode"
            assert "x-powered-by" not in result.headers, f"x-powered-by leaked in {mode} mode"

    @pytest.mark.asyncio
    async def test_header_stripping_cannot_be_bypassed_by_feature_flag(self):
        """Header stripping happens even when feature flag is disabled."""
        mw = ResponseSanitizer()
        ctx = _make_context(response_sanitizer=False)
        response = Response(
            content="error",
            status_code=500,
            headers={"server": "nginx", "x-aspnet-version": "4.0"},
        )

        result = await mw.process_response(response, ctx)

        assert "server" not in result.headers
        assert "x-aspnet-version" not in result.headers

    @pytest.mark.asyncio
    async def test_all_sensitive_patterns_are_compiled(self):
        """All pattern entries are valid compiled regexes with names."""
        for pattern, name in _SENSITIVE_PATTERNS:
            assert hasattr(pattern, "search"), f"Pattern for {name} is not a compiled regex"
            assert isinstance(name, str), f"Pattern name must be str, got {type(name)}"
            assert len(name) > 0, "Pattern name must not be empty"

    @pytest.mark.asyncio
    async def test_pattern_list_covers_major_frameworks(self):
        """Pattern list must cover all major web frameworks."""
        pattern_names = {name for _, name in _SENSITIVE_PATTERNS}
        # Python
        assert "python_traceback" in pattern_names
        # Node.js
        assert "nodejs_stack" in pattern_names
        # Java
        assert "java_stack" in pattern_names
        # Ruby
        assert "ruby_stack" in pattern_names
        # .NET
        assert "dotnet_stack" in pattern_names
        # Go
        assert "go_goroutine" in pattern_names
        # PHP
        assert "php_stack" in pattern_names
        # Database
        assert "postgres_driver_error" in pattern_names
        assert "mysql_driver_error" in pattern_names
        # Secrets
        assert "connection_string" in pattern_names
        assert "env_var_leak" in pattern_names
        assert "sql_query_leak" in pattern_names
