"""Response sanitizer middleware — masks sensitive data in error responses."""

from __future__ import annotations

import re
from uuid import uuid4

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxy.config.loader import get_settings
from proxy.middleware.pipeline import Middleware, RequestContext

logger = structlog.get_logger()

# ── Sensitive patterns ──────────────────────────────────────────────────
# Each tuple: (compiled regex, description for audit log)

_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Python tracebacks
    (re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE), "python_traceback"),
    (re.compile(r'File "/.+?", line \d+'), "python_file_path"),
    (re.compile(r'File "[A-Z]:\\.+?", line \d+'), "python_file_path_windows"),
    (re.compile(r"^\s+raise \w+", re.MULTILINE), "python_raise"),

    # Node.js stack traces
    (re.compile(r"at Object\.<anonymous>"), "nodejs_stack"),
    (re.compile(r"at Module\._compile"), "nodejs_module"),
    (re.compile(r"at Function\.Module\._load"), "nodejs_module_load"),
    (re.compile(r"at\s+\S+\s+\(/.+?:\d+:\d+\)"), "nodejs_stack_frame"),
    (re.compile(r"at\s+\S+\s+\([A-Z]:\\.+?:\d+:\d+\)"), "nodejs_stack_frame_windows"),

    # Java stack traces
    (re.compile(r"at\s+(com|org|java|javax|sun)\.\S+\(.+?:\d+\)"), "java_stack"),
    (re.compile(r"Exception in thread"), "java_exception_thread"),
    (re.compile(r"Caused by:\s+\S+Exception"), "java_caused_by"),
    (re.compile(r"\.java:\d+\)"), "java_file_ref"),

    # Ruby/Rails stack traces
    (re.compile(r"from\s+/.+?:\d+:in\s+`"), "ruby_stack"),
    (re.compile(r"app/controllers/\S+"), "rails_controller"),
    (re.compile(r"app/models/\S+"), "rails_model"),

    # .NET/C# stack traces
    (re.compile(r"at\s+\S+\.\S+\(.*?\)\s+in\s+\S+:line\s+\d+"), "dotnet_stack"),
    (re.compile(r"System\.\w+Exception"), "dotnet_exception"),

    # Go stack traces
    (re.compile(r"goroutine \d+ \["), "go_goroutine"),
    (re.compile(r"\S+\.go:\d+"), "go_file_ref"),

    # PHP stack traces
    (re.compile(r"Stack trace:\s*#\d+"), "php_stack"),
    (re.compile(r"PHP (?:Fatal error|Warning|Notice|Parse error)", re.IGNORECASE), "php_error"),

    # Generic error markers
    (re.compile(r"\b(psycopg2|psycopg|asyncpg)\.\w*Error", re.IGNORECASE), "postgres_driver_error"),
    (re.compile(r"\bmysql\.\w*Error", re.IGNORECASE), "mysql_driver_error"),
    (re.compile(r"\bSQLSTATE\[", re.IGNORECASE), "sqlstate_error"),
    (re.compile(r"\bOperationalError\b"), "operational_error"),
    (re.compile(r"\bProgrammingError\b"), "programming_error"),
    (re.compile(r"\bIntegrityError\b"), "integrity_error"),
    (re.compile(r"\bSyntaxError\b"), "syntax_error"),
    (re.compile(r"\bTypeError\b"), "type_error"),
    (re.compile(r"\bNameError\b"), "name_error"),
    (re.compile(r"\bAttributeError\b"), "attribute_error"),
    (re.compile(r"\bKeyError\b"), "key_error"),
    (re.compile(r"\bValueError\b"), "value_error"),
    (re.compile(r"\bImportError\b"), "import_error"),
    (re.compile(r"\bModuleNotFoundError\b"), "module_not_found_error"),
    (re.compile(r"\bRuntimeError\b"), "runtime_error"),
    (re.compile(r"\bNullPointerException\b"), "null_pointer"),
    (re.compile(r"\bClassNotFoundException\b"), "class_not_found"),
    (re.compile(r"\bSegmentation fault", re.IGNORECASE), "segfault"),

    # File/directory paths (Unix and Windows)
    (re.compile(r"(?:/(?:home|var|usr|app|opt|etc|tmp|srv|root)/)\S+"), "unix_file_path"),
    (re.compile(r"[A-Z]:\\(?:Users|Windows|Program Files|inetpub)\\\S+"), "windows_file_path"),

    # IP addresses (avoid matching version numbers like "1.0")
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "ip_address"),

    # Connection strings / DSNs
    (re.compile(r"(?:postgresql|postgres|mysql|mongodb|redis|amqp|mssql)://\S+", re.IGNORECASE), "connection_string"),

    # Environment variable leaks
    (re.compile(r"\b(?:DATABASE_URL|SECRET_KEY|API_KEY|AWS_ACCESS_KEY|PRIVATE_KEY|PASSWORD)\s*=\s*\S+", re.IGNORECASE), "env_var_leak"),

    # SQL query fragments in errors — use non-greedy match with length limit to prevent ReDoS
    (re.compile(r"\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM|DROP TABLE|ALTER TABLE)\b.{1,500}?\b(?:FROM|WHERE|SET|VALUES)\b", re.IGNORECASE), "sql_query_leak"),

    # Debug mode markers
    (re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE), "debug_mode_enabled"),
    (re.compile(r"DJANGO_SETTINGS_MODULE"), "django_settings_leak"),
    (re.compile(r"settings\.py"), "settings_file_ref"),
]

# ── Status-specific clean messages ──────────────────────────────────────

_STATUS_MESSAGES: dict[int, str] = {
    400: "The request was invalid or malformed.",
    401: "Authentication is required to access this resource.",
    403: "You do not have permission to access this resource.",
    404: "The requested resource was not found.",
    405: "The request method is not allowed for this resource.",
    408: "The request timed out.",
    409: "The request conflicts with the current state of the resource.",
    413: "The request payload is too large.",
    415: "The request media type is not supported.",
    422: "The request was well-formed but contains invalid data.",
    429: "Too many requests. Please try again later.",
    500: "An internal error occurred. Please try again later.",
    502: "The upstream service is temporarily unavailable.",
    503: "The service is temporarily unavailable.",
    504: "The upstream service did not respond in time.",
}

_DEFAULT_MESSAGE = "An error occurred while processing your request."

# ── Headers to strip from all responses ─────────────────────────────────

_STRIP_HEADERS_EXACT = frozenset({
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-powered-by",
    "server",
    "x-runtime",
    "x-generated-by",
    "x-sourcefiles",
})

_STRIP_HEADER_PREFIXES = ("x-debug-",)


def _build_error_response(status_code: int, error_id: str) -> JSONResponse:
    """Build a clean JSON error response with no sensitive data."""
    message = _STATUS_MESSAGES.get(status_code, _DEFAULT_MESSAGE)
    return JSONResponse(
        status_code=status_code,
        content={
            "error": True,
            "status": status_code,
            "message": message,
            "error_id": error_id,
        },
    )


def detect_sensitive_content(body: str, *, first_match_only: bool = False) -> list[str]:
    """Scan body text for sensitive patterns. Returns list of matched pattern names.

    When *first_match_only* is True, returns after the first match for faster
    detection when the caller only needs to know *if* sensitive content exists.
    """
    matches = []
    for pattern, name in _SENSITIVE_PATTERNS:
        if pattern.search(body):
            matches.append(name)
            if first_match_only:
                return matches
    return matches


class ResponseSanitizer(Middleware):
    """Sanitize outgoing error responses to prevent information leakage.

    Modes (via config or per-customer feature flag):
      - sanitize: replace sensitive error bodies with clean JSON (default)
      - log_only: detect and log sensitive content, but pass response through
      - passthrough: no scanning or modification

    Always strips sensitive headers regardless of mode.
    """

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        return None

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        # Always strip sensitive headers, regardless of mode or status
        response = self._strip_headers(response)

        # Determine mode — per-customer override, then global setting
        mode = self._get_mode(context)
        if mode == "passthrough":
            return response

        # Only scan error responses (4xx/5xx)
        if response.status_code < 400:
            return response

        # Check feature flag
        features = context.customer_config.get("enabled_features", {})
        if not features.get("response_sanitizer", True):
            return response

        # Read response body — guard against StreamingResponse or other
        # response types that lack a .body attribute.  Without this check
        # an attacker who can trigger a streaming error response would
        # bypass sensitive content scanning entirely.
        body_bytes = getattr(response, "body", None)
        if body_bytes is None:
            logger.warning(
                "response_sanitizer_skip_no_body",
                response_type=type(response).__name__,
                status_code=response.status_code,
                request_id=context.request_id,
                tenant_id=context.tenant_id,
            )
            return response
        if not body_bytes:
            return response

        try:
            body_text = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            return response

        # Scan for sensitive patterns.
        # In sanitize mode we only need to know IF there's a match (early-exit).
        # In log_only mode we want the full list for audit.
        matches = detect_sensitive_content(body_text, first_match_only=(mode == "sanitize"))
        if not matches:
            return response

        # Generate error reference ID
        error_id = uuid4().hex[:8]

        # Log the original error with reference ID for debugging
        logger.warning(
            "sensitive_content_detected",
            error_id=error_id,
            request_id=context.request_id,
            status_code=response.status_code,
            patterns=matches,
            path=context.extra.get("path", ""),
            method=context.extra.get("method", ""),
            tenant_id=context.tenant_id,
            original_body=body_text[:2000],  # cap logged body at 2KB
        )

        if mode == "log_only":
            return response

        # mode == "sanitize": replace body with clean error response
        sanitized = _build_error_response(response.status_code, error_id)

        # Preserve any headers from the original response that aren't sensitive
        for key, value in response.headers.items():
            lower = key.lower()
            if lower in _STRIP_HEADERS_EXACT:
                continue
            if any(lower.startswith(p) for p in _STRIP_HEADER_PREFIXES):
                continue
            # Don't overwrite content-type/content-length set by JSONResponse
            if lower in ("content-type", "content-length"):
                continue
            sanitized.headers[key] = value

        return sanitized

    def _get_mode(self, context: RequestContext) -> str:
        """Get sanitizer mode from customer config or global settings."""
        customer_settings = context.customer_config.get("settings", {})
        mode = customer_settings.get("response_sanitizer_mode")
        if mode in ("sanitize", "log_only", "passthrough"):
            return mode
        return get_settings().response_sanitizer_mode

    def _strip_headers(self, response: Response) -> Response:
        """Strip sensitive headers from the response."""
        headers_to_remove = []
        for key in response.headers:
            lower = key.lower()
            if lower in _STRIP_HEADERS_EXACT:
                headers_to_remove.append(key)
            elif any(lower.startswith(p) for p in _STRIP_HEADER_PREFIXES):
                headers_to_remove.append(key)

        for key in headers_to_remove:
            del response.headers[key]

        return response
