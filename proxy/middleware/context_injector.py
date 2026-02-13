"""Context injector middleware — injects X-Request-ID, X-Tenant-ID, X-User-ID headers."""

from __future__ import annotations

from uuid import uuid4

import structlog
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import Middleware, RequestContext

logger = structlog.get_logger()

# Headers that clients must not be able to spoof
_STRIP_HEADERS = frozenset({
    "x-tenant-id",
    "x-user-id",
})

_STRIP_PREFIXES = ("x-shieldai-",)


class ContextInjector(Middleware):
    """Inject security context headers into upstream requests.

    - Generates a unique X-Request-ID (uuid4, first 8 chars)
    - Preserves original client X-Request-ID as X-Original-Request-ID
    - Strips spoofed X-Tenant-ID, X-User-ID, X-ShieldAI-* headers
    - Injects tenant_id and user_id from session context if available
    - Sets X-Forwarded-For and X-Forwarded-Proto
    """

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        # Generate request ID
        new_request_id = uuid4().hex[:8]

        # Preserve original client request ID if present
        client_request_id = request.headers.get("x-request-id")
        if client_request_id:
            context.extra["original_request_id"] = client_request_id

        # Set our request ID on context
        context.request_id = new_request_id

        # Bind request_id and tenant_id to structlog contextvars so all
        # subsequent log entries within this request include them.
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=new_request_id,
            tenant_id=context.tenant_id or "",
        )

        # Strip spoofed headers — we track which ones to strip so the proxy
        # handler knows not to forward them. Store in context for main.py.
        stripped = set()
        for header_name in request.headers:
            lower = header_name.lower()
            if lower in _STRIP_HEADERS:
                stripped.add(lower)
            elif any(lower.startswith(prefix) for prefix in _STRIP_PREFIXES):
                stripped.add(lower)
        context.extra["stripped_headers"] = stripped

        # Set X-Forwarded-For
        client_ip = request.client.host if request.client else "unknown"
        existing_xff = request.headers.get("x-forwarded-for")
        if existing_xff:
            context.extra["x_forwarded_for"] = f"{existing_xff}, {client_ip}"
        else:
            context.extra["x_forwarded_for"] = client_ip

        # Set X-Forwarded-Proto
        context.extra["x_forwarded_proto"] = request.url.scheme

        logger.debug(
            "context_injected",
            client_ip=client_ip,
        )

        return None

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        """Add context headers to response."""
        response.headers["x-request-id"] = context.request_id
        if context.extra.get("original_request_id"):
            # Sanitize client-provided value to prevent CRLF header injection
            safe_value = self._sanitize_header_value(context.extra["original_request_id"])
            response.headers["x-original-request-id"] = safe_value
        return response

    @staticmethod
    def _sanitize_header_value(value: str) -> str:
        """Strip CRLF and null bytes from a header value to prevent injection."""
        return value.replace("\r", "").replace("\n", "").replace("\x00", "")
