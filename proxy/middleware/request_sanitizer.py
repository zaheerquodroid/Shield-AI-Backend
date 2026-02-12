"""Request sanitizer middleware — STUB: pass-through (Sprint 5)."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import Middleware, RequestContext


class RequestSanitizer(Middleware):
    """Sanitize incoming requests (WAF). Stub — passes all requests through."""

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        return None
