"""Response sanitizer middleware — STUB: pass-through (Sprint 4)."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import Middleware, RequestContext


class ResponseSanitizer(Middleware):
    """Sanitize outgoing responses (error masking). Stub — passes all responses through."""

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        return None
