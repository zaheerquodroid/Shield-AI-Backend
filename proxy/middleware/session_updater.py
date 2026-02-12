"""Session updater middleware — STUB: pass-through (Sprint 5)."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import Middleware, RequestContext


class SessionUpdater(Middleware):
    """Update session state after response. Stub — passes all responses through."""

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        return None
