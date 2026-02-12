"""Audit logger middleware — STUB: pass-through (Sprint 6)."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import Middleware, RequestContext


class AuditLogger(Middleware):
    """Log requests and responses for audit. Stub — passes all through."""

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        return None
