"""Ordered middleware chain framework."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import structlog
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger()


@dataclass
class RequestContext:
    """Mutable context passed through the middleware pipeline."""

    request_id: str = ""
    tenant_id: str = ""
    user_id: str = ""
    customer_config: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.request_id:
            self.request_id = uuid4().hex[:8]


class Middleware(abc.ABC):
    """Base class for middleware in the pipeline."""

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abc.abstractmethod
    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        """Process an incoming request.

        Return None to continue the pipeline, or a Response to short-circuit.
        """
        ...

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        """Process an outgoing response. Override if needed."""
        return response


class MiddlewarePipeline:
    """Ordered list of middleware. Executes request handlers forward, response handlers in reverse."""

    def __init__(self) -> None:
        self._middleware: list[Middleware] = []
        self._enabled: dict[str, bool] = {}

    def add(self, middleware: Middleware, enabled: bool = True) -> None:
        """Add a middleware to the end of the pipeline."""
        self._middleware.append(middleware)
        self._enabled[middleware.name] = enabled
        logger.info("middleware_registered", name=middleware.name, enabled=enabled)

    def set_enabled(self, name: str, enabled: bool) -> None:
        """Enable or disable a middleware by name."""
        if name in self._enabled:
            self._enabled[name] = enabled

    async def process_request(self, request: Request, context: RequestContext) -> Response | None:
        """Run request through all enabled middleware in order.

        Returns a Response if any middleware short-circuits, otherwise None.
        Individual middleware exceptions are caught so one broken middleware
        doesn't crash the entire pipeline.
        """
        for mw in self._middleware:
            if not self._enabled.get(mw.name, True):
                continue
            try:
                result = await mw.process_request(request, context)
            except Exception:
                logger.exception("middleware_request_error", middleware=mw.name)
                return Response(content="Internal proxy error", status_code=502)
            if isinstance(result, Response):
                logger.info("middleware_short_circuit", middleware=mw.name)
                return result
        return None

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        """Run response through all enabled middleware in reverse order.

        Individual middleware exceptions are caught so one broken middleware
        doesn't corrupt the response.
        """
        for mw in reversed(self._middleware):
            if not self._enabled.get(mw.name, True):
                continue
            try:
                response = await mw.process_response(response, context)
            except Exception:
                logger.exception("middleware_response_error", middleware=mw.name)
        return response
