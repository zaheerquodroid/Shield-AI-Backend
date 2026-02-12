"""Tenant router middleware — routes by Host header to customer config."""

from __future__ import annotations

import structlog
from starlette.requests import Request
from starlette.responses import Response

from proxy.config.customer_config import get_config_service
from proxy.middleware.pipeline import Middleware, RequestContext

logger = structlog.get_logger()


class TenantRouter(Middleware):
    """Extract Host header, look up customer config, attach to context."""

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        host = request.headers.get("host", "")
        # Strip port if present
        domain = host.split(":")[0] if host else ""

        config_service = get_config_service()
        config = config_service.get_config(domain)

        context.customer_config = config

        # Set tenant info from config if available
        if "customer_id" in config:
            context.tenant_id = config["customer_id"]

        if domain and domain not in ("localhost", "127.0.0.1") and "customer_id" not in config:
            logger.warning("unknown_domain", domain=domain)

        return None
