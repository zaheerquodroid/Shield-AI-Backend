"""Session validator middleware — enforces idle and absolute session timeouts."""

from __future__ import annotations

import hmac
import time

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxy.config.loader import get_settings
from proxy.middleware.pipeline import Middleware, RequestContext
from proxy.store.session import compute_fingerprint, delete_session, load_session, update_activity

logger = structlog.get_logger()


class SessionValidator(Middleware):
    """Validate proxy-managed session tokens on each request.

    - Extracts session token from cookie (configurable name, default ``shield_session``)
    - Loads session from Redis
    - Checks idle timeout (last_activity + threshold)
    - Checks absolute timeout (created_at + threshold)
    - Optionally validates session binding (IP + User-Agent fingerprint)
    - Updates last_activity on successful validation
    - Returns 401 if session is invalid or expired
    - Passes through if no session cookie is present (app handles its own auth)
    - Graceful degradation if Redis is unavailable
    """

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        # Check feature flag
        features = context.customer_config.get("enabled_features", {})
        if not features.get("session_validation", True):
            return None

        settings = get_settings()
        cookie_name = self._get_cookie_name(context, settings)

        # Extract session token from cookie
        token = request.cookies.get(cookie_name)
        if not token:
            # No session cookie — pass through (app handles its own auth)
            return None

        # Load session from Redis
        session = await load_session(token)
        if session is None:
            # Session not found — expired or invalid token
            logger.warning(
                "session_not_found",
                request_id=context.request_id,
                tenant_id=context.tenant_id,
            )
            return self._unauthorized("Session expired or invalid.")

        now = int(time.time())

        # Check absolute timeout
        absolute_timeout = self._get_absolute_timeout(context, settings)
        created_at = int(session.get("created_at", "0"))
        if now - created_at > absolute_timeout:
            logger.warning(
                "session_absolute_timeout",
                request_id=context.request_id,
                tenant_id=session.get("tenant_id"),
                user_id=session.get("user_id"),
                age_seconds=now - created_at,
                threshold=absolute_timeout,
            )
            # Actively delete expired session from Redis
            try:
                await delete_session(token)
            except Exception:
                logger.error("session_delete_failed", token_prefix=token[:8])
            return self._unauthorized("Session expired. Please log in again.")

        # Check idle timeout
        idle_timeout = self._get_idle_timeout(context, settings)
        last_activity = int(session.get("last_activity", "0"))
        if now - last_activity > idle_timeout:
            logger.warning(
                "session_idle_timeout",
                request_id=context.request_id,
                tenant_id=session.get("tenant_id"),
                user_id=session.get("user_id"),
                idle_seconds=now - last_activity,
                threshold=idle_timeout,
            )
            # Actively delete expired session from Redis
            try:
                await delete_session(token)
            except Exception:
                logger.error("session_delete_failed", token_prefix=token[:8])
            return self._unauthorized("Session timed out due to inactivity.")

        # Check session binding (fingerprint)
        binding_mode = self._get_binding_mode(context, settings)
        if binding_mode != "off":
            client_ip = request.client.host if request.client else "unknown"
            client_ua = request.headers.get("user-agent", "")
            current_fp = compute_fingerprint(client_ip, client_ua)
            stored_fp = session.get("fingerprint", "")

            if not hmac.compare_digest(current_fp.encode(), stored_fp.encode()):
                logger.warning(
                    "session_binding_mismatch",
                    request_id=context.request_id,
                    tenant_id=session.get("tenant_id"),
                    user_id=session.get("user_id"),
                    stored_ip=session.get("ip"),
                    current_ip=client_ip,
                    binding_mode=binding_mode,
                )
                if binding_mode == "strict":
                    return self._unauthorized("Session security violation. Please log in again.")
                # "warn" mode: log but allow

        # Session is valid — populate context
        context.user_id = session.get("user_id", "")
        context.extra["session_token"] = token
        context.extra["session_tenant_id"] = session.get("tenant_id", "")

        # Update last_activity
        await update_activity(token)

        return None

    def _unauthorized(self, message: str) -> JSONResponse:
        """Build a 401 JSON response."""
        return JSONResponse(
            status_code=401,
            content={"error": True, "message": message},
        )

    def _get_cookie_name(self, context: RequestContext, settings) -> str:
        """Get session cookie name from customer config or global setting."""
        customer_settings = context.customer_config.get("settings", {})
        return customer_settings.get("session_cookie_name", settings.session_cookie_name)

    def _get_idle_timeout(self, context: RequestContext, settings) -> int:
        """Get idle timeout from customer config or global setting."""
        customer_settings = context.customer_config.get("settings", {})
        session_cfg = customer_settings.get("session", {})
        return int(session_cfg.get("idle_timeout", settings.session_idle_timeout))

    def _get_absolute_timeout(self, context: RequestContext, settings) -> int:
        """Get absolute timeout from customer config or global setting."""
        customer_settings = context.customer_config.get("settings", {})
        session_cfg = customer_settings.get("session", {})
        return int(session_cfg.get("absolute_timeout", settings.session_absolute_timeout))

    def _get_binding_mode(self, context: RequestContext, settings) -> str:
        """Get session binding mode from customer config or global setting."""
        customer_settings = context.customer_config.get("settings", {})
        session_cfg = customer_settings.get("session", {})
        mode = session_cfg.get("binding_mode", settings.session_binding_mode)
        if mode in ("off", "warn", "strict"):
            return mode
        return settings.session_binding_mode
