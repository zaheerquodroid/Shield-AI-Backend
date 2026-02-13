"""Session updater middleware — manages session lifecycle (create/delete)."""

from __future__ import annotations

import fnmatch

import structlog
from starlette.requests import Request
from starlette.responses import Response

from proxy.config.loader import get_settings
from proxy.middleware.pipeline import Middleware, RequestContext
from proxy.store.session import create_session, delete_session, generate_token

logger = structlog.get_logger()


class SessionUpdater(Middleware):
    """Detect login/logout from upstream responses and manage session lifecycle.

    This middleware runs in the *response* phase (reverse pipeline order)
    so it sees the upstream response after the app has processed the request.

    Login detection:
      - Request path matches a configured login pattern (default: ``/login``, ``/auth/login``)
      - Request method is POST
      - Upstream response status is 2xx

    Logout detection:
      - Request path matches a configured logout pattern (default: ``/logout``, ``/auth/logout``)
      - OR session token is present and upstream response indicates logout

    On login: creates a Redis session and sets a ``shield_session`` cookie.
    On logout: deletes the Redis session and clears the cookie.
    """

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        # Store request info for use in process_response
        context.extra["path"] = request.url.path
        context.extra["method"] = request.method.upper()
        context.extra["client_ip"] = request.client.host if request.client else "unknown"
        context.extra["client_ua"] = request.headers.get("user-agent", "")
        return None

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        # Check feature flag
        features = context.customer_config.get("enabled_features", {})
        if not features.get("session_validation", True):
            return response

        settings = get_settings()
        path = context.extra.get("path", "")
        method = context.extra.get("method", "")

        # Get customer-specific patterns or defaults
        customer_settings = context.customer_config.get("settings", {})
        session_cfg = customer_settings.get("session", {})

        login_patterns = session_cfg.get("login_paths", ["/login", "/auth/login", "/api/login"])
        logout_patterns = session_cfg.get("logout_paths", ["/logout", "/auth/logout", "/api/logout"])

        # Check for login response
        if method == "POST" and self._matches_patterns(path, login_patterns):
            if 200 <= response.status_code < 300:
                response = await self._handle_login(response, context, settings, session_cfg)

        # Check for logout response — POST only to prevent CSRF via GET (e.g. <img src="/logout">)
        elif method == "POST" and self._matches_patterns(path, logout_patterns):
            response = await self._handle_logout(response, context, settings)

        return response

    async def _handle_login(
        self,
        response: Response,
        context: RequestContext,
        settings,
        session_cfg: dict,
    ) -> Response:
        """Create a session and set the cookie on successful login."""
        token = generate_token()
        tenant_id = context.tenant_id or "unknown"
        # Try to extract user_id from context (set by TenantRouter or upstream headers)
        user_id = context.user_id or "unknown"
        ip = context.extra.get("client_ip", "unknown")
        ua = context.extra.get("client_ua", "")

        idle_timeout = int(session_cfg.get("idle_timeout", settings.session_idle_timeout))
        absolute_timeout = int(session_cfg.get("absolute_timeout", settings.session_absolute_timeout))

        session_data = await create_session(
            token,
            tenant_id=tenant_id,
            user_id=user_id,
            ip=ip,
            user_agent=ua,
            idle_timeout=idle_timeout,
            absolute_timeout=absolute_timeout,
        )

        if session_data is None:
            logger.warning("session_create_failed", request_id=context.request_id)
            return response

        cookie_name = settings.session_cookie_name
        # Set secure cookie on response
        # We need to build a new response with the Set-Cookie header
        response.set_cookie(
            key=cookie_name,
            value=token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=absolute_timeout,
            path="/",
        )

        logger.info(
            "session_login_detected",
            request_id=context.request_id,
            tenant_id=tenant_id,
            user_id=user_id,
            path=context.extra.get("path"),
        )

        return response

    async def _handle_logout(
        self,
        response: Response,
        context: RequestContext,
        settings,
    ) -> Response:
        """Delete the session and clear the cookie on logout."""
        token = context.extra.get("session_token")
        if token:
            await delete_session(token)

        cookie_name = settings.session_cookie_name
        response.delete_cookie(
            key=cookie_name,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )

        logger.info(
            "session_logout_detected",
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            path=context.extra.get("path"),
        )

        return response

    def _matches_patterns(self, path: str, patterns: list[str]) -> bool:
        """Check if path matches any of the configured patterns.

        Supports exact match and glob patterns (e.g., ``/api/*/login``).
        """
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
