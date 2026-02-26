"""Callback/webhook signature verification middleware.

Verifies HMAC-SHA256 signatures on incoming webhook callbacks from external
services (Stripe, GitHub, etc.) before forwarding to the customer's origin app.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import time
from uuid import uuid4

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxy.middleware.pipeline import Middleware, RequestContext

logger = structlog.get_logger()

# Defaults
_DEFAULT_SIGNATURE_HEADER = "x-signature"
_DEFAULT_TIMESTAMP_HEADER = "x-timestamp"
_DEFAULT_TIMESTAMP_TOLERANCE = 300  # 5 minutes
_MAX_TIMESTAMP_TOLERANCE = 3600  # 1 hour — cap to limit replay window


class CallbackVerifier(Middleware):
    """Verify HMAC-SHA256 signatures on incoming callback/webhook requests.

    Customers configure which endpoints require signature verification and
    the shared secrets used. Supports secret rotation via a list of secrets.
    Fail-closed: missing or invalid signatures result in 401.
    """

    async def process_request(
        self, request: Request, context: RequestContext
    ) -> Request | Response | None:
        # Skip WebSocket upgrade requests (no body to verify)
        if context.extra.get("is_websocket"):
            return None

        # Check feature flag (default False — opt-in)
        features = context.customer_config.get("enabled_features", {})
        if not features.get("callback_verifier", False):
            return None

        # Load callback_verifier settings
        customer_settings = context.customer_config.get("settings", {})
        cb_cfg = customer_settings.get("callback_verifier", {})

        endpoints: list[dict] = cb_cfg.get("endpoints", [])
        if not endpoints:
            return None

        # Match request path against endpoint patterns (first match wins)
        path = request.url.path
        matched_endpoint = None
        for ep in endpoints:
            pattern = ep.get("pattern", "")
            if fnmatch.fnmatch(path, pattern):
                matched_endpoint = ep
                break

        if matched_endpoint is None:
            return None

        # Resolve per-endpoint config
        sig_header = matched_endpoint.get(
            "signature_header", _DEFAULT_SIGNATURE_HEADER
        ).lower()
        ts_header = matched_endpoint.get(
            "timestamp_header", _DEFAULT_TIMESTAMP_HEADER
        ).lower()
        tolerance = cb_cfg.get("timestamp_tolerance", _DEFAULT_TIMESTAMP_TOLERANCE)
        # Clamp tolerance to prevent absurd replay windows
        if not isinstance(tolerance, (int, float)) or tolerance < 0:
            tolerance = _DEFAULT_TIMESTAMP_TOLERANCE
        tolerance = min(int(tolerance), _MAX_TIMESTAMP_TOLERANCE)
        mode = cb_cfg.get("mode", "block")

        # Normalize secrets: support both "secret" (single) and "secrets" (list)
        secrets = matched_endpoint.get("secrets", [])
        single_secret = matched_endpoint.get("secret")
        if single_secret and not secrets:
            secrets = [single_secret]
        # Filter empty/whitespace-only secrets — empty key is a forgeable HMAC
        secrets = [s for s in secrets if isinstance(s, str) and s.strip()]
        if not secrets:
            logger.warning(
                "callback_no_valid_secrets",
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                path=path,
                pattern=matched_endpoint.get("pattern"),
            )
            return self._reject(
                "callback_signature_invalid",
                "No valid secrets configured",
                mode,
                context,
                path=path,
            )

        # Extract signature header — fail-closed on missing
        signature = request.headers.get(sig_header)
        if not signature:
            return self._reject(
                "callback_signature_missing",
                "Missing signature header",
                mode,
                context,
                path=path,
            )

        # Extract timestamp header — fail-closed on missing
        ts_raw = request.headers.get(ts_header)
        if not ts_raw:
            return self._reject(
                "callback_timestamp_missing",
                "Missing timestamp header",
                mode,
                context,
                path=path,
            )

        # Parse timestamp — fail-closed on non-numeric
        try:
            ts_value = int(ts_raw)
        except (ValueError, OverflowError):
            return self._reject(
                "callback_timestamp_invalid",
                "Invalid timestamp",
                mode,
                context,
                path=path,
            )

        # Validate timestamp freshness
        now = int(time.time())
        if abs(now - ts_value) > tolerance:
            return self._reject(
                "callback_timestamp_expired",
                "Timestamp outside tolerance",
                mode,
                context,
                path=path,
                delta=abs(now - ts_value),
                tolerance=tolerance,
            )

        # Read request body (Starlette caches, safe for later middleware)
        body = await request.body()

        # Try each secret (supports rotation) — iterate ALL for constant-time
        signing_input = f"{ts_value}.".encode() + body
        matched = False
        for secret in secrets:
            expected = "sha256=" + hmac.new(
                secret.encode("utf-8"),
                signing_input,
                hashlib.sha256,
            ).hexdigest()
            if hmac.compare_digest(expected, signature):
                matched = True
            # Do NOT break — iterate all secrets for constant-time behavior

        if matched:
            logger.info(
                "callback_signature_valid",
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                path=path,
            )
            return None  # Valid — continue pipeline

        # No secret matched
        return self._reject(
            "callback_signature_invalid",
            "Invalid signature",
            mode,
            context,
            path=path,
        )

    @staticmethod
    def _reject(
        event: str,
        message: str,
        mode: str,
        context: RequestContext,
        **log_extra,
    ) -> Response | None:
        """Log rejection and return 401 (block) or None (detect_only)."""
        error_id = uuid4().hex[:8]
        logger.warning(
            event,
            error_id=error_id,
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            mode=mode,
            **log_extra,
        )
        if mode == "detect_only":
            return None
        return JSONResponse(
            status_code=401,
            content={
                "error": True,
                "message": "Callback signature verification failed.",
                "error_id": error_id,
            },
        )
