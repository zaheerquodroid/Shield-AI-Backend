"""Audit logger middleware — logs every request/response with structured metadata."""

from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from datetime import datetime, timezone

import structlog
from starlette.requests import Request
from starlette.responses import Response

from proxy.config.audit_actions import classify_action
from proxy.config.webhook import SECURITY_EVENTS, dispatch_webhook_event
from proxy.middleware.pipeline import Middleware, RequestContext
from proxy.store.audit import insert_audit_log

logger = structlog.get_logger()

# Strip control characters from paths and user-agents.
# Covers: C0 controls (\x00-\x1f), DEL (\x7f), C1 controls (\x80-\x9f),
# Unicode line/paragraph separators (\u2028-\u2029),
# bidi overrides (\u200b-\u200f, \u202a-\u202e, \u2066-\u2069),
# zero-width no-break space / BOM (\ufeff).
_CONTROL_CHARS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)

_MAX_UA_LENGTH = 1024
_MAX_PATH_LENGTH = 2048
_MAX_IP_LENGTH = 45       # IPv6 max = 45 chars
_MAX_USERID_LENGTH = 255
_MAX_PENDING_TASKS = 1000


def _sanitize(value: str, max_length: int) -> str:
    """Strip control chars and truncate."""
    return _CONTROL_CHARS.sub("", value)[:max_length]


class AuditLogger(Middleware):
    """Log every request/response to the audit_logs table.

    process_request: captures timing start and request metadata.
    process_response: computes duration, classifies action, fires async insert.

    Fail-open: errors are logged but never propagate.
    Bounded task queue: max 1000 pending inserts to prevent memory growth.

    Also dispatches webhook events for security-related actions (waf_blocked,
    rate_limited, session_blocked) independent of the audit_logging feature flag.
    """

    def __init__(self) -> None:
        self._pending: deque[asyncio.Task] = deque(maxlen=_MAX_PENDING_TASKS)

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        # Check feature flag — but always capture metadata for webhooks
        features = context.customer_config.get("enabled_features", {})
        if not features.get("audit_logging", True):
            context.extra["_audit_skip"] = True

        # Always capture request metadata (needed for both audit and webhooks)
        context.extra["_audit_start"] = time.monotonic()
        context.extra["_audit_method"] = request.method
        context.extra["_audit_path"] = _sanitize(
            request.url.path, _MAX_PATH_LENGTH
        )
        # Capture direct client IP and raw XFF for process_response.
        # ContextInjector (position 2) will set x_forwarded_for with the
        # full chain.  process_response picks the best IP available.
        context.extra["_audit_direct_ip"] = (
            request.client.host if request.client else ""
        )
        context.extra["_audit_user_agent"] = _sanitize(
            request.headers.get("user-agent", ""), _MAX_UA_LENGTH
        )
        return None

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        start = context.extra.get("_audit_start")
        if start is None:
            return response

        # Skip both audit and webhooks for requests with no resolved tenant
        if not context.tenant_id:
            return response

        duration_ms = (time.monotonic() - start) * 1000
        method = context.extra.get("_audit_method", "")
        path = context.extra.get("_audit_path", "")
        status_code = response.status_code

        action, is_blocked = classify_action(
            method=method,
            path=path,
            status_code=status_code,
            blocked=False,
            context_extra=context.extra,
        )

        # Always use direct TCP peer IP for audit logging.
        # X-Forwarded-For is entirely attacker-controlled and MUST NOT be
        # trusted without explicit trusted-proxy configuration.  An attacker
        # can spoof XFF to:
        #   1. Forge their IP in audit logs
        #   2. Overflow client_ip VARCHAR(45) to cause INSERT failure,
        #      silently evading audit logging
        # The direct peer IP cannot be spoofed at the TCP level.
        client_ip = context.extra.get("_audit_direct_ip", "")[:45]

        # Fire audit insert (only if audit logging is enabled)
        if not context.extra.get("_audit_skip"):
            try:
                task = asyncio.create_task(
                    insert_audit_log(
                        tenant_id=context.tenant_id,
                        app_id=context.customer_config.get("app_id", ""),
                        request_id=context.request_id,
                        timestamp=datetime.now(timezone.utc),
                        method=method,
                        path=path,
                        status_code=status_code,
                        duration_ms=round(duration_ms, 2),
                        client_ip=client_ip,
                        user_agent=context.extra.get("_audit_user_agent", ""),
                        country=context.extra.get("country", "")[:8],
                        user_id=(context.user_id or "")[:_MAX_USERID_LENGTH],
                        action=action,
                        blocked=is_blocked,
                    )
                )
                # Add done callback to suppress "exception never retrieved"
                # warnings if task is evicted from the bounded deque.
                task.add_done_callback(lambda t: t.exception() if t.done() and not t.cancelled() else None)
                if len(self._pending) >= _MAX_PENDING_TASKS:
                    logger.warning("audit_task_queue_full", dropped=True)
                self._pending.append(task)
            except Exception:
                logger.exception("audit_task_create_failed")

        # Dispatch webhook for security events (independent of audit_logging flag)
        if action in SECURITY_EVENTS:
            try:
                wh_task = asyncio.create_task(
                    dispatch_webhook_event(
                        customer_id=context.customer_config.get("customer_id", ""),
                        event_type=action,
                        message=f"{action} on {method} {path} (status {status_code})",
                        context={
                            "tenant_id": context.tenant_id,
                            "app_id": context.customer_config.get("app_id", ""),
                            "request_id": context.request_id,
                            "client_ip": client_ip,
                            "path": path,
                            "method": method,
                            "status_code": status_code,
                        },
                    )
                )
                wh_task.add_done_callback(lambda t: t.exception() if t.done() and not t.cancelled() else None)
                self._pending.append(wh_task)
            except Exception:
                logger.exception("webhook_task_create_failed")

        return response
