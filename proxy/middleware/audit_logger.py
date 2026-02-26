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
from proxy.store.audit import batch_insert_audit_logs

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
_MAX_METHOD_LENGTH = 10
_MAX_APPID_LENGTH = 255
_MAX_REQUESTID_LENGTH = 64
_MAX_ACTION_LENGTH = 64
_MAX_COUNTRY_LENGTH = 8
_MAX_AUDIT_QUEUE_SIZE = 10_000
_MAX_PENDING_WEBHOOK_TASKS = 500
_FLUSH_INTERVAL = 0.5     # seconds between flushes
_FLUSH_BATCH_SIZE = 500   # max rows per flush
_MAX_FLUSH_RETRIES = 3    # max consecutive failures before dropping rows


def _sanitize(value: str, max_length: int) -> str:
    """Strip control chars and truncate."""
    return _CONTROL_CHARS.sub("", value)[:max_length]


class AuditLogger(Middleware):
    """Log every request/response to the audit_logs table.

    process_request: captures timing start and request metadata.
    process_response: computes duration, classifies action, queues row for batch insert.

    Uses an asyncio.Queue + background flush loop for batched inserts.
    Fail-open: errors are logged but never propagate.

    Also dispatches webhook events for security-related actions (waf_blocked,
    rate_limited, session_blocked) independent of the audit_logging feature flag.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=_MAX_AUDIT_QUEUE_SIZE)
        self._flush_task: asyncio.Task | None = None
        self._pending_webhooks: deque[asyncio.Task] = deque(maxlen=_MAX_PENDING_WEBHOOK_TASKS)
        self._shutdown = False
        self._consecutive_failures = 0
        self._entries_dropped: int = 0

    async def start(self) -> None:
        """Start the background flush loop."""
        self._shutdown = False
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Drain queue and stop flush loop."""
        self._shutdown = True
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final drain — loop until queue is fully empty (not just one batch)
        while not self._queue.empty():
            await self._flush_batch()
        # Cancel pending webhook tasks
        for t in self._pending_webhooks:
            if not t.done():
                t.cancel()

    async def _flush_loop(self) -> None:
        """Flush audit rows every 500ms."""
        while not self._shutdown:
            await asyncio.sleep(_FLUSH_INTERVAL)
            await self._flush_batch()

    async def _flush_batch(self) -> None:
        """Drain queue into a batch insert."""
        rows = []
        while not self._queue.empty() and len(rows) < _FLUSH_BATCH_SIZE:
            try:
                rows.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if rows:
            try:
                await batch_insert_audit_logs(rows)
                self._consecutive_failures = 0  # Reset on success
                if self._entries_dropped > 0:
                    self._entries_dropped = 0
            except Exception:
                self._consecutive_failures += 1
                logger.exception(
                    "audit_batch_flush_failed",
                    count=len(rows),
                    consecutive_failures=self._consecutive_failures,
                )
                # Re-queue rows only if under retry limit and not shutting down.
                # Without a retry limit, a persistent DB failure would cause an
                # infinite dequeue-fail-requeue loop (audit evasion via DoS).
                if not self._shutdown and self._consecutive_failures < _MAX_FLUSH_RETRIES:
                    requeued = 0
                    for row in rows:
                        try:
                            self._queue.put_nowait(row)
                            requeued += 1
                        except asyncio.QueueFull:
                            break
                    if requeued < len(rows):
                        logger.error(
                            "audit_rows_lost",
                            lost=len(rows) - requeued,
                            requeued=requeued,
                        )
                else:
                    # Max retries exceeded or shutting down — drop rows to
                    # prevent infinite retry loop.
                    logger.error(
                        "audit_rows_dropped_max_retries",
                        dropped=len(rows),
                        consecutive_failures=self._consecutive_failures,
                    )

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        # Check feature flag — but always capture metadata for webhooks
        features = context.customer_config.get("enabled_features", {})
        if not features.get("audit_logging", True):
            context.extra["_audit_skip"] = True

        # Always capture request metadata (needed for both audit and webhooks)
        context.extra["_audit_start"] = time.monotonic()
        context.extra["_audit_timestamp"] = datetime.now(timezone.utc)
        context.extra["_audit_method"] = getattr(request, "method", "WS")
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

        # Truncate all fields to their DB column limits to prevent INSERT
        # failure (which would silently drop the audit log entry — audit evasion).
        method = method[:_MAX_METHOD_LENGTH]
        path = path[:_MAX_PATH_LENGTH]
        app_id = context.customer_config.get("app_id", "")[:_MAX_APPID_LENGTH]
        request_id = (context.request_id or "")[:_MAX_REQUESTID_LENGTH]
        user_agent = context.extra.get("_audit_user_agent", "")
        country = _sanitize(context.extra.get("country", ""), _MAX_COUNTRY_LENGTH)
        user_id = (context.user_id or "")[:_MAX_USERID_LENGTH]
        action = action[:_MAX_ACTION_LENGTH]

        # Queue audit row for batch insert (only if audit logging is enabled)
        if not context.extra.get("_audit_skip"):
            row = (
                context.tenant_id,
                app_id,
                request_id,
                context.extra.get("_audit_timestamp", datetime.now(timezone.utc)),
                method,
                path,
                status_code,
                round(duration_ms, 2),
                client_ip,
                user_agent,
                country,
                user_id,
                action,
                is_blocked,
            )
            try:
                self._queue.put_nowait(row)
            except asyncio.QueueFull:
                self._entries_dropped += 1
                if self._entries_dropped == 1 or self._entries_dropped % 100 == 0:
                    logger.error(
                        "audit_queue_full",
                        total_dropped=self._entries_dropped,
                        queue_size=self._queue.maxsize,
                        tenant_id=context.tenant_id,
                        request_id=context.request_id,
                    )

        # Dispatch webhook for security events (independent of audit_logging flag).
        # Uses a SEPARATE bounded queue so slow webhooks cannot evict audit tasks.
        if action in SECURITY_EVENTS:
            try:
                wh_task = asyncio.create_task(
                    dispatch_webhook_event(
                        customer_id=context.customer_config.get("customer_id", ""),
                        event_type=action,
                        message=f"{action} on {method} {path} (status {status_code})",
                        context={
                            "tenant_id": context.tenant_id,
                            "app_id": app_id,
                            "request_id": request_id,
                            "client_ip": client_ip,
                            "path": path,
                            "method": method,
                            "status_code": status_code,
                        },
                    )
                )

                def _webhook_done(t: asyncio.Task) -> None:
                    if t.done() and not t.cancelled():
                        exc = t.exception()
                        if exc:
                            logger.error("webhook_task_exception", error=str(exc))

                wh_task.add_done_callback(_webhook_done)
                if len(self._pending_webhooks) >= _MAX_PENDING_WEBHOOK_TASKS:
                    logger.warning("webhook_task_queue_full", dropped=True)
                self._pending_webhooks.append(wh_task)
            except Exception:
                logger.exception("webhook_task_create_failed")

        return response
