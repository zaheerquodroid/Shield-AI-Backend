"""WebSocket reverse proxy handler with security middleware integration.

Phase 1 (handshake): Runs the existing middleware pipeline on the upgrade
request — tenant routing, rate limiting, session validation, audit logging
all apply identically to regular HTTP.

Phase 2 (frame relay): Bidirectionally relays WebSocket frames between the
client and upstream.  For security-critical paths (e.g. /ws/conversations/),
client→upstream text frames are scanned for prompt injection using the
existing LLM sanitizer patterns.
"""

from __future__ import annotations

import asyncio
import json
import fnmatch

import structlog
import websockets
from starlette.websockets import WebSocket, WebSocketDisconnect

from proxy.config.loader import get_settings
from proxy.middleware.llm_sanitizer import detect_injection, sanitize_text
from proxy.middleware.pipeline import MiddlewarePipeline, RequestContext

logger = structlog.get_logger()


async def websocket_proxy(
    ws: WebSocket,
    path: str,
    pipeline: MiddlewarePipeline,
) -> None:
    """Handle a WebSocket connection through the security pipeline."""

    settings = get_settings()
    context = RequestContext()

    # Mark as WebSocket so body-reading middleware skips gracefully
    context.extra["is_websocket"] = True

    # ── Phase 1: Handshake security ──────────────────────────
    # Starlette's WebSocket inherits from HTTPConnection — it exposes
    # .headers, .url, .client, .cookies, .query_params so most middleware
    # works unmodified.

    short_circuit = await pipeline.process_request(ws, context)
    if short_circuit is not None:
        # Middleware rejected — map HTTP status to WebSocket close code.
        # 4000-4999 = application-defined close codes per RFC 6455.
        status = short_circuit.status_code
        if status == 429:
            code, reason = 4029, "Rate limit exceeded"
        elif status in (401, 403):
            code, reason = 4001, "Authentication required"
        else:
            code, reason = 4000 + (status % 1000), "Request blocked"

        # Accept first so we can send a close frame with reason
        await ws.accept()
        await ws.close(code=code, reason=reason)

        # Still run response pipeline for audit logging
        await pipeline.process_response(short_circuit, context)
        return

    # ── Determine upstream URL ───────────────────────────────
    upstream_base = context.customer_config.get("origin_url", settings.upstream_url)
    # Convert http(s) → ws(s)
    ws_upstream = upstream_base.replace("https://", "wss://").replace("http://", "ws://")
    upstream_url = f"{ws_upstream.rstrip('/')}/{path}"

    query = ws.scope.get("query_string", b"").decode()
    if query:
        upstream_url = f"{upstream_url}?{query}"

    # ── Build upstream headers ───────────────────────────────
    # Forward cookies (session auth) and relevant headers.
    # Skip headers that the websockets library manages itself.
    _skip_headers = frozenset({
        "host", "connection", "upgrade",
        "sec-websocket-key", "sec-websocket-version",
        "sec-websocket-extensions", "sec-websocket-protocol",
    })
    extra_headers = {}
    for key, value in ws.headers.items():
        if key.lower() not in _skip_headers:
            extra_headers[key] = value

    # Inject context headers
    if context.request_id:
        extra_headers["x-request-id"] = context.request_id
    if context.tenant_id:
        extra_headers["x-tenant-id"] = context.tenant_id
    if context.user_id:
        extra_headers["x-user-id"] = context.user_id

    # ── Phase 2: Accept client & connect upstream ────────────
    await ws.accept()

    logger.info(
        "ws_proxy_connected",
        path=path,
        request_id=context.request_id,
        tenant_id=context.tenant_id,
    )

    try:
        async with websockets.connect(
            upstream_url,
            additional_headers=extra_headers,
            max_size=settings.ws_max_message_size,
            ping_interval=settings.ws_ping_interval,
            ping_timeout=settings.ws_ping_timeout,
            open_timeout=settings.ws_timeout,
        ) as upstream_ws:
            # Determine if this path needs message-level sanitization
            sanitize = _should_sanitize(path, context)

            # Bidirectional relay — when either coroutine finishes (disconnect
            # or error), cancel the other via return_exceptions + task group.
            client_task = asyncio.create_task(
                _relay_client_to_upstream(ws, upstream_ws, context, sanitize)
            )
            upstream_task = asyncio.create_task(
                _relay_upstream_to_client(ws, upstream_ws, context)
            )

            # Wait for either side to finish
            done, pending = await asyncio.wait(
                [client_task, upstream_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Cancel the other side
            for task in pending:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    except websockets.exceptions.InvalidStatus as exc:
        logger.error(
            "ws_upstream_rejected",
            path=path,
            status=exc.response.status_code,
            request_id=context.request_id,
        )
        try:
            await ws.close(code=4502, reason="Upstream rejected connection")
        except Exception:
            pass
    except (ConnectionRefusedError, OSError) as exc:
        logger.error(
            "ws_upstream_unreachable",
            path=path,
            error=str(exc),
            request_id=context.request_id,
        )
        try:
            await ws.close(code=4502, reason="Upstream unreachable")
        except Exception:
            pass
    except WebSocketDisconnect:
        pass  # Client disconnected normally
    except Exception:
        logger.exception("ws_proxy_error", path=path, request_id=context.request_id)
        try:
            await ws.close(code=4500, reason="Internal proxy error")
        except Exception:
            pass

    logger.info(
        "ws_proxy_disconnected",
        path=path,
        request_id=context.request_id,
    )


def _should_sanitize(path: str, context: RequestContext) -> bool:
    """Check if this WebSocket path requires message-level LLM sanitization."""
    settings = get_settings()

    # Check customer-specific config first, fall back to global setting
    customer_settings = context.customer_config.get("settings", {})
    llm_cfg = customer_settings.get("llm", {})
    ws_paths = llm_cfg.get("ws_sanitize_paths", settings.ws_sanitize_paths)

    normalized = f"/{path}" if not path.startswith("/") else path
    for pattern in ws_paths:
        if fnmatch.fnmatch(normalized, pattern):
            return True
    return False


async def _relay_client_to_upstream(
    client_ws: WebSocket,
    upstream_ws: websockets.ClientConnection,
    context: RequestContext,
    sanitize: bool,
) -> None:
    """Relay frames from client to upstream, optionally scanning for injection."""
    try:
        while True:
            data = await client_ws.receive()
            msg_type = data.get("type", "")

            if msg_type == "websocket.disconnect":
                await upstream_ws.close()
                return

            text = data.get("text")
            bytes_data = data.get("bytes")

            if text is not None:
                if sanitize:
                    result = _sanitize_ws_message(text, context)
                    if result is None:
                        # Message blocked — notify client, don't forward
                        await client_ws.send_json({
                            "type": "error",
                            "message": "Message contains potentially unsafe content.",
                        })
                        continue
                    text = result
                await upstream_ws.send(text)
            elif bytes_data is not None:
                await upstream_ws.send(bytes_data)
    except WebSocketDisconnect:
        try:
            await upstream_ws.close()
        except Exception:
            pass
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("ws_client_relay_error", request_id=context.request_id)
        try:
            await upstream_ws.close()
        except Exception:
            pass


async def _relay_upstream_to_client(
    client_ws: WebSocket,
    upstream_ws: websockets.ClientConnection,
    context: RequestContext,
) -> None:
    """Relay frames from upstream to client (passthrough — no sanitization)."""
    try:
        async for message in upstream_ws:
            if isinstance(message, str):
                await client_ws.send_text(message)
            elif isinstance(message, bytes):
                await client_ws.send_bytes(message)
    except websockets.exceptions.ConnectionClosed:
        try:
            await client_ws.close()
        except Exception:
            pass
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("ws_upstream_relay_error", request_id=context.request_id)
        try:
            await client_ws.close()
        except Exception:
            pass


def _sanitize_ws_message(text: str, context: RequestContext) -> str | None:
    """Scan a WebSocket text frame for prompt injection.

    Returns the (possibly sanitized) text, or None if the message should be
    blocked.  Only scans the ``question`` field in ``send_message`` actions —
    other actions (subscribe, unsubscribe, create_conversation) pass through.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return text  # Not JSON — pass through

    if not isinstance(data, dict):
        return text

    action = data.get("action") or data.get("type")

    # Only scan messages that contain user text destined for LLM
    if action != "send_message":
        return text

    question = data.get("question", "")
    if not question:
        return text

    # Get mode from customer config
    customer_settings = context.customer_config.get("settings", {})
    llm_cfg = customer_settings.get("llm", {})
    mode = llm_cfg.get("mode", "sanitize")

    # Detect injection
    detections = detect_injection(question)

    if detections:
        logger.warning(
            "ws_injection_detected",
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            action=action,
            patterns=detections,
            mode=mode,
        )

        if mode == "block":
            return None  # Drop the message

    if mode == "detect_only":
        return text

    # mode == "sanitize": sanitize the question field
    data["question"] = sanitize_text(question)
    return json.dumps(data)
