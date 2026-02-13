"""Webhook event dispatcher — fire-and-forget delivery to customer endpoints."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

import structlog

from proxy.middleware.url_validator import validate_origin_url
from proxy.store.webhooks import get_enabled_webhooks_for_event

logger = structlog.get_logger()

# Security events that trigger webhook dispatch.
# Must match event names in VALID_EVENTS (proxy/models/webhook.py)
# so customer subscriptions actually receive notifications.
SECURITY_EVENTS = frozenset({
    "waf_blocked",
    "rate_limited",
    "session_blocked",
    "login_attempt",
})

# Severity mapping for event types
_EVENT_SEVERITY: dict[str, str] = {
    "waf_blocked": "high",
    "rate_limited": "warning",
    "session_blocked": "high",
    "login_attempt": "info",
}

try:
    import httpx
except ImportError:
    httpx = None

_webhook_client = None


def _get_client():
    """Lazy-init a shared httpx client for webhook delivery."""
    global _webhook_client
    if httpx is None:
        return None
    if _webhook_client is None:
        _webhook_client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            verify=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _webhook_client


async def close_webhook_client() -> None:
    """Close the shared webhook httpx client."""
    global _webhook_client
    if _webhook_client is not None:
        await _webhook_client.aclose()
        _webhook_client = None


def _sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for a webhook payload."""
    return "sha256=" + hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


def _format_custom_payload(
    event_type: str,
    severity: str,
    message: str,
    timestamp: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Format payload for custom webhook provider."""
    return {
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "timestamp": timestamp,
        "context": context,
    }


def _sanitize_slack_text(text: str) -> str:
    """Sanitize text for Slack mrkdwn to prevent injection.

    Escapes:
    - @channel, @here, @everyone mentions (prevent notification spam)
    - <url> link syntax (prevent phishing links)
    - Slack special entities (& < >)
    """
    # Escape Slack HTML entities first
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Neutralize @-mentions by inserting zero-width space after @
    text = text.replace("@channel", "@\u200bchannel")
    text = text.replace("@here", "@\u200bhere")
    text = text.replace("@everyone", "@\u200beveryone")
    return text


def _format_slack_payload(
    event_type: str,
    severity: str,
    message: str,
    timestamp: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Format payload for Slack incoming webhook."""
    severity_emoji = {
        "high": "🚨",
        "warning": "⚠️",
        "info": "ℹ️",
    }.get(severity, "📋")

    safe_message = _sanitize_slack_text(message)
    context_lines = "\n".join(
        f"• *{k}*: {_sanitize_slack_text(str(v))}" for k, v in context.items() if v
    )

    text = f"{severity_emoji} *{event_type.upper()}*: {safe_message}"
    return {
        "text": text,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{text}\n\n{context_lines}\n_{timestamp}_",
                },
            },
        ],
    }


def _format_pagerduty_payload(
    event_type: str,
    severity: str,
    message: str,
    timestamp: str,
    context: dict[str, Any],
    routing_key: str,
) -> dict[str, Any]:
    """Format payload for PagerDuty Events API v2."""
    pd_severity = {
        "high": "critical",
        "warning": "warning",
        "info": "info",
    }.get(severity, "error")

    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": f"[ShieldAI] {event_type}: {message}",
            "severity": pd_severity,
            "source": "shieldai-proxy",
            "timestamp": timestamp,
            "custom_details": context,
        },
    }


def _validate_webhook_url(url: str) -> str | None:
    """Validate webhook URL against SSRF. Returns error message or None."""
    return validate_origin_url(url)


async def dispatch_webhook_event(
    *,
    customer_id: str,
    event_type: str,
    message: str,
    context: dict[str, Any],
) -> None:
    """Dispatch a security event to all matching webhooks for the customer.

    Fire-and-forget: catches all exceptions, never raises.
    """
    client = _get_client()
    if client is None:
        return

    severity = _EVENT_SEVERITY.get(event_type, "info")
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        webhooks = await get_enabled_webhooks_for_event(customer_id, event_type)
    except Exception:
        logger.exception("webhook_fetch_failed", customer_id=customer_id)
        return

    for wh in webhooks:
        try:
            url = wh["url"]

            # SSRF check on every dispatch (URL could have been modified)
            ssrf_error = _validate_webhook_url(url)
            if ssrf_error:
                logger.warning(
                    "webhook_ssrf_blocked",
                    webhook_id=str(wh["id"]),
                    reason=ssrf_error,
                )
                continue

            provider = wh.get("provider", "custom")
            secret = wh.get("secret", "")

            if provider == "slack":
                payload = _format_slack_payload(
                    event_type, severity, message, timestamp, context,
                )
            elif provider == "pagerduty":
                payload = _format_pagerduty_payload(
                    event_type, severity, message, timestamp, context,
                    routing_key=secret,
                )
            else:
                payload = _format_custom_payload(
                    event_type, severity, message, timestamp, context,
                )

            payload_bytes = json.dumps(payload, default=str).encode("utf-8")
            headers = {"Content-Type": "application/json"}

            # HMAC signature for custom and slack providers
            if secret and provider != "pagerduty":
                headers["X-ShieldAI-Signature"] = _sign_payload(payload_bytes, secret)

            await client.post(url, content=payload_bytes, headers=headers)

        except Exception:
            logger.exception(
                "webhook_dispatch_failed",
                webhook_id=str(wh.get("id", "")),
            )
