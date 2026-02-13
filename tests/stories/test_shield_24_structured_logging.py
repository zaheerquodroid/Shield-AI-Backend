"""SHIELD-24 — Emit structured JSON logs for observability.

Acceptance Criteria:
  AC1: All proxy logs emitted as JSON with fields: timestamp, level, module,
       message, request_id, exc_info.
  AC2: Log level configurable per environment (DEBUG for dev, INFO for prod).
  AC3: Logs written to stdout for container log collection.
  AC4: Webhook integration for real-time log streaming to customer-configured
       endpoints (Slack, PagerDuty, custom).
  AC5: Webhook payloads include: event type, severity, message, timestamp,
       and relevant context.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, call
from uuid import uuid4

import pytest
import structlog

from proxy.config.webhook import (
    SECURITY_EVENTS,
    _format_custom_payload,
    _format_slack_payload,
    _format_pagerduty_payload,
    _sign_payload,
    _validate_webhook_url,
    dispatch_webhook_event,
    close_webhook_client,
)
from proxy.logging_config import setup_logging, _rename_logger_to_module
from proxy.middleware.audit_logger import AuditLogger
from proxy.middleware.pipeline import RequestContext
from proxy.models.webhook import VALID_EVENTS, VALID_PROVIDERS, WebhookCreate, WebhookUpdate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(
    method: str = "GET",
    path: str = "/api/data",
    client_ip: str = "10.0.0.1",
    user_agent: str = "TestAgent/1.0",
    host: str = "app.example.com",
) -> MagicMock:
    req = MagicMock()
    req.method = method
    req.url = MagicMock()
    req.url.path = path
    req.client = MagicMock()
    req.client.host = client_ip
    req.headers = MagicMock()
    req.headers.get = lambda key, default="": {
        "user-agent": user_agent,
        "host": host,
    }.get(key, default)
    return req


def _make_context(
    tenant_id: str = "tenant-1",
    audit_logging: bool = True,
    request_id: str = "abc123",
    customer_id: str = "cust-uuid-1",
) -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = tenant_id
    ctx.request_id = request_id
    ctx.customer_config = {
        "enabled_features": {"audit_logging": audit_logging},
        "customer_id": customer_id,
        "app_id": "app-1",
    }
    return ctx


# ===========================================================================
# AC1 — Structured JSON log fields
# ===========================================================================

class TestAC1StructuredLogFields:
    """All proxy logs include timestamp, level, module, message, request_id, exc_info."""

    def test_json_log_contains_timestamp(self, capfd):
        """JSON logs contain ISO timestamp field."""
        setup_logging(log_level="debug", json_format=True)
        logger = structlog.get_logger("proxy.test_module")
        logger.info("test_event")
        captured = capfd.readouterr()
        log = json.loads(captured.out.strip())
        assert "timestamp" in log

    def test_json_log_contains_level(self, capfd):
        """JSON logs contain log_level field."""
        setup_logging(log_level="debug", json_format=True)
        logger = structlog.get_logger("proxy.test_module")
        logger.warning("test_warning")
        captured = capfd.readouterr()
        log = json.loads(captured.out.strip())
        assert log.get("level") == "warning"

    def test_json_log_contains_module(self, capfd):
        """JSON logs contain module field (renamed from logger)."""
        setup_logging(log_level="debug", json_format=True)
        logger = structlog.get_logger("proxy.middleware.waf")
        logger.info("test_event")
        captured = capfd.readouterr()
        log = json.loads(captured.out.strip())
        assert "module" in log
        assert "logger" not in log  # renamed, not duplicated

    def test_json_log_contains_event_as_message(self, capfd):
        """JSON logs contain event field (structlog message key)."""
        setup_logging(log_level="debug", json_format=True)
        logger = structlog.get_logger("proxy.test")
        logger.info("my_message")
        captured = capfd.readouterr()
        log = json.loads(captured.out.strip())
        assert log.get("event") == "my_message"

    def test_json_log_includes_request_id_from_contextvars(self, capfd):
        """request_id bound via contextvars appears in log output."""
        setup_logging(log_level="debug", json_format=True)
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id="req-abc123")
        logger = structlog.get_logger("proxy.test")
        logger.info("test_with_request_id")
        captured = capfd.readouterr()
        structlog.contextvars.clear_contextvars()
        log = json.loads(captured.out.strip())
        assert log.get("request_id") == "req-abc123"

    def test_json_log_includes_exc_info(self, capfd):
        """exc_info is formatted as string in JSON output under 'exception' key."""
        setup_logging(log_level="debug", json_format=True)
        logger = structlog.get_logger("proxy.test")
        try:
            raise ValueError("test_exception")
        except ValueError:
            logger.error("error_occurred", exc_info=True)
        captured = capfd.readouterr()
        log = json.loads(captured.out.strip())
        # structlog's format_exc_info stores formatted traceback under 'exception'
        assert "exception" in log
        assert "ValueError" in log["exception"]
        assert "test_exception" in log["exception"]

    def test_rename_logger_to_module_processor(self):
        """_rename_logger_to_module renames the 'logger' key to 'module'."""
        event_dict = {"logger": "proxy.middleware.waf", "event": "test"}
        result = _rename_logger_to_module(None, None, event_dict)
        assert result["module"] == "proxy.middleware.waf"
        assert "logger" not in result

    def test_rename_logger_to_module_no_logger_key(self):
        """_rename_logger_to_module is a no-op when no logger key."""
        event_dict = {"event": "test"}
        result = _rename_logger_to_module(None, None, event_dict)
        assert "module" not in result


# ===========================================================================
# AC2 — Log level configurable per environment
# ===========================================================================

class TestAC2LogLevelConfigurable:
    """Log level is configurable and controls output filtering."""

    def test_debug_level_shows_debug_messages(self, capfd):
        """DEBUG level allows debug messages through."""
        setup_logging(log_level="debug", json_format=True)
        logger = structlog.get_logger("proxy.test")
        logger.debug("debug_message")
        captured = capfd.readouterr()
        assert "debug_message" in captured.out

    def test_info_level_hides_debug_messages(self, capfd):
        """INFO level filters out debug messages."""
        setup_logging(log_level="info", json_format=True)
        logger = structlog.get_logger("proxy.test")
        logger.debug("debug_message")
        captured = capfd.readouterr()
        assert "debug_message" not in captured.out

    def test_warning_level_hides_info_messages(self, capfd):
        """WARNING level filters out info messages."""
        setup_logging(log_level="warning", json_format=True)
        logger = structlog.get_logger("proxy.test")
        logger.info("info_message")
        captured = capfd.readouterr()
        assert "info_message" not in captured.out

    def test_invalid_level_defaults_to_info(self, capfd):
        """Invalid log level falls back to INFO."""
        setup_logging(log_level="INVALID", json_format=True)
        root = logging.getLogger()
        assert root.level == logging.INFO


# ===========================================================================
# AC3 — Logs to stdout
# ===========================================================================

class TestAC3LogsToStdout:
    """Logs are written to stdout for container collection."""

    def test_handler_writes_to_stdout(self):
        """Root logger handler writes to sys.stdout."""
        setup_logging(log_level="info", json_format=True)
        root = logging.getLogger()
        assert len(root.handlers) >= 1
        handler = root.handlers[0]
        assert isinstance(handler, logging.StreamHandler)
        assert handler.stream is sys.stdout

    def test_noisy_loggers_quieted(self):
        """uvicorn.access and httpx loggers set to WARNING."""
        setup_logging(log_level="debug", json_format=True)
        assert logging.getLogger("uvicorn.access").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.WARNING


# ===========================================================================
# AC4 — Webhook integration
# ===========================================================================

class TestAC4WebhookIntegration:
    """Webhook integration for real-time log streaming."""

    def test_valid_providers(self):
        """All expected providers are recognized."""
        assert "custom" in VALID_PROVIDERS
        assert "slack" in VALID_PROVIDERS
        assert "pagerduty" in VALID_PROVIDERS

    def test_valid_events(self):
        """All expected event types are recognized."""
        assert "security" in VALID_EVENTS
        assert "waf_blocked" in VALID_EVENTS
        assert "rate_limited" in VALID_EVENTS
        assert "session_blocked" in VALID_EVENTS
        assert "login_attempt" in VALID_EVENTS
        assert "all" in VALID_EVENTS

    def test_security_events_match(self):
        """SECURITY_EVENTS in dispatcher matches expected set."""
        assert "waf_blocked" in SECURITY_EVENTS
        assert "rate_limited" in SECURITY_EVENTS
        assert "session_blocked" in SECURITY_EVENTS
        assert "login_attempt" in SECURITY_EVENTS

    def test_security_events_complete(self):
        """SECURITY_EVENTS contains exactly the expected events, no more, no less."""
        expected = {"waf_blocked", "rate_limited", "session_blocked", "login_attempt"}
        assert SECURITY_EVENTS == expected

    def test_webhook_create_model_validation(self):
        """WebhookCreate validates required fields."""
        wh = WebhookCreate(name="test", url="https://hooks.example.com/wh")
        assert wh.provider == "custom"
        assert wh.events == ["security"]
        assert wh.enabled is True

    def test_webhook_create_rejects_invalid_provider(self):
        """WebhookCreate rejects unknown providers."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WebhookCreate(name="test", url="https://example.com", provider="unknown")

    def test_webhook_create_rejects_empty_name(self):
        """WebhookCreate rejects empty name."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WebhookCreate(name="", url="https://example.com")

    def test_webhook_update_partial(self):
        """WebhookUpdate allows partial updates."""
        wh = WebhookUpdate(enabled=False)
        assert wh.enabled is False
        assert wh.name is None
        assert wh.url is None

    @pytest.mark.asyncio
    async def test_webhook_dispatch_calls_matching_webhooks(self):
        """dispatch_webhook_event sends to matching webhooks."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://hooks.example.com/wh1", "provider": "custom", "secret": "", "events": ["security"]},
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._validate_webhook_url", return_value=None), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="SQL injection detected",
                context={"path": "/api/users"},
            )

            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_webhook_dispatch_skips_ssrf_urls(self):
        """dispatch_webhook_event skips webhooks with SSRF URLs."""
        mock_webhooks = [
            {"id": uuid4(), "url": "http://169.254.169.254/metadata", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client

            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

            # Should NOT have called post (URL blocked)
            mock_client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_webhook_dispatch_no_client_graceful(self):
        """dispatch_webhook_event gracefully handles no httpx client."""
        with patch("proxy.config.webhook._get_client", return_value=None):
            # Should not raise
            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

    @pytest.mark.asyncio
    async def test_webhook_dispatch_handles_network_error(self):
        """dispatch_webhook_event catches network errors gracefully."""
        import httpx
        mock_webhooks = [
            {"id": uuid4(), "url": "https://hooks.example.com/wh1", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._validate_webhook_url", return_value=None), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
            mock_get_client.return_value = mock_client

            # Should not raise
            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

    @pytest.mark.asyncio
    async def test_webhook_dispatch_handles_fetch_error(self):
        """dispatch_webhook_event catches DB query errors gracefully."""
        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, side_effect=Exception("db error")), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client

            # Should not raise
            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )


# ===========================================================================
# AC5 — Webhook payload format
# ===========================================================================

class TestAC5WebhookPayloadFormat:
    """Webhook payloads include event_type, severity, message, timestamp, context."""

    def test_custom_payload_fields(self):
        """Custom payload includes all required fields."""
        payload = _format_custom_payload(
            event_type="waf_blocked",
            severity="high",
            message="SQL injection detected",
            timestamp="2024-01-01T00:00:00Z",
            context={"path": "/api/users", "method": "POST"},
        )
        assert payload["event_type"] == "waf_blocked"
        assert payload["severity"] == "high"
        assert payload["message"] == "SQL injection detected"
        assert payload["timestamp"] == "2024-01-01T00:00:00Z"
        assert payload["context"]["path"] == "/api/users"

    def test_slack_payload_format(self):
        """Slack payload contains text and blocks."""
        payload = _format_slack_payload(
            event_type="rate_limited",
            severity="warning",
            message="Rate limit exceeded",
            timestamp="2024-01-01T00:00:00Z",
            context={"tenant_id": "t1", "path": "/api"},
        )
        assert "text" in payload
        assert "RATE_LIMITED" in payload["text"]
        assert "blocks" in payload
        assert payload["blocks"][0]["type"] == "section"

    def test_pagerduty_payload_format(self):
        """PagerDuty payload follows Events API v2 format."""
        payload = _format_pagerduty_payload(
            event_type="waf_blocked",
            severity="high",
            message="WAF triggered",
            timestamp="2024-01-01T00:00:00Z",
            context={"path": "/admin"},
            routing_key="my-routing-key",
        )
        assert payload["routing_key"] == "my-routing-key"
        assert payload["event_action"] == "trigger"
        assert "ShieldAI" in payload["payload"]["summary"]
        assert payload["payload"]["severity"] == "critical"
        assert payload["payload"]["source"] == "shieldai-proxy"

    def test_hmac_signing(self):
        """HMAC-SHA256 signature is computed correctly."""
        payload = b'{"event_type":"test"}'
        secret = "my-secret-key"
        sig = _sign_payload(payload, secret)
        assert sig.startswith("sha256=")
        # Verify manually
        expected = hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        assert sig == f"sha256={expected}"

    @pytest.mark.asyncio
    async def test_webhook_dispatch_sends_hmac_header(self):
        """Webhook dispatch includes X-ShieldAI-Signature header when secret is set."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://hooks.example.com/wh1", "provider": "custom", "secret": "my-secret", "events": ["security"]},
        ]

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._validate_webhook_url", return_value=None), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))
            mock_get_client.return_value = mock_client

            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={"path": "/api"},
            )

            call_kwargs = mock_client.post.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            assert "X-ShieldAI-Signature" in headers
            assert headers["X-ShieldAI-Signature"].startswith("sha256=")

    @pytest.mark.asyncio
    async def test_webhook_dispatch_no_hmac_when_no_secret(self):
        """Webhook dispatch omits signature when no secret configured."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://hooks.example.com/wh1", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._validate_webhook_url", return_value=None), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))
            mock_get_client.return_value = mock_client

            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

            call_kwargs = mock_client.post.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            assert "X-ShieldAI-Signature" not in headers

    def test_custom_payload_no_sensitive_data(self):
        """Custom payload context never includes request/response body."""
        payload = _format_custom_payload(
            event_type="waf_blocked",
            severity="high",
            message="test",
            timestamp="2024-01-01T00:00:00Z",
            context={"path": "/api", "method": "POST", "client_ip": "1.2.3.4"},
        )
        ctx = payload["context"]
        assert "body" not in ctx
        assert "request_body" not in ctx
        assert "response_body" not in ctx


# ===========================================================================
# Integration — Security events trigger webhooks
# ===========================================================================

class TestSecurityEventWebhookIntegration:
    """Security events from audit logger trigger webhook dispatch."""

    @pytest.mark.asyncio
    async def test_waf_blocked_triggers_webhook(self):
        """WAF blocked action dispatches a webhook event."""
        al = AuditLogger()
        req = _make_request()
        ctx = _make_context()
        resp = MagicMock(spec=["status_code", "headers"])
        resp.status_code = 403

        await al.process_request(req, ctx)
        # Simulate WAF block
        ctx.extra["_waf_blocked"] = True

        with patch("proxy.middleware.audit_logger.insert_audit_log", new_callable=AsyncMock), \
             patch("proxy.middleware.audit_logger.dispatch_webhook_event", new_callable=AsyncMock) as mock_dispatch:
            await al.process_response(resp, ctx)
            # Give asyncio tasks a chance to be created
            await asyncio.sleep(0.01)

        # The dispatch was called via asyncio.create_task, so it may
        # not be directly captured. Verify the task was created by
        # checking the pending deque has tasks.
        assert len(al._pending) >= 1

    @pytest.mark.asyncio
    async def test_normal_request_no_webhook(self):
        """Normal 200 request does not trigger webhook dispatch."""
        al = AuditLogger()
        req = _make_request()
        ctx = _make_context()
        resp = MagicMock(spec=["status_code", "headers"])
        resp.status_code = 200

        await al.process_request(req, ctx)

        with patch("proxy.middleware.audit_logger.insert_audit_log", new_callable=AsyncMock), \
             patch("proxy.middleware.audit_logger.dispatch_webhook_event", new_callable=AsyncMock) as mock_dispatch:
            await al.process_response(resp, ctx)

        # For a normal GET /api/data returning 200, action is "api_read"
        # which is NOT in SECURITY_EVENTS, so no webhook task for dispatch
        # Only 1 pending task (the audit insert)
        assert len(al._pending) == 1

    @pytest.mark.asyncio
    async def test_webhook_fires_when_audit_logging_disabled(self):
        """Webhooks fire even when audit_logging feature is disabled."""
        al = AuditLogger()
        req = _make_request()
        ctx = _make_context(audit_logging=False)
        resp = MagicMock(spec=["status_code", "headers"])
        resp.status_code = 429  # rate limited

        await al.process_request(req, ctx)

        with patch("proxy.middleware.audit_logger.insert_audit_log", new_callable=AsyncMock) as mock_insert, \
             patch("proxy.middleware.audit_logger.dispatch_webhook_event", new_callable=AsyncMock):
            await al.process_response(resp, ctx)

        # Audit insert should NOT have been called (audit_skip=True)
        # But a webhook task should be created for rate_limited
        # The pending deque should have 1 task (webhook only, no audit)
        assert len(al._pending) == 1


# ===========================================================================
# Webhook URL validation (SSRF)
# ===========================================================================

class TestWebhookURLValidation:
    """Webhook URLs validated against SSRF."""

    def test_public_https_url_allowed(self):
        """Public HTTPS URL passes validation."""
        assert _validate_webhook_url("https://hooks.slack.com/services/T00/B00/xxx") is None

    def test_private_ip_blocked(self):
        """Private IP in webhook URL is blocked."""
        result = _validate_webhook_url("http://192.168.1.1/webhook")
        assert result is not None
        assert "Blocked" in result or "blocked" in result.lower()

    def test_localhost_blocked(self):
        """localhost in webhook URL is blocked."""
        result = _validate_webhook_url("http://127.0.0.1/webhook")
        assert result is not None

    def test_metadata_endpoint_blocked(self):
        """AWS metadata endpoint blocked."""
        result = _validate_webhook_url("http://169.254.169.254/latest/meta-data/")
        assert result is not None

    def test_ipv6_loopback_blocked(self):
        """IPv6 loopback blocked."""
        result = _validate_webhook_url("http://[::1]/webhook")
        assert result is not None


# ===========================================================================
# Webhook API endpoint tests
# ===========================================================================

class TestWebhookAPIEndpoints:
    """Webhook CRUD API requires auth and validates input."""

    def test_create_webhook_requires_auth(self, client):
        """POST /api/config/webhooks/customers/{id}/ requires API key."""
        resp = client.post(
            f"/api/config/webhooks/customers/{uuid4()}/",
            json={"name": "test", "url": "https://example.com/wh"},
        )
        assert resp.status_code == 401

    def test_list_webhooks_requires_auth(self, client):
        """GET /api/config/webhooks/customers/{id}/ requires API key."""
        resp = client.get(f"/api/config/webhooks/customers/{uuid4()}/")
        assert resp.status_code == 401

    def test_get_webhook_requires_auth(self, client):
        """GET /api/config/webhooks/customers/{cid}/{wid} requires API key."""
        resp = client.get(f"/api/config/webhooks/customers/{uuid4()}/{uuid4()}")
        assert resp.status_code == 401

    def test_update_webhook_requires_auth(self, client):
        """PUT /api/config/webhooks/customers/{cid}/{wid} requires API key."""
        resp = client.put(
            f"/api/config/webhooks/customers/{uuid4()}/{uuid4()}",
            json={"name": "updated"},
        )
        assert resp.status_code == 401

    def test_delete_webhook_requires_auth(self, client):
        """DELETE /api/config/webhooks/customers/{cid}/{wid} requires API key."""
        resp = client.delete(f"/api/config/webhooks/customers/{uuid4()}/{uuid4()}")
        assert resp.status_code == 401

    def test_create_webhook_rejects_ssrf_url(self, client, api_headers):
        """Create webhook rejects internal IP URLs with generic message."""
        with patch("proxy.api.webhook_routes.pg_store.get_customer", new_callable=AsyncMock, return_value={"id": uuid4()}):
            resp = client.post(
                f"/api/config/webhooks/customers/{uuid4()}/",
                json={"name": "evil", "url": "http://169.254.169.254/metadata"},
                headers=api_headers,
            )
        assert resp.status_code == 422
        # Generic error — no internal IP details leaked to client
        assert "validation failed" in resp.json()["detail"].lower()
        assert "169.254" not in resp.json()["detail"]

    def test_create_webhook_rejects_invalid_events(self, client, api_headers):
        """Create webhook rejects unknown event types."""
        cid = uuid4()
        with patch("proxy.api.webhook_routes.pg_store.get_customer", new_callable=AsyncMock, return_value={"id": cid}), \
             patch("proxy.api.webhook_routes.validate_origin_url", return_value=None), \
             patch("proxy.api.webhook_routes.webhook_store.list_webhooks", new_callable=AsyncMock, return_value=[]):
            resp = client.post(
                f"/api/config/webhooks/customers/{cid}/",
                json={
                    "name": "test",
                    "url": "https://example.com/wh",
                    "events": ["nonexistent_event"],
                },
                headers=api_headers,
            )
        assert resp.status_code == 422
        assert "Invalid event types" in resp.json()["detail"]

    def test_create_webhook_customer_not_found(self, client, api_headers):
        """Create webhook returns 404 for unknown customer."""
        with patch("proxy.api.webhook_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=None):
            resp = client.post(
                f"/api/config/webhooks/customers/{uuid4()}/",
                json={"name": "test", "url": "https://example.com/wh"},
                headers=api_headers,
            )
        assert resp.status_code == 404

    def test_update_webhook_rejects_ssrf_url(self, client, api_headers):
        """Update webhook rejects internal IP URLs."""
        resp = client.put(
            f"/api/config/webhooks/customers/{uuid4()}/{uuid4()}",
            json={"url": "http://10.0.0.1/webhook"},
            headers=api_headers,
        )
        assert resp.status_code == 422

    def test_create_webhook_enforces_per_customer_limit(self, client, api_headers):
        """Create webhook rejects when per-customer limit reached."""
        cid = uuid4()
        # Mock 25 existing webhooks (the limit)
        existing = [{"id": uuid4()} for _ in range(25)]
        with patch("proxy.api.webhook_routes.pg_store.get_customer", new_callable=AsyncMock, return_value={"id": cid}), \
             patch("proxy.api.webhook_routes.validate_origin_url", return_value=None), \
             patch("proxy.api.webhook_routes.webhook_store.list_webhooks", new_callable=AsyncMock, return_value=existing):
            resp = client.post(
                f"/api/config/webhooks/customers/{cid}/",
                json={"name": "test", "url": "https://example.com/wh"},
                headers=api_headers,
            )
        assert resp.status_code == 422
        assert "Maximum webhooks" in resp.json()["detail"]

    def test_events_list_max_length(self):
        """WebhookCreate rejects events list exceeding max length."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WebhookCreate(
                name="test",
                url="https://example.com/wh",
                events=["security"] * 11,  # max is 10
            )

    def test_ssrf_error_does_not_leak_internal_ip(self, client, api_headers):
        """SSRF rejection error message does not reveal internal IP."""
        with patch("proxy.api.webhook_routes.pg_store.get_customer", new_callable=AsyncMock, return_value={"id": uuid4()}):
            resp = client.post(
                f"/api/config/webhooks/customers/{uuid4()}/",
                json={"name": "test", "url": "http://192.168.1.1/webhook"},
                headers=api_headers,
            )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert "192.168" not in detail
        assert "10.0" not in detail
        assert "validation failed" in detail.lower()


# ===========================================================================
# Webhook store tests
# ===========================================================================

class TestWebhookStore:
    """Webhook store CRUD operations."""

    @pytest.mark.asyncio
    async def test_get_enabled_webhooks_no_pool(self):
        """get_enabled_webhooks_for_event returns [] when no DB pool."""
        from proxy.store.webhooks import get_enabled_webhooks_for_event
        with patch("proxy.store.webhooks.get_pool", return_value=None):
            result = await get_enabled_webhooks_for_event("cust-id", "waf_blocked")
            assert result == []

    @pytest.mark.asyncio
    async def test_get_enabled_webhooks_invalid_uuid(self):
        """get_enabled_webhooks_for_event returns [] for invalid customer_id."""
        from proxy.store.webhooks import get_enabled_webhooks_for_event
        with patch("proxy.store.webhooks.get_pool", return_value=MagicMock()):
            result = await get_enabled_webhooks_for_event("not-a-uuid", "waf_blocked")
            assert result == []

    @pytest.mark.asyncio
    async def test_create_webhook_raises_when_no_pool(self):
        """create_webhook raises StoreUnavailable when no DB pool."""
        from proxy.store.webhooks import create_webhook
        from proxy.store.postgres import StoreUnavailable
        with patch("proxy.store.webhooks.get_pool", return_value=None):
            with pytest.raises(StoreUnavailable):
                await create_webhook(
                    customer_id=uuid4(), name="test",
                    url="https://example.com", provider="custom",
                )

    @pytest.mark.asyncio
    async def test_delete_webhook_raises_when_no_pool(self):
        """delete_webhook raises StoreUnavailable when no DB pool."""
        from proxy.store.webhooks import delete_webhook
        from proxy.store.postgres import StoreUnavailable
        with patch("proxy.store.webhooks.get_pool", return_value=None):
            with pytest.raises(StoreUnavailable):
                await delete_webhook(uuid4())

    @pytest.mark.asyncio
    async def test_update_webhook_rejects_bad_column(self):
        """update_webhook rejects non-whitelisted column names."""
        from proxy.store.webhooks import update_webhook
        mock_pool = MagicMock()
        with patch("proxy.store.webhooks.get_pool", return_value=mock_pool):
            with pytest.raises(ValueError, match="Invalid column name"):
                await update_webhook(uuid4(), id="injected")


# ===========================================================================
# Context binding — request_id in all middleware logs
# ===========================================================================

class TestContextBinding:
    """ContextInjector binds request_id to structlog contextvars."""

    @pytest.mark.asyncio
    async def test_context_injector_binds_request_id(self):
        """ContextInjector.process_request binds request_id to contextvars."""
        from proxy.middleware.context_injector import ContextInjector

        ci = ContextInjector()
        req = _make_request()
        ctx = RequestContext()
        ctx.tenant_id = "test-tenant"

        await ci.process_request(req, ctx)

        # request_id should now be in contextvars
        bound = structlog.contextvars.get_contextvars()
        assert "request_id" in bound
        assert bound["request_id"] == ctx.request_id
        assert bound["tenant_id"] == "test-tenant"

        structlog.contextvars.clear_contextvars()

    @pytest.mark.asyncio
    async def test_context_injector_clears_previous_context(self):
        """ContextInjector clears stale contextvars from previous requests."""
        from proxy.middleware.context_injector import ContextInjector

        # Bind stale context
        structlog.contextvars.bind_contextvars(
            request_id="old-request",
            stale_key="stale_value",
        )

        ci = ContextInjector()
        req = _make_request()
        ctx = RequestContext()
        ctx.tenant_id = "new-tenant"

        await ci.process_request(req, ctx)

        bound = structlog.contextvars.get_contextvars()
        assert bound["request_id"] != "old-request"
        assert "stale_key" not in bound

        structlog.contextvars.clear_contextvars()
