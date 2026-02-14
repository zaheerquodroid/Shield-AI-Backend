"""Webhook security attack simulation tests.

Tests for:
  1. SSRF attacks via webhook URLs
  2. HMAC signature verification
  3. Secret non-exposure in API responses
  4. Payload sanitization (no sensitive data leakage)
  5. Provider-specific payload safety
  6. Webhook URL validation edge cases
  7. Error resilience (fail-open, no crashes)
"""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from proxy.config.webhook import (
    SECURITY_EVENTS,
    _format_custom_payload,
    _format_slack_payload,
    _format_pagerduty_payload,
    _sanitize_slack_text,
    _sign_payload,
    _validate_webhook_url,
    close_webhook_client,
    dispatch_webhook_event,
)
from proxy.models.webhook import WebhookCreate, WebhookUpdate


# ===========================================================================
# 1. SSRF attacks via webhook URLs
# ===========================================================================

class TestSSRFProtection:
    """Webhook URL SSRF protection covers all attack vectors."""

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/webhook",
        "http://127.0.0.1:8080/callback",
        "http://10.0.0.1/internal",
        "http://10.255.255.255/internal",
        "http://172.16.0.1/internal",
        "http://172.31.255.255/internal",
        "http://192.168.0.1/internal",
        "http://192.168.255.255/internal",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://169.254.0.1/link-local",
        "http://0.0.0.0/zero",
        "http://[::1]/ipv6-loopback",
        "http://[fc00::1]/ipv6-private",
        "http://[fe80::1]/ipv6-link-local",
    ])
    def test_private_and_reserved_ips_blocked(self, url):
        """Private/reserved IP addresses in webhook URLs are blocked."""
        result = _validate_webhook_url(url)
        assert result is not None, f"Expected {url} to be blocked"

    @pytest.mark.parametrize("url", [
        "https://hooks.slack.com/services/T00/B00/xxx",
        "https://events.pagerduty.com/v2/enqueue",
        "https://webhook.example.com/callback",
        "http://api.example.com/webhook",
    ])
    def test_public_urls_allowed(self, url):
        """Public URLs are allowed for webhook targets (with mocked DNS for test stability)."""
        # Mock DNS to return a public IP since test env may not resolve these domains
        with patch("proxy.middleware.url_validator.socket.getaddrinfo",
                    return_value=[(2, 1, 0, '', ('93.184.216.34', 0))]):
            result = _validate_webhook_url(url)
        assert result is None, f"Expected {url} to be allowed, got: {result}"

    def test_ftp_scheme_blocked(self):
        """Non-HTTP schemes like ftp are blocked."""
        result = _validate_webhook_url("ftp://example.com/webhook")
        assert result is not None

    def test_file_scheme_blocked(self):
        """file:// scheme is blocked."""
        result = _validate_webhook_url("file:///etc/passwd")
        assert result is not None

    def test_no_scheme_blocked(self):
        """URL without scheme is blocked."""
        result = _validate_webhook_url("example.com/webhook")
        assert result is not None

    def test_empty_url_blocked(self):
        """Empty URL is blocked."""
        result = _validate_webhook_url("")
        assert result is not None

    @pytest.mark.asyncio
    async def test_ssrf_blocked_at_dispatch_time(self):
        """SSRF check runs at dispatch time, not just at registration."""
        # Even if URL was valid when registered, check again at dispatch
        mock_webhooks = [
            {"id": uuid4(), "url": "http://192.168.1.1/internal", "provider": "custom", "secret": "", "events": ["security"]},
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

            mock_client.post.assert_not_called()


# ===========================================================================
# 2. HMAC signature verification
# ===========================================================================

class TestHMACSignature:
    """HMAC-SHA256 signature is correctly computed and verifiable."""

    def test_hmac_is_sha256(self):
        """Signature uses SHA-256 algorithm."""
        sig = _sign_payload(b"test", "secret")
        assert sig.startswith("sha256=")
        # hex digest should be 64 chars
        assert len(sig.split("=")[1]) == 64

    def test_hmac_changes_with_payload(self):
        """Different payloads produce different signatures."""
        sig1 = _sign_payload(b"payload1", "secret")
        sig2 = _sign_payload(b"payload2", "secret")
        assert sig1 != sig2

    def test_hmac_changes_with_secret(self):
        """Different secrets produce different signatures."""
        sig1 = _sign_payload(b"payload", "secret1")
        sig2 = _sign_payload(b"payload", "secret2")
        assert sig1 != sig2

    def test_hmac_deterministic(self):
        """Same payload+secret always produces same signature."""
        sig1 = _sign_payload(b"payload", "secret")
        sig2 = _sign_payload(b"payload", "secret")
        assert sig1 == sig2

    def test_hmac_verifiable_by_receiver(self):
        """Receiver can verify signature using standard HMAC library."""
        payload = b'{"event":"test"}'
        secret = "webhook-secret-123"
        sig = _sign_payload(payload, secret)

        # Receiver-side verification
        expected = "sha256=" + hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        assert hmac.compare_digest(sig, expected)

    @pytest.mark.asyncio
    async def test_pagerduty_no_hmac_header(self):
        """PagerDuty provider does not include X-ShieldAI-Signature (uses routing_key instead)."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://events.pagerduty.com/v2/enqueue", "provider": "pagerduty", "secret": "routing-key", "events": ["security"]},
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


# ===========================================================================
# 3. Secret non-exposure
# ===========================================================================

class TestSecretNonExposure:
    """Webhook secrets are never exposed in API responses or logs."""

    def test_webhook_response_model_excludes_secret(self):
        """WebhookResponse model does not have a secret field."""
        from proxy.models.webhook import WebhookResponse
        fields = WebhookResponse.model_fields
        assert "secret" not in fields

    def test_webhook_store_select_excludes_secret(self):
        """Webhook store SELECT queries do not include secret column."""
        import inspect
        from proxy.store import webhooks

        source = inspect.getsource(webhooks.get_webhook)
        assert "secret" not in source.split("SELECT")[1].split("FROM")[0]

        source = inspect.getsource(webhooks.list_webhooks)
        assert "secret" not in source.split("SELECT")[1].split("FROM")[0]


# ===========================================================================
# 4. Payload sanitization
# ===========================================================================

class TestPayloadSanitization:
    """Webhook payloads never contain sensitive data."""

    def test_custom_payload_no_body_fields(self):
        """Custom payload context must not contain request/response bodies."""
        context = {
            "path": "/api/users",
            "method": "POST",
            "client_ip": "1.2.3.4",
            "tenant_id": "t1",
        }
        payload = _format_custom_payload("waf_blocked", "high", "test", "2024-01-01T00:00:00Z", context)
        flat = json.dumps(payload)
        # Ensure no body-related keys
        assert "request_body" not in flat
        assert "response_body" not in flat

    def test_slack_payload_no_secrets(self):
        """Slack payload does not expose secrets or internal details."""
        payload = _format_slack_payload(
            "waf_blocked", "high", "SQL injection blocked",
            "2024-01-01T00:00:00Z",
            {"tenant_id": "t1", "path": "/api/users"},
        )
        flat = json.dumps(payload)
        assert "password" not in flat.lower()
        assert "api_key" not in flat.lower()
        assert "secret" not in flat.lower()

    def test_pagerduty_payload_no_secrets(self):
        """PagerDuty payload does not expose internal secrets."""
        payload = _format_pagerduty_payload(
            "waf_blocked", "high", "test", "2024-01-01T00:00:00Z",
            {"tenant_id": "t1"}, routing_key="pd-key",
        )
        # routing_key IS the PagerDuty integration key, it's expected to be there
        flat = json.dumps(payload)
        assert "password" not in flat.lower()
        assert "api_key" not in flat.lower()


# ===========================================================================
# 5. Provider-specific safety
# ===========================================================================

class TestProviderSafety:
    """Provider-specific payload formatting is safe."""

    def test_slack_mrkdwn_injection(self):
        """Slack payload handles special mrkdwn characters in context."""
        payload = _format_slack_payload(
            "waf_blocked", "high",
            "Path: *bold* _italic_ ~strike~",
            "2024-01-01T00:00:00Z",
            {"path": "/*/_/~strike~/path"},
        )
        # Should not crash — formatting is informational
        assert "blocks" in payload

    def test_pagerduty_severity_mapping(self):
        """PagerDuty severity maps correctly."""
        for severity, expected_pd in [("high", "critical"), ("warning", "warning"), ("info", "info")]:
            payload = _format_pagerduty_payload(
                "test", severity, "msg", "2024-01-01T00:00:00Z", {}, "",
            )
            assert payload["payload"]["severity"] == expected_pd

    def test_custom_payload_json_serializable(self):
        """Custom payload is always JSON-serializable."""
        from datetime import datetime
        context = {"timestamp": datetime.now(), "uuid": uuid4()}
        payload = _format_custom_payload("test", "info", "msg", "2024-01-01T00:00:00Z", context)
        # Should serialize without error using default=str
        json.dumps(payload, default=str)


# ===========================================================================
# 6. Error resilience
# ===========================================================================

class TestErrorResilience:
    """Webhook dispatch is fail-open and never crashes the proxy."""

    @pytest.mark.asyncio
    async def test_dispatch_survives_json_serialization_error(self):
        """Webhook dispatch handles non-serializable context gracefully."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://example.com/wh", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        # Context with non-serializable object — json.dumps(default=str) handles this
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
                context={"obj": object()},
            )

            # Should still have called post (default=str handles it)
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_survives_timeout(self):
        """Webhook dispatch handles timeout gracefully."""
        import httpx
        mock_webhooks = [
            {"id": uuid4(), "url": "https://slow.example.com/wh", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._validate_webhook_url", return_value=None), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
            mock_get_client.return_value = mock_client

            # Should not raise
            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

    @pytest.mark.asyncio
    async def test_dispatch_survives_multiple_webhook_errors(self):
        """Webhook dispatch continues to next webhook after one fails."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://fail.example.com/wh", "provider": "custom", "secret": "", "events": ["security"]},
            {"id": uuid4(), "url": "https://success.example.com/wh", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "fail" in url:
                raise Exception("network error")
            return MagicMock(status_code=200)

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._validate_webhook_url", return_value=None), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.post = mock_post
            mock_get_client.return_value = mock_client

            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

            # Both webhooks should have been attempted
            assert call_count == 2

    @pytest.mark.asyncio
    async def test_close_webhook_client_idempotent(self):
        """close_webhook_client is safe to call multiple times."""
        import proxy.config.webhook as wh_mod
        wh_mod._webhook_client = None
        await close_webhook_client()  # no-op
        await close_webhook_client()  # still no-op


# ===========================================================================
# 7. Webhook model validation
# ===========================================================================

class TestWebhookModelValidation:
    """Webhook Pydantic models enforce constraints."""

    def test_name_max_length(self):
        """Name must be <= 255 characters."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WebhookCreate(name="x" * 256, url="https://example.com")

    def test_url_max_length(self):
        """URL must be <= 2048 characters."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WebhookCreate(name="test", url="https://example.com/" + "x" * 2048)

    def test_secret_max_length(self):
        """Secret must be <= 255 characters."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WebhookCreate(name="test", url="https://example.com", secret="x" * 256)

    def test_provider_enum_validation(self):
        """Only valid providers are accepted."""
        from pydantic import ValidationError
        for provider in ["custom", "slack", "pagerduty"]:
            wh = WebhookCreate(name="test", url="https://example.com", provider=provider)
            assert wh.provider == provider
        with pytest.raises(ValidationError):
            WebhookCreate(name="test", url="https://example.com", provider="discord")

    def test_event_string_too_long_rejected(self):
        """Individual event strings exceeding 64 chars are rejected."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="Event string too long"):
            WebhookCreate(
                name="test",
                url="https://example.com",
                events=["x" * 65],
            )

    def test_event_string_at_limit_accepted(self):
        """Event string at exactly 64 chars is accepted."""
        wh = WebhookCreate(
            name="test",
            url="https://example.com",
            events=["x" * 64],
        )
        assert len(wh.events[0]) == 64

    def test_update_event_string_too_long_rejected(self):
        """WebhookUpdate also rejects event strings exceeding 64 chars."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="Event string too long"):
            WebhookUpdate(events=["y" * 65])


# ===========================================================================
# 8. Slack mention injection attack simulation
# ===========================================================================

class TestSlackMentionInjection:
    """Verify Slack payloads sanitize attacker-controlled input to prevent
    @channel/@here/@everyone notification spam."""

    def test_sanitize_at_channel(self):
        """@channel is neutralized with zero-width space."""
        result = _sanitize_slack_text("alert @channel now")
        assert "@channel" not in result
        assert "@\u200bchannel" in result

    def test_sanitize_at_here(self):
        """@here is neutralized with zero-width space."""
        result = _sanitize_slack_text("hey @here look")
        assert "@here" not in result
        assert "@\u200bhere" in result

    def test_sanitize_at_everyone(self):
        """@everyone is neutralized with zero-width space."""
        result = _sanitize_slack_text("hi @everyone")
        assert "@everyone" not in result
        assert "@\u200beveryone" in result

    def test_sanitize_html_entities(self):
        """Slack HTML entities (& < >) are escaped."""
        result = _sanitize_slack_text("a & b <script> c > d")
        assert "&amp;" in result
        assert "&lt;" in result
        assert "&gt;" in result
        assert "<script>" not in result

    def test_sanitize_link_injection(self):
        """Slack <url|text> link syntax is escaped."""
        result = _sanitize_slack_text("<https://evil.com|click here>")
        assert "<https" not in result
        assert "&lt;" in result

    def test_slack_payload_sanitizes_message(self):
        """Slack payload message with @channel is sanitized."""
        payload = _format_slack_payload(
            "waf_blocked", "high",
            "Attack from @channel path",
            "2024-01-01T00:00:00Z",
            {"path": "/api"},
        )
        text = payload["text"]
        assert "@channel" not in text
        assert "@\u200bchannel" in text

    def test_slack_payload_sanitizes_context_values(self):
        """Slack payload context values with @here are sanitized."""
        payload = _format_slack_payload(
            "waf_blocked", "high", "test",
            "2024-01-01T00:00:00Z",
            {"path": "/@here/admin", "tenant_id": "t1"},
        )
        block_text = payload["blocks"][0]["text"]["text"]
        assert "@here" not in block_text
        assert "@\u200bhere" in block_text

    def test_slack_payload_multiple_mentions_all_sanitized(self):
        """All mention types in one message are sanitized."""
        payload = _format_slack_payload(
            "waf_blocked", "high",
            "@channel @here @everyone attack",
            "2024-01-01T00:00:00Z",
            {},
        )
        text = payload["text"]
        assert "@channel" not in text
        assert "@here" not in text
        assert "@everyone" not in text

    @pytest.mark.asyncio
    async def test_attacker_path_with_mentions_sanitized_in_dispatch(self):
        """Attacker-controlled path containing @channel is sanitized in Slack webhook."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://hooks.slack.com/T/B/x", "provider": "slack", "secret": "", "events": ["security"]},
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
                message="blocked @channel injection",
                context={"path": "/@everyone/admin"},
            )

            call_kwargs = mock_client.post.call_args
            sent_bytes = call_kwargs.kwargs.get("content", b"")
            sent_text = sent_bytes.decode("utf-8")
            # Verify @channel and @everyone do NOT appear unsanitized
            assert "@channel" not in sent_text
            assert "@everyone" not in sent_text


# ===========================================================================
# 9. login_attempt webhook dispatch (was silently dead)
# ===========================================================================

class TestLoginAttemptWebhookDispatch:
    """login_attempt is in SECURITY_EVENTS and actually dispatches webhooks."""

    def test_login_attempt_in_security_events(self):
        """login_attempt is included in SECURITY_EVENTS."""
        assert "login_attempt" in SECURITY_EVENTS

    def test_all_valid_security_events_in_dispatcher(self):
        """All security event types that should trigger webhooks are in SECURITY_EVENTS."""
        expected = {"waf_blocked", "rate_limited", "session_blocked", "login_attempt"}
        assert expected == SECURITY_EVENTS

    @pytest.mark.asyncio
    async def test_login_attempt_triggers_webhook_via_audit_logger(self):
        """Login attempt on auth endpoint actually creates a webhook dispatch task."""
        import asyncio
        from proxy.middleware.audit_logger import AuditLogger
        from proxy.middleware.pipeline import RequestContext
        from proxy.config.rate_limit_defaults import AUTH_PATH_PATTERNS

        al = AuditLogger()

        # Pick a known auth endpoint
        auth_path = "/api/login"

        req = MagicMock()
        req.method = "POST"
        req.url = MagicMock()
        req.url.path = auth_path
        req.client = MagicMock()
        req.client.host = "10.0.0.1"
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "user-agent": "TestAgent/1.0",
            "host": "app.example.com",
        }.get(key, default)

        ctx = RequestContext()
        ctx.tenant_id = "tenant-1"
        ctx.request_id = "req-123"
        ctx.customer_config = {
            "enabled_features": {"audit_logging": True},
            "customer_id": "cust-uuid-1",
            "app_id": "app-1",
        }

        await al.process_request(req, ctx)

        resp = MagicMock(spec=["status_code", "headers"])
        resp.status_code = 200

        with patch("proxy.middleware.audit_logger.dispatch_webhook_event", new_callable=AsyncMock) as mock_dispatch:
            await al.process_response(resp, ctx)
            await asyncio.sleep(0.01)

        # Should have 1 audit row in queue + 1 webhook task in _pending_webhooks
        assert al._queue.qsize() == 1
        assert len(al._pending_webhooks) == 1


# ===========================================================================
# 10. CRLF log forging protection in TenantRouter
# ===========================================================================

class TestCRLFLogForging:
    """TenantRouter strips control characters from domain to prevent log forging."""

    @pytest.mark.asyncio
    async def test_crlf_stripped_from_domain(self):
        """Carriage return and newline characters removed from Host header domain.

        The attack: an attacker sends Host: evil.com\\r\\nINFO Forged log entry
        In ConsoleRenderer (dev mode), the \\r\\n would create a fake log line.
        After sanitization, the \\r\\n are stripped so the output stays on one line.
        """
        from proxy.middleware.router import TenantRouter
        from proxy.middleware.pipeline import RequestContext

        router = TenantRouter()
        req = MagicMock()
        req.headers = MagicMock()
        # Attacker sends: evil.com\r\nINFO Forged log entry
        req.headers.get = lambda key, default="": {
            "host": "evil.com\r\nINFO Forged log entry",
        }.get(key, default)

        ctx = RequestContext()

        with patch("proxy.middleware.router.get_config_service") as mock_svc:
            mock_config = MagicMock()
            mock_config.get_config.return_value = {}
            mock_svc.return_value = mock_config

            await router.process_request(req, ctx)

            # The config service should receive a domain with CRLF stripped
            # (the remaining text is harmless — it just becomes an invalid domain)
            call_args = mock_config.get_config.call_args[0][0]
            assert "\r" not in call_args
            assert "\n" not in call_args
            assert "\x00" not in call_args

    @pytest.mark.asyncio
    async def test_null_byte_stripped_from_domain(self):
        """Null bytes removed from Host header domain."""
        from proxy.middleware.router import TenantRouter
        from proxy.middleware.pipeline import RequestContext

        router = TenantRouter()
        req = MagicMock()
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "host": "evil.com\x00.attacker.com",
        }.get(key, default)

        ctx = RequestContext()

        with patch("proxy.middleware.router.get_config_service") as mock_svc:
            mock_config = MagicMock()
            mock_config.get_config.return_value = {}
            mock_svc.return_value = mock_config

            await router.process_request(req, ctx)

            call_args = mock_config.get_config.call_args[0][0]
            assert "\x00" not in call_args

    @pytest.mark.asyncio
    async def test_clean_domain_passes_through(self):
        """Normal domain passes through sanitization unchanged."""
        from proxy.middleware.router import TenantRouter
        from proxy.middleware.pipeline import RequestContext

        router = TenantRouter()
        req = MagicMock()
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "host": "app.example.com:8080",
        }.get(key, default)

        ctx = RequestContext()

        with patch("proxy.middleware.router.get_config_service") as mock_svc:
            mock_config = MagicMock()
            mock_config.get_config.return_value = {}
            mock_svc.return_value = mock_config

            await router.process_request(req, ctx)

            call_args = mock_config.get_config.call_args[0][0]
            assert call_args == "app.example.com"
