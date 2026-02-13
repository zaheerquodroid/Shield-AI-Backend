"""Round 3 security hardening — attack simulation tests.

Tests for vulnerabilities found by web research and deep code audit:
  1. IPv4-mapped IPv6 SSRF bypass (::ffff:127.0.0.1)
  2. DNS resolution failure fail-closed for webhooks
  3. URL @userinfo parser confusion SSRF
  4. Negative retention_days audit log deletion
  5. Field truncation audit evasion
  6. CSV injection via leading whitespace
  7. Slack mention case-insensitive bypass
  8. Slack link unfurling disabled
  9. Separate webhook/audit task queues
  10. Unicode control character sanitization consistency
  11. X-Request-ID sanitization and length limit
  12. Webhook response status logging
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from proxy.middleware.url_validator import validate_origin_url, _is_blocked, _normalize_ip
from proxy.config.webhook import (
    _format_slack_payload,
    _format_pagerduty_payload,
    _sanitize_slack_text,
    _validate_webhook_url,
    dispatch_webhook_event,
)
from proxy.middleware.audit_logger import AuditLogger, _sanitize
from proxy.middleware.pipeline import RequestContext
from proxy.utils.sanitize import strip_control_chars


# ===========================================================================
# 1. IPv4-mapped IPv6 SSRF bypass
# ===========================================================================

class TestIPv4MappedIPv6SSRF:
    """IPv4-mapped IPv6 addresses must be blocked just like their IPv4 equivalents."""

    @pytest.mark.parametrize("url", [
        "http://[::ffff:127.0.0.1]/callback",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:10.0.0.1]/internal",
        "http://[::ffff:192.168.1.1]/internal",
        "http://[::ffff:172.16.0.1]/internal",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/callback",
        "http://[::ffff:0.0.0.0]/zero",
    ])
    def test_ipv4_mapped_ipv6_blocked(self, url):
        """IPv4-mapped IPv6 addresses are normalized and blocked."""
        result = validate_origin_url(url)
        assert result is not None, f"IPv4-mapped IPv6 bypass: {url} was not blocked"

    def test_normalize_ip_maps_ipv4(self):
        """_normalize_ip extracts IPv4 from IPv4-mapped IPv6."""
        import ipaddress
        addr = ipaddress.ip_address("::ffff:127.0.0.1")
        normalized = _normalize_ip(addr)
        assert isinstance(normalized, ipaddress.IPv4Address)
        assert str(normalized) == "127.0.0.1"

    def test_normalize_ip_passthrough_ipv4(self):
        """_normalize_ip passes through regular IPv4 unchanged."""
        import ipaddress
        addr = ipaddress.ip_address("8.8.8.8")
        assert _normalize_ip(addr) == addr

    def test_normalize_ip_passthrough_ipv6(self):
        """_normalize_ip passes through non-mapped IPv6 unchanged."""
        import ipaddress
        addr = ipaddress.ip_address("::1")
        assert _normalize_ip(addr) == addr

    def test_is_blocked_ipv4_mapped_loopback(self):
        """_is_blocked catches IPv4-mapped loopback."""
        import ipaddress
        assert _is_blocked(ipaddress.ip_address("::ffff:127.0.0.1"))

    def test_is_blocked_ipv4_mapped_metadata(self):
        """_is_blocked catches IPv4-mapped AWS metadata."""
        import ipaddress
        assert _is_blocked(ipaddress.ip_address("::ffff:169.254.169.254"))

    def test_dns_resolution_also_normalizes(self):
        """DNS-resolved IPv4-mapped IPv6 addresses are also caught."""
        # Simulate DNS returning an IPv4-mapped IPv6 address
        mock_infos = [(10, 1, 0, '', ('::ffff:10.0.0.1', 0, 0, 0))]
        with patch("proxy.middleware.url_validator.socket.getaddrinfo", return_value=mock_infos):
            result = validate_origin_url("http://evil.com/hook")
        assert result is not None
        assert "blocked" in result.lower()


# ===========================================================================
# 2. DNS resolution failure behavior
# ===========================================================================

class TestDNSFailureBehavior:
    """DNS resolution failure is fail-closed for webhooks, fail-open for origins."""

    def test_strict_dns_blocks_on_failure(self):
        """strict_dns=True blocks when DNS resolution fails."""
        import socket
        with patch("proxy.middleware.url_validator.socket.getaddrinfo",
                    side_effect=socket.gaierror("DNS failed")):
            result = validate_origin_url("http://evil-dns.com/hook", strict_dns=True)
        assert result is not None
        assert "DNS resolution failed" in result

    def test_non_strict_dns_allows_on_failure(self):
        """strict_dns=False (default) allows when DNS resolution fails."""
        import socket
        with patch("proxy.middleware.url_validator.socket.getaddrinfo",
                    side_effect=socket.gaierror("DNS failed")):
            result = validate_origin_url("http://origin.internal:3000")
        assert result is None

    def test_webhook_validation_uses_strict_dns(self):
        """_validate_webhook_url uses strict_dns=True internally."""
        import socket
        with patch("proxy.middleware.url_validator.socket.getaddrinfo",
                    side_effect=socket.gaierror("DNS failed")):
            result = _validate_webhook_url("http://attacker-dns-rebind.com/hook")
        assert result is not None
        assert "DNS" in result

    @pytest.mark.asyncio
    async def test_dns_failure_blocks_webhook_dispatch(self):
        """Webhook dispatch skips URLs that fail DNS resolution."""
        import socket
        mock_webhooks = [
            {"id": uuid4(), "url": "http://dns-fail.com/wh", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.middleware.url_validator.socket.getaddrinfo", side_effect=socket.gaierror("fail")), \
             patch("proxy.config.webhook._get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client

            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

            # Should NOT have called post (DNS failed, strict mode)
            mock_client.post.assert_not_called()


# ===========================================================================
# 3. URL @userinfo parser confusion SSRF
# ===========================================================================

class TestUserinfoSSRF:
    """URLs with @userinfo are rejected to prevent parser confusion attacks."""

    @pytest.mark.parametrize("url", [
        "http://public.com@169.254.169.254/latest/meta-data/",
        "http://user:pass@127.0.0.1/admin",
        "http://foo@bar@192.168.1.1/",
        "https://legit.com@internal-service/secret",
    ])
    def test_userinfo_urls_blocked(self, url):
        """URLs with @ in netloc are blocked."""
        result = validate_origin_url(url)
        assert result is not None, f"@userinfo bypass: {url} was not blocked"
        assert "userinfo" in result.lower() or "@" in result

    def test_null_byte_userinfo_blocked(self):
        """Null-byte + @userinfo combo blocked (caught by null byte check)."""
        result = validate_origin_url("http://safe.com%00@10.0.0.1/internal")
        assert result is not None
        assert "null byte" in result.lower()

    def test_email_like_path_not_blocked(self):
        """@ in path (not netloc) is allowed."""
        # This URL has @ in the path, not in the authority
        with patch("proxy.middleware.url_validator.socket.getaddrinfo",
                    return_value=[(2, 1, 0, '', ('93.184.216.34', 0))]):
            result = validate_origin_url("http://example.com/user@domain")
        assert result is None


# ===========================================================================
# 4. Negative retention_days attack
# ===========================================================================

class TestNegativeRetentionDays:
    """Negative retention_days must not delete all audit logs."""

    @pytest.mark.asyncio
    async def test_negative_days_rejected(self):
        """retention_days < 1 is rejected without executing DELETE."""
        from proxy.store.audit import delete_old_audit_logs
        mock_pool = MagicMock()
        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            result = await delete_old_audit_logs("tenant-1", -1)
        assert result == 0
        # Pool should never have been used
        mock_pool.acquire.assert_not_called()

    @pytest.mark.asyncio
    async def test_zero_days_rejected(self):
        """retention_days = 0 is rejected."""
        from proxy.store.audit import delete_old_audit_logs
        mock_pool = MagicMock()
        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            result = await delete_old_audit_logs("tenant-1", 0)
        assert result == 0

    @pytest.mark.asyncio
    async def test_positive_days_allowed(self):
        """retention_days = 1 is the minimum accepted."""
        from proxy.store.audit import delete_old_audit_logs
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="DELETE 3")
        mock_pool = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            result = await delete_old_audit_logs("tenant-1", 1)
        assert result == 3

    @pytest.mark.asyncio
    async def test_make_interval_used(self):
        """SQL uses make_interval() not string concat for interval construction."""
        from proxy.store.audit import delete_old_audit_logs
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="DELETE 0")
        mock_pool = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        with patch("proxy.store.audit.get_pool", return_value=mock_pool):
            await delete_old_audit_logs("tenant-1", 30)
        sql = mock_conn.execute.call_args[0][0]
        assert "make_interval" in sql
        # Second parameter should be integer 30, not string "30"
        assert mock_conn.execute.call_args[0][2] == 30


# ===========================================================================
# 5. Field truncation audit evasion
# ===========================================================================

class TestFieldTruncationAuditEvasion:
    """Oversized fields must be truncated to prevent INSERT failure (audit evasion)."""

    @pytest.mark.asyncio
    async def test_oversized_method_truncated(self):
        """HTTP method longer than 10 chars is truncated, not dropped."""
        al = AuditLogger()
        req = MagicMock()
        req.method = "SUPERLONGMETHOD"  # > 10 chars
        req.url = MagicMock()
        req.url.path = "/api/test"
        req.client = MagicMock()
        req.client.host = "1.2.3.4"
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "user-agent": "Test",
            "host": "app.example.com",
        }.get(key, default)

        ctx = RequestContext()
        ctx.tenant_id = "tenant-1"
        ctx.request_id = "req-123"
        ctx.customer_config = {
            "enabled_features": {"audit_logging": True},
            "customer_id": "cust-1",
            "app_id": "app-1",
        }

        await al.process_request(req, ctx)
        resp = MagicMock(spec=["status_code", "headers"])
        resp.status_code = 200

        with patch("proxy.middleware.audit_logger.insert_audit_log", new_callable=AsyncMock) as mock_insert:
            await al.process_response(resp, ctx)

        # Verify the method arg was truncated
        call_kwargs = mock_insert.call_args.kwargs
        assert len(call_kwargs["method"]) <= 10

    @pytest.mark.asyncio
    async def test_oversized_app_id_truncated(self):
        """app_id longer than 255 chars is truncated."""
        al = AuditLogger()
        req = MagicMock()
        req.method = "GET"
        req.url = MagicMock()
        req.url.path = "/test"
        req.client = MagicMock()
        req.client.host = "1.2.3.4"
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "user-agent": "Test", "host": "a.com",
        }.get(key, default)

        ctx = RequestContext()
        ctx.tenant_id = "t1"
        ctx.request_id = "r1"
        ctx.customer_config = {
            "enabled_features": {"audit_logging": True},
            "customer_id": "c1",
            "app_id": "A" * 300,  # > 255 chars
        }

        await al.process_request(req, ctx)
        resp = MagicMock(spec=["status_code", "headers"])
        resp.status_code = 200

        with patch("proxy.middleware.audit_logger.insert_audit_log", new_callable=AsyncMock) as mock_insert:
            await al.process_response(resp, ctx)

        assert len(mock_insert.call_args.kwargs["app_id"]) <= 255

    @pytest.mark.asyncio
    async def test_country_field_sanitized(self):
        """Country field has control chars stripped (not just truncated)."""
        al = AuditLogger()
        req = MagicMock()
        req.method = "GET"
        req.url = MagicMock()
        req.url.path = "/test"
        req.client = MagicMock()
        req.client.host = "1.2.3.4"
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "user-agent": "Test", "host": "a.com",
        }.get(key, default)

        ctx = RequestContext()
        ctx.tenant_id = "t1"
        ctx.request_id = "r1"
        ctx.customer_config = {
            "enabled_features": {"audit_logging": True},
            "customer_id": "c1",
            "app_id": "a1",
        }
        ctx.extra["country"] = "US\r\nINJECT"  # CRLF injection attempt

        await al.process_request(req, ctx)
        resp = MagicMock(spec=["status_code", "headers"])
        resp.status_code = 200

        with patch("proxy.middleware.audit_logger.insert_audit_log", new_callable=AsyncMock) as mock_insert:
            await al.process_response(resp, ctx)

        country = mock_insert.call_args.kwargs["country"]
        assert "\r" not in country
        assert "\n" not in country


# ===========================================================================
# 6. CSV injection via leading whitespace
# ===========================================================================

class TestCSVInjectionWhitespace:
    """CSV formula injection via leading whitespace is prevented."""

    def test_leading_spaces_then_equals(self):
        """'   =CMD()' is still caught after stripping leading whitespace."""
        from proxy.api.audit_routes import _csv_safe
        result = _csv_safe("   =CMD('calc')")
        assert result.startswith("'")

    def test_leading_tab_then_plus(self):
        """Leading tab before + is caught."""
        from proxy.api.audit_routes import _csv_safe
        result = _csv_safe("\t+1+1")
        # \t itself is a formula prefix, should be caught
        assert result.startswith("'")

    def test_normal_values_pass(self):
        """Normal string values are not modified."""
        from proxy.api.audit_routes import _csv_safe
        assert _csv_safe("GET") == "GET"
        assert _csv_safe("/api/users") == "/api/users"
        assert _csv_safe("200") == "200"

    def test_empty_string(self):
        """Empty string is safe."""
        from proxy.api.audit_routes import _csv_safe
        assert _csv_safe("") == ""

    def test_none_value(self):
        """None is safe."""
        from proxy.api.audit_routes import _csv_safe
        assert _csv_safe(None) == ""


# ===========================================================================
# 7. Slack mention case-insensitive bypass
# ===========================================================================

class TestSlackMentionCaseInsensitive:
    """Slack mention sanitization is case-insensitive."""

    @pytest.mark.parametrize("mention,word", [
        ("@Channel", "channel"),
        ("@CHANNEL", "channel"),
        ("@Here", "here"),
        ("@HERE", "here"),
        ("@Everyone", "everyone"),
        ("@EVERYONE", "everyone"),
        ("@cHaNnEl", "channel"),
    ])
    def test_case_variants_sanitized(self, mention, word):
        """Case variations of Slack mentions are neutralized."""
        result = _sanitize_slack_text(f"alert {mention} now")
        # ZWS inserted between @ and the word breaks Slack's mention parsing.
        # The contiguous @word must NOT exist in the result (ZWS breaks it).
        assert f"@{word}" not in result.lower()
        assert "\u200b" in result

    def test_mixed_case_in_slack_payload(self):
        """Slack payload sanitizes mixed-case mentions in context."""
        payload = _format_slack_payload(
            "waf_blocked", "high",
            "Attack from @CHANNEL path",
            "2024-01-01T00:00:00Z",
            {"path": "/@HERE/admin"},
        )
        flat = json.dumps(payload)
        # Check that no unsanitized @channel/@here exists as contiguous string
        # (zero-width space breaks the mention in Slack's parser)
        assert "@channel" not in flat.lower()
        assert "@here" not in flat.lower()


# ===========================================================================
# 8. Slack link unfurling disabled
# ===========================================================================

class TestSlackUnfurlDisabled:
    """Slack payloads disable link and media unfurling."""

    def test_unfurl_links_false(self):
        """Slack payload sets unfurl_links=False."""
        payload = _format_slack_payload("test", "info", "msg", "2024-01-01T00:00:00Z", {})
        assert payload.get("unfurl_links") is False

    def test_unfurl_media_false(self):
        """Slack payload sets unfurl_media=False."""
        payload = _format_slack_payload("test", "info", "msg", "2024-01-01T00:00:00Z", {})
        assert payload.get("unfurl_media") is False

    def test_unfurl_fields_present_with_attacker_url(self):
        """Unfurling disabled even when context contains URLs."""
        payload = _format_slack_payload(
            "waf_blocked", "high", "blocked",
            "2024-01-01T00:00:00Z",
            {"path": "https://evil.com/exfiltrate?token=secret123"},
        )
        assert payload["unfurl_links"] is False
        assert payload["unfurl_media"] is False


# ===========================================================================
# 9. Separate webhook/audit task queues
# ===========================================================================

class TestSeparateTaskQueues:
    """Webhook tasks use a separate queue so they cannot evict audit tasks."""

    @pytest.mark.asyncio
    async def test_webhook_and_audit_use_different_queues(self):
        """WAF block creates audit task in _pending and webhook task in _pending_webhooks."""
        al = AuditLogger()
        req = MagicMock()
        req.method = "GET"
        req.url = MagicMock()
        req.url.path = "/api/test"
        req.client = MagicMock()
        req.client.host = "1.2.3.4"
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "user-agent": "Test", "host": "a.com",
        }.get(key, default)

        ctx = RequestContext()
        ctx.tenant_id = "t1"
        ctx.request_id = "r1"
        ctx.customer_config = {
            "enabled_features": {"audit_logging": True},
            "customer_id": "c1",
            "app_id": "a1",
        }

        await al.process_request(req, ctx)
        ctx.extra["waf_blocked"] = True  # WAF blocked (no underscore prefix)

        resp = MagicMock(spec=["status_code", "headers"])
        resp.status_code = 403

        with patch("proxy.middleware.audit_logger.insert_audit_log", new_callable=AsyncMock), \
             patch("proxy.middleware.audit_logger.dispatch_webhook_event", new_callable=AsyncMock):
            await al.process_response(resp, ctx)

        # Audit in _pending, webhook in _pending_webhooks
        assert len(al._pending) >= 1
        assert len(al._pending_webhooks) >= 1

    def test_queue_sizes_are_independent(self):
        """Queue maxlen is set independently for audit and webhook."""
        al = AuditLogger()
        assert al._pending.maxlen is not None
        assert al._pending_webhooks.maxlen is not None
        # They should be separate deque objects
        assert al._pending is not al._pending_webhooks


# ===========================================================================
# 10. Unicode control character sanitization consistency
# ===========================================================================

class TestUnicodeSanitizationConsistency:
    """All middleware uses the same comprehensive control char sanitization."""

    @pytest.mark.parametrize("char,name", [
        ("\u2028", "LINE_SEPARATOR"),
        ("\u2029", "PARAGRAPH_SEPARATOR"),
        ("\u202e", "RTL_OVERRIDE"),
        ("\u200b", "ZERO_WIDTH_SPACE"),
        ("\u200f", "RTL_MARK"),
        ("\ufeff", "BOM"),
        ("\x7f", "DEL"),
        ("\x80", "C1_CONTROL"),
    ])
    def test_strip_control_chars_covers_unicode(self, char, name):
        """strip_control_chars removes {name}."""
        result = strip_control_chars(f"test{char}value")
        assert char not in result
        assert result == "testvalue"

    @pytest.mark.asyncio
    async def test_router_strips_unicode_control_chars(self):
        """TenantRouter strips Unicode line separators from domain."""
        from proxy.middleware.router import TenantRouter
        router = TenantRouter()
        req = MagicMock()
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "host": "evil.com\u2028INJECTED\u2029LINE",
        }.get(key, default)

        ctx = RequestContext()
        with patch("proxy.middleware.router.get_config_service") as mock_svc:
            mock_config = MagicMock()
            mock_config.get_config.return_value = {}
            mock_svc.return_value = mock_config
            await router.process_request(req, ctx)
            domain = mock_config.get_config.call_args[0][0]
            assert "\u2028" not in domain
            assert "\u2029" not in domain

    @pytest.mark.asyncio
    async def test_router_strips_bidi_overrides(self):
        """TenantRouter strips RTL override characters from domain."""
        from proxy.middleware.router import TenantRouter
        router = TenantRouter()
        req = MagicMock()
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "host": "evil.com\u202erekcat",
        }.get(key, default)

        ctx = RequestContext()
        with patch("proxy.middleware.router.get_config_service") as mock_svc:
            mock_config = MagicMock()
            mock_config.get_config.return_value = {}
            mock_svc.return_value = mock_config
            await router.process_request(req, ctx)
            domain = mock_config.get_config.call_args[0][0]
            assert "\u202e" not in domain


# ===========================================================================
# 11. X-Request-ID sanitization and length limit
# ===========================================================================

class TestXRequestIDSanitization:
    """Client-provided X-Request-ID is sanitized at storage time with length limit."""

    @pytest.mark.asyncio
    async def test_request_id_sanitized_at_storage(self):
        """X-Request-ID with control chars is sanitized when stored in context."""
        from proxy.middleware.context_injector import ContextInjector
        ci = ContextInjector()
        req = MagicMock()
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "x-request-id": "legit-id\r\nInjected-Header: evil",
        }.get(key, default)
        req.client = MagicMock()
        req.client.host = "1.2.3.4"
        req.url = MagicMock()
        req.url.scheme = "https"

        ctx = RequestContext()
        ctx.tenant_id = "t1"

        await ci.process_request(req, ctx)

        stored = ctx.extra.get("original_request_id", "")
        assert "\r" not in stored
        assert "\n" not in stored

    @pytest.mark.asyncio
    async def test_request_id_length_limited(self):
        """X-Request-ID longer than 256 chars is truncated."""
        from proxy.middleware.context_injector import ContextInjector
        ci = ContextInjector()
        req = MagicMock()
        long_id = "A" * 1000
        req.headers = MagicMock()
        req.headers.get = lambda key, default="": {
            "x-request-id": long_id,
        }.get(key, default)
        req.client = MagicMock()
        req.client.host = "1.2.3.4"
        req.url = MagicMock()
        req.url.scheme = "https"

        ctx = RequestContext()
        ctx.tenant_id = "t1"

        await ci.process_request(req, ctx)

        stored = ctx.extra.get("original_request_id", "")
        assert len(stored) <= 256

    @pytest.mark.asyncio
    async def test_x_request_id_in_strip_headers(self):
        """x-request-id is in _STRIP_HEADERS to prevent upstream spoofing."""
        from proxy.middleware.context_injector import _STRIP_HEADERS
        assert "x-request-id" in _STRIP_HEADERS


# ===========================================================================
# 12. Webhook response status logging
# ===========================================================================

class TestWebhookResponseStatusLogging:
    """Webhook dispatch logs non-2xx responses for observability."""

    @pytest.mark.asyncio
    async def test_4xx_response_logged(self):
        """Webhook endpoint returning 4xx is logged as warning."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://hooks.example.com/wh", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._validate_webhook_url", return_value=None), \
             patch("proxy.config.webhook._get_client") as mock_get_client, \
             patch("proxy.config.webhook.logger") as mock_logger:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=MagicMock(status_code=401))
            mock_get_client.return_value = mock_client

            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

            # Should have logged the failure
            mock_logger.warning.assert_called()
            call_kwargs = mock_logger.warning.call_args.kwargs
            assert call_kwargs.get("status_code") == 401

    @pytest.mark.asyncio
    async def test_2xx_response_not_logged_as_warning(self):
        """Webhook endpoint returning 200 does not log a warning."""
        mock_webhooks = [
            {"id": uuid4(), "url": "https://hooks.example.com/wh", "provider": "custom", "secret": "", "events": ["security"]},
        ]

        with patch("proxy.config.webhook.get_enabled_webhooks_for_event", new_callable=AsyncMock, return_value=mock_webhooks), \
             patch("proxy.config.webhook._validate_webhook_url", return_value=None), \
             patch("proxy.config.webhook._get_client") as mock_get_client, \
             patch("proxy.config.webhook.logger") as mock_logger:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=MagicMock(status_code=200))
            mock_get_client.return_value = mock_client

            await dispatch_webhook_event(
                customer_id="cust-1",
                event_type="waf_blocked",
                message="test",
                context={},
            )

            # Should NOT have logged a warning for 200
            for call in mock_logger.warning.call_args_list:
                assert call[0][0] != "webhook_delivery_failed"


# ===========================================================================
# 13. Silent audit failure logging
# ===========================================================================

class TestSilentAuditFailureLogging:
    """Database pool absence is now logged, not silently swallowed."""

    @pytest.mark.asyncio
    async def test_insert_logs_warning_when_no_pool(self):
        """insert_audit_log logs a warning when pool is None."""
        from proxy.store.audit import insert_audit_log
        from datetime import datetime, timezone
        with patch("proxy.store.audit.get_pool", return_value=None), \
             patch("proxy.store.audit.logger") as mock_logger:
            await insert_audit_log(
                tenant_id="t1", app_id="a1", request_id="r1",
                timestamp=datetime.now(timezone.utc),
                method="GET", path="/test", status_code=200,
                duration_ms=1.0, client_ip="1.2.3.4",
                user_agent="Test", country="US", user_id="",
                action="api_read", blocked=False,
            )
            mock_logger.warning.assert_called_once()
            assert mock_logger.warning.call_args[0][0] == "audit_insert_skipped"


# ===========================================================================
# 14. Error message sanitization
# ===========================================================================

class TestErrorMessageSanitization:
    """Error messages strip control chars from reflected user input."""

    def test_ansi_escape_stripped(self):
        """ANSI escape codes in datetime input are stripped from error message."""
        from proxy.api.audit_routes import _parse_datetime
        with pytest.raises(Exception) as exc_info:
            _parse_datetime("\x1b[31mEVIL\x1b[0m", "start_time")
        detail = str(exc_info.value.detail)
        assert "\x1b" not in detail

    def test_crlf_stripped_from_error(self):
        """CRLF in datetime input is stripped from error message."""
        from proxy.api.audit_routes import _parse_datetime
        with pytest.raises(Exception) as exc_info:
            _parse_datetime("bad\r\ninjected", "start_time")
        detail = str(exc_info.value.detail)
        assert "\r" not in detail
        assert "\n" not in detail


# ===========================================================================
# 15. httpx client security configuration
# ===========================================================================

class TestHttpxClientSecurity:
    """httpx webhook client has secure configuration."""

    def test_no_redirect_following(self):
        """httpx client does not follow redirects (prevents redirect SSRF)."""
        import proxy.config.webhook as wh_mod
        old = wh_mod._webhook_client
        wh_mod._webhook_client = None
        try:
            client = wh_mod._get_client()
            assert client is not None
            assert client.follow_redirects is False
        finally:
            if wh_mod._webhook_client is not None:
                # Don't actually close in sync test
                wh_mod._webhook_client = None
            wh_mod._webhook_client = old

    def test_tls_verification_enabled(self):
        """httpx client is created with verify=True (TLS certificate verification)."""
        import proxy.config.webhook as wh_mod
        old = wh_mod._webhook_client
        wh_mod._webhook_client = None
        try:
            with patch("proxy.config.webhook.httpx") as mock_httpx:
                mock_httpx.AsyncClient.return_value = MagicMock()
                mock_httpx.Timeout = MagicMock(return_value=5.0)
                wh_mod._get_client()
                mock_httpx.AsyncClient.assert_called_once()
                call_kwargs = mock_httpx.AsyncClient.call_args[1]
                assert call_kwargs.get("verify") is True
        finally:
            wh_mod._webhook_client = None
            wh_mod._webhook_client = old

    def test_timeout_configured(self):
        """httpx client has a reasonable timeout."""
        import proxy.config.webhook as wh_mod
        old = wh_mod._webhook_client
        wh_mod._webhook_client = None
        try:
            client = wh_mod._get_client()
            assert client is not None
            # Timeout should be 5 seconds
            assert client._timeout.connect is not None
        finally:
            wh_mod._webhook_client = None
            wh_mod._webhook_client = old
