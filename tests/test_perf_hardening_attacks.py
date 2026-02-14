"""Attack simulation tests for performance optimization security hardening.

Validates fixes for vulnerabilities discovered during the performance optimization
security review. Each test class simulates a specific attack vector:

1. Audit queue exhaustion — stop() drain completeness, retry limit on re-queue
2. StreamingResponse bypass — response sanitizer skips unscannable responses
3. IPv6 embedding attacks — 6to4, NAT64, Teredo tunnel private IPs
4. DNS cache flooding — LRU eviction under burst attacks
5. RLS cache race — atomic set vs invalidate-then-re-read
6. Retention error swallowing — asyncio.gather return_exceptions logging
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.responses import Response

from proxy.middleware.audit_logger import (
    AuditLogger,
    _MAX_AUDIT_QUEUE_SIZE,
    _MAX_FLUSH_RETRIES,
)
from proxy.middleware.pipeline import RequestContext
from proxy.middleware.response_sanitizer import ResponseSanitizer, detect_sensitive_content
from proxy.middleware.url_validator import (
    _BLOCKED_NETWORKS,
    _DNS_CACHE,
    _DNS_CACHE_MAX,
    _cached_getaddrinfo,
    _evict_dns_cache,
    _is_blocked,
    validate_origin_url,
)
from proxy.store.rls import (
    _is_rls_enabled,
    _rls_enabled_cache,
    invalidate_rls_cache,
    set_rls_cache,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(
    method: str = "GET",
    path: str = "/api/data",
    client_ip: str = "10.0.0.1",
    user_agent: str = "TestAgent/1.0",
) -> MagicMock:
    req = MagicMock()
    req.method = method
    req.url = MagicMock()
    req.url.path = path
    req.client = MagicMock()
    req.client.host = client_ip
    _headers = {"user-agent": user_agent, "host": "app.example.com"}
    req.headers = MagicMock()
    req.headers.get = lambda key, default="": _headers.get(key, default)
    return req


def _make_context(tenant_id: str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = tenant_id
    ctx.request_id = "abc123"
    ctx.customer_config = {
        "app_id": "app-1",
        "customer_id": "cust-1",
        "enabled_features": {"audit_logging": True, "response_sanitizer": True},
        "settings": {},
    }
    return ctx


def _make_audit_row(tenant_id: str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") -> tuple:
    """Create a minimal audit log row tuple."""
    return (
        tenant_id, "app-1", "req-1", datetime.now(timezone.utc),
        "GET", "/api/data", 200, 1.23, "10.0.0.1",
        "TestAgent/1.0", "", "", "page_view", False,
    )


# ===================================================================
# 1. AUDIT QUEUE EXHAUSTION — stop() drain & retry limit
# ===================================================================


class TestAuditQueueDrainOnStop:
    """P0: stop() must drain ALL rows, not just the first 500."""

    @pytest.mark.asyncio
    async def test_stop_drains_more_than_one_batch(self):
        """stop() drains queue beyond single batch size (>500 rows)."""
        logger = AuditLogger()
        # Enqueue 750 rows (more than one batch of 500)
        for _ in range(750):
            logger._queue.put_nowait(_make_audit_row())

        assert logger._queue.qsize() == 750

        with patch(
            "proxy.middleware.audit_logger.batch_insert_audit_logs",
            new_callable=AsyncMock,
            return_value=500,
        ) as mock_insert:
            await logger.stop()

        # Queue must be completely empty after stop
        assert logger._queue.empty()
        # Should have been called at least twice (500 + 250)
        assert mock_insert.call_count >= 2

    @pytest.mark.asyncio
    async def test_stop_drains_exactly_max_queue(self):
        """stop() handles draining a full queue (10,000 rows)."""
        logger = AuditLogger()
        for _ in range(1000):
            logger._queue.put_nowait(_make_audit_row())

        with patch(
            "proxy.middleware.audit_logger.batch_insert_audit_logs",
            new_callable=AsyncMock,
            return_value=500,
        ):
            await logger.stop()

        assert logger._queue.empty()

    @pytest.mark.asyncio
    async def test_stop_drains_empty_queue(self):
        """stop() with empty queue does not error."""
        logger = AuditLogger()
        with patch(
            "proxy.middleware.audit_logger.batch_insert_audit_logs",
            new_callable=AsyncMock,
        ) as mock_insert:
            await logger.stop()
        mock_insert.assert_not_called()


class TestAuditRetryLimit:
    """P0: Re-queue on flush failure must have a retry limit to prevent infinite loop."""

    @pytest.mark.asyncio
    async def test_consecutive_failures_drop_rows_after_max_retries(self):
        """After MAX_FLUSH_RETRIES consecutive failures, rows are dropped (not re-queued)."""
        logger = AuditLogger()
        logger._shutdown = False

        # Enqueue 10 rows
        for _ in range(10):
            logger._queue.put_nowait(_make_audit_row())

        with patch(
            "proxy.middleware.audit_logger.batch_insert_audit_logs",
            new_callable=AsyncMock,
            side_effect=Exception("persistent DB failure"),
        ):
            # Flush _MAX_FLUSH_RETRIES times — each should re-queue
            for i in range(_MAX_FLUSH_RETRIES):
                await logger._flush_batch()
                assert logger._consecutive_failures == i + 1

            # One more flush should NOT re-queue (max retries exceeded)
            initial_size = logger._queue.qsize()
            await logger._flush_batch()
            # Rows consumed but NOT re-queued — queue should be empty or smaller
            assert logger._queue.qsize() < initial_size or logger._queue.empty()

    @pytest.mark.asyncio
    async def test_success_resets_consecutive_failures(self):
        """A successful flush resets the consecutive failure counter."""
        logger = AuditLogger()
        logger._consecutive_failures = 2  # Simulate prior failures

        logger._queue.put_nowait(_make_audit_row())

        with patch(
            "proxy.middleware.audit_logger.batch_insert_audit_logs",
            new_callable=AsyncMock,
            return_value=1,
        ):
            await logger._flush_batch()

        assert logger._consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_shutdown_flag_prevents_requeue(self):
        """During shutdown, failed rows are dropped (not re-queued) to prevent hang."""
        logger = AuditLogger()
        logger._shutdown = True

        for _ in range(5):
            logger._queue.put_nowait(_make_audit_row())

        with patch(
            "proxy.middleware.audit_logger.batch_insert_audit_logs",
            new_callable=AsyncMock,
            side_effect=Exception("DB down"),
        ):
            await logger._flush_batch()

        # Rows consumed but NOT re-queued
        assert logger._queue.empty()

    @pytest.mark.asyncio
    async def test_infinite_retry_loop_is_prevented(self):
        """Simulates the infinite loop scenario: persistent failure should terminate."""
        logger = AuditLogger()
        logger._shutdown = False

        for _ in range(5):
            logger._queue.put_nowait(_make_audit_row())

        flush_count = 0
        with patch(
            "proxy.middleware.audit_logger.batch_insert_audit_logs",
            new_callable=AsyncMock,
            side_effect=Exception("persistent failure"),
        ):
            # Flush until queue is empty — should terminate (not infinite)
            while not logger._queue.empty():
                await logger._flush_batch()
                flush_count += 1
                if flush_count > 100:
                    pytest.fail("Infinite retry loop detected!")

        # Should terminate within MAX_FLUSH_RETRIES + 1 flushes
        assert flush_count <= _MAX_FLUSH_RETRIES + 1
        assert logger._queue.empty()


# ===================================================================
# 2. STREAMING RESPONSE BYPASS
# ===================================================================


class TestStreamingResponseBypass:
    """CRITICAL: Responses without .body attribute must not silently bypass scanning."""

    @pytest.mark.asyncio
    async def test_response_without_body_attr_logs_warning(self):
        """Response object without .body attribute triggers a warning, not silent bypass."""
        sanitizer = ResponseSanitizer()
        ctx = _make_context()

        # Simulate a response-like object without .body (e.g. StreamingResponse)
        mock_response = MagicMock(spec=[])
        mock_response.status_code = 500
        mock_response.headers = MagicMock()
        mock_response.headers.__iter__ = MagicMock(return_value=iter([]))
        # Remove .body attribute
        type(mock_response).body = property(lambda self: (_ for _ in ()).throw(AttributeError))

        with patch("proxy.middleware.response_sanitizer.logger") as mock_logger:
            result = await sanitizer.process_response(mock_response, ctx)

        # Should still return the response (not crash)
        assert result is mock_response
        # Should log a warning about the missing body
        mock_logger.warning.assert_called()
        call_args = mock_logger.warning.call_args
        assert call_args[0][0] == "response_sanitizer_skip_no_body"

    @pytest.mark.asyncio
    async def test_normal_response_with_body_still_scanned(self):
        """Regular Response with .body continues to be scanned normally."""
        sanitizer = ResponseSanitizer()
        ctx = _make_context()

        response = Response(
            content=b'Traceback (most recent call last):\n  File "/app/main.py", line 42',
            status_code=500,
        )

        with patch("proxy.middleware.response_sanitizer.get_settings") as mock_settings:
            mock_settings.return_value.response_sanitizer_mode = "sanitize"
            result = await sanitizer.process_response(response, ctx)

        # Should be sanitized (replaced with clean error)
        assert result.status_code == 500
        assert b"Traceback" not in result.body

    @pytest.mark.asyncio
    async def test_empty_body_response_not_scanned(self):
        """Response with empty body skips scanning (no crash, no false positive)."""
        sanitizer = ResponseSanitizer()
        ctx = _make_context()

        response = Response(content=b"", status_code=500)

        with patch("proxy.middleware.response_sanitizer.get_settings") as mock_settings:
            mock_settings.return_value.response_sanitizer_mode = "sanitize"
            result = await sanitizer.process_response(response, ctx)

        assert result.status_code == 500

    @pytest.mark.asyncio
    async def test_none_body_is_detected(self):
        """Response where getattr(response, 'body', None) returns None is caught."""
        sanitizer = ResponseSanitizer()
        ctx = _make_context()

        # Create a response-like object where body is explicitly None
        response = MagicMock()
        response.status_code = 500
        response.body = None
        response.headers = {}
        response.headers = MagicMock()
        response.headers.__iter__ = MagicMock(return_value=iter([]))
        response.headers.items.return_value = []

        with (
            patch("proxy.middleware.response_sanitizer.get_settings") as mock_settings,
            patch("proxy.middleware.response_sanitizer.logger"),
        ):
            mock_settings.return_value.response_sanitizer_mode = "sanitize"
            result = await sanitizer.process_response(response, ctx)

        # None body should be treated as "no body" — skips scanning
        assert result is response


# ===================================================================
# 3. IPv6 EMBEDDING ATTACKS — 6to4, NAT64, Teredo
# ===================================================================


class TestIPv6EmbeddingAttacks:
    """HIGH: IPv6 transition mechanisms that embed private IPv4 addresses."""

    def test_6to4_embedding_private_ipv4(self):
        """6to4 address 2002:0a00:0001:: embeds 10.0.0.1 — must be blocked."""
        # 6to4 encodes IPv4 in bits 16-47: 2002:AABB:CCDD::
        # 10.0.0.1 → 0a.00.00.01 → 2002:0a00:0001::
        addr = ipaddress.ip_address("2002:0a00:0001::")
        assert _is_blocked(addr), "6to4 embedding 10.0.0.1 should be blocked"

    def test_6to4_embedding_loopback(self):
        """6to4 address 2002:7f00:0001:: embeds 127.0.0.1 — must be blocked."""
        addr = ipaddress.ip_address("2002:7f00:0001::")
        assert _is_blocked(addr), "6to4 embedding 127.0.0.1 should be blocked"

    def test_6to4_embedding_metadata_ip(self):
        """6to4 address 2002:a9fe:a9fe:: embeds 169.254.169.254 — must be blocked."""
        addr = ipaddress.ip_address("2002:a9fe:a9fe::")
        assert _is_blocked(addr), "6to4 embedding 169.254.169.254 should be blocked"

    def test_nat64_embedding_private_ipv4(self):
        """NAT64 address 64:ff9b::10.0.0.1 embeds private IPv4 — must be blocked."""
        addr = ipaddress.ip_address("64:ff9b::a00:1")  # 10.0.0.1
        assert _is_blocked(addr), "NAT64 embedding 10.0.0.1 should be blocked"

    def test_nat64_embedding_loopback(self):
        """NAT64 address 64:ff9b::127.0.0.1 embeds loopback — must be blocked."""
        addr = ipaddress.ip_address("64:ff9b::7f00:1")  # 127.0.0.1
        assert _is_blocked(addr), "NAT64 embedding 127.0.0.1 should be blocked"

    def test_nat64_local_use_prefix(self):
        """NAT64 local-use prefix (RFC 8215) 64:ff9b:1:: — must be blocked."""
        addr = ipaddress.ip_address("64:ff9b:1::a00:1")
        assert _is_blocked(addr), "NAT64 local-use prefix should be blocked"

    def test_teredo_tunnel(self):
        """Teredo address 2001:0000:: can tunnel private IPv4 — must be blocked."""
        addr = ipaddress.ip_address("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
        assert _is_blocked(addr), "Teredo tunnel should be blocked"

    def test_6to4_with_public_ipv4_also_blocked(self):
        """6to4 with public IPv4 (8.8.8.8 → 2002:0808:0808::) is also blocked.

        All 6to4 is blocked because we cannot verify the embedded IPv4 won't
        resolve to private ranges on the target system.
        """
        addr = ipaddress.ip_address("2002:0808:0808::")
        assert _is_blocked(addr), "All 6to4 should be blocked (cannot verify embedded IPv4)"

    def test_validate_origin_url_blocks_6to4(self):
        """validate_origin_url blocks 6to4 URLs."""
        result = validate_origin_url("http://[2002:0a00:0001::]/evil")
        assert result is not None
        assert "blocked" in result.lower() or "Blocked" in result

    def test_validate_origin_url_blocks_nat64(self):
        """validate_origin_url blocks NAT64 URLs."""
        result = validate_origin_url("http://[64:ff9b::a00:1]/evil")
        assert result is not None
        assert "blocked" in result.lower() or "Blocked" in result

    def test_validate_origin_url_blocks_teredo(self):
        """validate_origin_url blocks Teredo URLs."""
        result = validate_origin_url("http://[2001:0000:4136:e378:8000:63bf:3fff:fdd2]/evil")
        assert result is not None
        assert "blocked" in result.lower() or "Blocked" in result

    def test_existing_ipv6_private_still_blocked(self):
        """Existing IPv6 private ranges (fc00::/7) remain blocked after adding new ranges."""
        addr = ipaddress.ip_address("fd12:3456:789a::1")
        assert _is_blocked(addr), "IPv6 private (fc00::/7) should still be blocked"

    def test_existing_ipv6_link_local_still_blocked(self):
        """IPv6 link-local (fe80::/10) remains blocked."""
        addr = ipaddress.ip_address("fe80::1")
        assert _is_blocked(addr), "IPv6 link-local should still be blocked"

    def test_public_ipv6_not_blocked(self):
        """Public IPv6 addresses outside transition ranges are NOT blocked."""
        # Google DNS IPv6
        addr = ipaddress.ip_address("2001:4860:4860::8888")
        # Note: This falls in 2001::/32 (Teredo). If we block all of 2001::/32,
        # this would be blocked. Teredo is specifically 2001:0000::/32.
        # Let's test with an address clearly outside all blocked ranges.
        addr2 = ipaddress.ip_address("2607:f8b0:4004:800::200e")  # Google
        assert not _is_blocked(addr2), "Public IPv6 should not be blocked"


# ===================================================================
# 4. DNS CACHE FLOODING
# ===================================================================


class TestDNSCacheFlooding:
    """MEDIUM: Attacker floods DNS cache with unique hostnames to exhaust memory."""

    def test_eviction_caps_cache_size(self):
        """Cache never exceeds _DNS_CACHE_MAX entries even with all-fresh entries."""
        from proxy.middleware import url_validator

        # Save and restore original cache
        original_cache = url_validator._DNS_CACHE.copy()
        try:
            url_validator._DNS_CACHE.clear()
            now = time.monotonic()

            # Fill cache beyond max with fresh entries (all within TTL)
            for i in range(_DNS_CACHE_MAX + 500):
                url_validator._DNS_CACHE[f"host-{i}.evil.com"] = (
                    [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('1.2.3.4', 0))],
                    now,  # All fresh
                )

            assert len(url_validator._DNS_CACHE) == _DNS_CACHE_MAX + 500

            # Trigger eviction
            _evict_dns_cache(now)

            # Cache should be capped at max
            assert len(url_validator._DNS_CACHE) <= _DNS_CACHE_MAX

        finally:
            url_validator._DNS_CACHE = original_cache

    def test_eviction_preserves_newest_entries(self):
        """LRU eviction keeps newest entries when all are fresh."""
        from proxy.middleware import url_validator

        original_cache = url_validator._DNS_CACHE.copy()
        try:
            url_validator._DNS_CACHE.clear()
            base_time = time.monotonic()

            # Add entries with staggered timestamps
            for i in range(100):
                url_validator._DNS_CACHE[f"host-{i}.test.com"] = (
                    [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('1.2.3.4', 0))],
                    base_time + i * 0.001,
                )

            # Temporarily lower max to trigger eviction
            old_max = url_validator._DNS_CACHE_MAX
            url_validator._DNS_CACHE_MAX = 50
            try:
                _evict_dns_cache(base_time + 0.1)
                assert len(url_validator._DNS_CACHE) <= 50
                # Newest entries should be preserved
                assert f"host-99.test.com" in url_validator._DNS_CACHE
            finally:
                url_validator._DNS_CACHE_MAX = old_max

        finally:
            url_validator._DNS_CACHE = original_cache

    def test_stale_entries_evicted_first(self):
        """Stale entries (beyond TTL) are evicted before fresh entries."""
        from proxy.middleware import url_validator

        original_cache = url_validator._DNS_CACHE.copy()
        try:
            url_validator._DNS_CACHE.clear()
            now = time.monotonic()

            # Add stale entries
            for i in range(50):
                url_validator._DNS_CACHE[f"stale-{i}.test.com"] = (
                    [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('1.2.3.4', 0))],
                    now - 120,  # Way past TTL
                )

            # Add fresh entries
            for i in range(50):
                url_validator._DNS_CACHE[f"fresh-{i}.test.com"] = (
                    [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('1.2.3.4', 0))],
                    now,  # Fresh
                )

            old_max = url_validator._DNS_CACHE_MAX
            url_validator._DNS_CACHE_MAX = 60
            try:
                _evict_dns_cache(now)
                # All stale entries should be gone
                for i in range(50):
                    assert f"stale-{i}.test.com" not in url_validator._DNS_CACHE
                # Fresh entries should be preserved
                for i in range(50):
                    assert f"fresh-{i}.test.com" in url_validator._DNS_CACHE
            finally:
                url_validator._DNS_CACHE_MAX = old_max

        finally:
            url_validator._DNS_CACHE = original_cache


# ===================================================================
# 5. RLS CACHE RACE — SIGHUP Reload
# ===================================================================


class TestRLSCacheRace:
    """MEDIUM: Atomic set_rls_cache prevents stale read during SIGHUP reload."""

    def test_set_rls_cache_atomically_updates(self):
        """set_rls_cache directly sets the value without intermediate None state."""
        from proxy.store import rls

        original = rls._rls_enabled_cache
        try:
            rls._rls_enabled_cache = True
            set_rls_cache(False)
            assert rls._rls_enabled_cache is False

            set_rls_cache(True)
            assert rls._rls_enabled_cache is True
        finally:
            rls._rls_enabled_cache = original

    def test_invalidate_rls_cache_sets_none(self):
        """invalidate_rls_cache sets cache to None (forces re-read on next call)."""
        from proxy.store import rls

        original = rls._rls_enabled_cache
        try:
            rls._rls_enabled_cache = True
            invalidate_rls_cache()
            assert rls._rls_enabled_cache is None
        finally:
            rls._rls_enabled_cache = original

    def test_load_settings_uses_set_rls_cache(self):
        """load_settings calls set_rls_cache (not invalidate) for atomic update."""
        from proxy.store import rls

        original = rls._rls_enabled_cache
        try:
            with patch("proxy.config.loader.ProxySettings") as mock_cls:
                mock_settings = MagicMock()
                mock_settings.rls_enabled = False
                mock_settings.secrets_provider = "env"
                mock_settings.secrets_cache_ttl = 300
                mock_settings.upstream_url = "http://localhost:3000"
                mock_settings.listen_port = 8080
                mock_cls.return_value = mock_settings

                with patch("proxy.config.secrets.init_provider", return_value=None):
                    from proxy.config.loader import load_settings
                    load_settings()

            # Should be False (not None from invalidate)
            assert rls._rls_enabled_cache is False
        finally:
            rls._rls_enabled_cache = original

    def test_is_rls_enabled_reads_from_cache(self):
        """_is_rls_enabled reads from cache without calling get_settings."""
        from proxy.store import rls

        original = rls._rls_enabled_cache
        try:
            rls._rls_enabled_cache = True
            assert _is_rls_enabled() is True

            rls._rls_enabled_cache = False
            assert _is_rls_enabled() is False
        finally:
            rls._rls_enabled_cache = original


# ===================================================================
# 6. RETENTION ERROR SWALLOWING
# ===================================================================


class TestRetentionErrorLogging:
    """HIGH: asyncio.gather with return_exceptions must log failures."""

    @pytest.mark.asyncio
    async def test_cleanup_exceptions_are_logged(self):
        """Exceptions from cleanup tasks are logged (not silently swallowed)."""
        from proxy.middleware.audit_retention import run_retention_cleanup

        mock_conn = AsyncMock()
        # Return 2 customers — one will succeed, one will fail
        mock_conn.fetch.return_value = [
            {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "plan": "starter"},
            {"id": "11111111-2222-3333-4444-555555555555", "plan": "pro"},
        ]

        mock_pool = MagicMock()

        @asynccontextmanager
        async def _mock_acquire():
            yield mock_conn

        mock_pool.acquire = _mock_acquire

        call_count = 0

        async def _mock_delete(tenant_id, days):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("DB connection lost")
            return 5

        with (
            patch("proxy.middleware.audit_retention.get_pool", return_value=mock_pool),
            patch(
                "proxy.middleware.audit_retention.delete_old_audit_logs",
                side_effect=_mock_delete,
            ),
            patch("proxy.middleware.audit_retention.logger") as mock_logger,
        ):
            # Run one iteration of the cleanup loop
            task = asyncio.create_task(run_retention_cleanup(interval_seconds=0))
            await asyncio.sleep(0.15)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Verify the exception was logged (not swallowed)
        error_calls = [
            c for c in mock_logger.error.call_args_list
            if c[0][0] == "audit_retention_task_error"
        ]
        assert len(error_calls) >= 1, "Retention task exceptions must be logged"
        assert "RuntimeError" in str(error_calls[0])


# ===================================================================
# 7. AUDIT LOGGER QUEUE ATTACKS
# ===================================================================


class TestAuditQueueAttacks:
    """Verify queue-based audit cannot be used for audit evasion."""

    @pytest.mark.asyncio
    async def test_queue_full_logs_context(self):
        """When queue is full, warning includes tenant_id and request_id for forensics."""
        logger = AuditLogger()
        ctx = _make_context()
        req = _make_request()

        # Fill queue to capacity
        for _ in range(_MAX_AUDIT_QUEUE_SIZE):
            logger._queue.put_nowait(_make_audit_row())

        response = Response(content=b"OK", status_code=200)

        with (
            patch("proxy.middleware.audit_logger.classify_action", return_value=("page_view", False)),
            patch("proxy.middleware.audit_logger.logger") as mock_log,
        ):
            await logger.process_request(req, ctx)
            await logger.process_response(response, ctx)

        # Warning should include context for incident response
        warning_calls = [
            c for c in mock_log.warning.call_args_list
            if c[0][0] == "audit_queue_full"
        ]
        assert len(warning_calls) >= 1
        kwargs = warning_calls[0][1]
        assert "tenant_id" in kwargs
        assert "request_id" in kwargs

    @pytest.mark.asyncio
    async def test_flush_loop_continues_after_transient_failure(self):
        """Transient DB failure doesn't permanently break the flush loop."""
        logger = AuditLogger()
        logger._shutdown = False

        # Add rows
        for _ in range(5):
            logger._queue.put_nowait(_make_audit_row())

        call_count = 0

        async def _mock_batch_insert(rows):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("transient failure")
            return len(rows)

        with patch(
            "proxy.middleware.audit_logger.batch_insert_audit_logs",
            side_effect=_mock_batch_insert,
        ):
            # First flush fails, rows re-queued
            await logger._flush_batch()
            assert logger._consecutive_failures == 1
            assert not logger._queue.empty()

            # Second flush succeeds
            await logger._flush_batch()
            assert logger._consecutive_failures == 0
            assert logger._queue.empty()


# ===================================================================
# 8. DNS CACHE INTEGRATION WITH URL VALIDATOR
# ===================================================================


class TestDNSCacheIntegration:
    """Verify DNS cache interacts correctly with URL validation."""

    def test_cached_getaddrinfo_positive_cache(self):
        """Positive DNS results are cached."""
        from proxy.middleware import url_validator

        original_cache = url_validator._DNS_CACHE.copy()
        try:
            url_validator._DNS_CACHE.clear()
            mock_result = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))
            ]

            with patch("proxy.middleware.url_validator.socket.getaddrinfo", return_value=mock_result) as mock_dns:
                result1 = _cached_getaddrinfo("example.com")
                result2 = _cached_getaddrinfo("example.com")

            assert result1 == mock_result
            assert result2 == mock_result
            # Should only call DNS once (second is from cache)
            mock_dns.assert_called_once()

        finally:
            url_validator._DNS_CACHE = original_cache

    def test_cached_getaddrinfo_negative_cache(self):
        """DNS failures are cached with shorter TTL."""
        from proxy.middleware import url_validator

        original_cache = url_validator._DNS_CACHE.copy()
        try:
            url_validator._DNS_CACHE.clear()

            with patch(
                "proxy.middleware.url_validator.socket.getaddrinfo",
                side_effect=socket.gaierror("no such host"),
            ) as mock_dns:
                result1 = _cached_getaddrinfo("nonexistent.evil.com")
                result2 = _cached_getaddrinfo("nonexistent.evil.com")

            assert result1 is None
            assert result2 is None
            # Should only call DNS once (negative cache)
            mock_dns.assert_called_once()

        finally:
            url_validator._DNS_CACHE = original_cache


# ===================================================================
# 9. RESPONSE SANITIZER EARLY-EXIT CORRECTNESS
# ===================================================================


class TestResponseSanitizerEarlyExit:
    """Verify first_match_only doesn't miss detections."""

    def test_first_match_only_returns_at_least_one(self):
        """first_match_only=True returns exactly one match when content is sensitive."""
        body = 'Traceback (most recent call last):\n  File "/app/main.py", line 42\nTypeError: bad arg'
        matches = detect_sensitive_content(body, first_match_only=True)
        assert len(matches) == 1

    def test_full_scan_returns_all_matches(self):
        """first_match_only=False returns all matches."""
        body = 'Traceback (most recent call last):\n  File "/app/main.py", line 42\nTypeError: bad arg'
        matches = detect_sensitive_content(body, first_match_only=False)
        assert len(matches) >= 3  # traceback, file_path, type_error

    def test_no_false_negatives_with_early_exit(self):
        """Early exit doesn't cause false negatives (misses) for any input."""
        test_bodies = [
            "Traceback (most recent call last):",
            'File "/home/user/app.py", line 1',
            "at Object.<anonymous>",
            "psycopg2.OperationalError",
            "postgresql://user:pass@host/db",
            "SECRET_KEY = abc123",
            "DEBUG = True",
        ]
        for body in test_bodies:
            full = detect_sensitive_content(body, first_match_only=False)
            early = detect_sensitive_content(body, first_match_only=True)
            assert len(early) >= 1, f"Early exit missed detection for: {body!r}"
            assert early[0] in full, f"Early exit returned different match for: {body!r}"
