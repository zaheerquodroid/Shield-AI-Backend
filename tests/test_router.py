"""Multi-tenant routing tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.router import TenantRouter
from proxy.config.customer_config import CustomerConfigService


class _MockHeaders(dict):
    """Dict subclass for mock Starlette headers."""

    def get(self, key, default=None):
        return super().get(key.lower(), default)


def _make_request(host: str = "app.example.com"):
    """Create a mock request with Host header."""
    request = MagicMock()
    request.headers = _MockHeaders({"host": host})
    return request


@pytest.mark.asyncio
async def test_routes_known_domain():
    """Known domain attaches customer config to context."""
    service = CustomerConfigService()
    service._cache = {
        "app.example.com": {
            "customer_id": "cust-123",
            "origin_url": "http://customer-app:3000",
            "enabled_features": {"waf": True},
            "settings": {},
        }
    }

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        await router.process_request(_make_request("app.example.com"), context)

    assert context.tenant_id == "cust-123"
    assert context.customer_config["origin_url"] == "http://customer-app:3000"


@pytest.mark.asyncio
async def test_unknown_domain_uses_default():
    """Unknown domain gets default config."""
    service = CustomerConfigService()
    service._cache = {}

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        await router.process_request(_make_request("unknown.example.com"), context)

    assert context.customer_config["origin_url"] == "http://localhost:3000"
    assert context.tenant_id == ""


@pytest.mark.asyncio
async def test_strips_port_from_host():
    """Port is stripped from Host header for domain lookup."""
    service = CustomerConfigService()
    service._cache = {
        "app.example.com": {
            "customer_id": "cust-123",
            "origin_url": "http://app:3000",
            "enabled_features": {},
            "settings": {},
        }
    }

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        await router.process_request(_make_request("app.example.com:8080"), context)

    assert context.tenant_id == "cust-123"


@pytest.mark.asyncio
async def test_localhost_no_warning():
    """localhost requests don't trigger unknown domain warning."""
    service = CustomerConfigService()
    service._cache = {}

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        result = await router.process_request(_make_request("localhost:8080"), context)

    assert result is None  # No short-circuit


@pytest.mark.asyncio
async def test_multiple_domains_route_correctly():
    """Different domains route to different configs."""
    service = CustomerConfigService()
    service._cache = {
        "app1.example.com": {
            "customer_id": "cust-1",
            "origin_url": "http://app1:3000",
            "enabled_features": {},
            "settings": {},
        },
        "app2.example.com": {
            "customer_id": "cust-2",
            "origin_url": "http://app2:4000",
            "enabled_features": {},
            "settings": {},
        },
    }

    router = TenantRouter()

    ctx1 = RequestContext()
    ctx2 = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        await router.process_request(_make_request("app1.example.com"), ctx1)
        await router.process_request(_make_request("app2.example.com"), ctx2)

    assert ctx1.customer_config["origin_url"] == "http://app1:3000"
    assert ctx2.customer_config["origin_url"] == "http://app2:4000"
    assert ctx1.tenant_id == "cust-1"
    assert ctx2.tenant_id == "cust-2"


# --- Edge cases ---


@pytest.mark.asyncio
async def test_empty_host_header():
    """Empty Host header routes to default config."""
    service = CustomerConfigService()
    service._cache = {}

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        result = await router.process_request(_make_request(""), context)

    assert result is None
    assert context.customer_config["origin_url"] == "http://localhost:3000"
    assert context.tenant_id == ""


@pytest.mark.asyncio
async def test_ip_address_host():
    """IP address host routes to default config."""
    service = CustomerConfigService()
    service._cache = {}

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        result = await router.process_request(_make_request("192.168.1.1:8080"), context)

    assert result is None
    # IP address should use default config


@pytest.mark.asyncio
async def test_127_0_0_1_no_warning():
    """127.0.0.1 requests don't trigger unknown domain warning."""
    service = CustomerConfigService()
    service._cache = {}

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        result = await router.process_request(_make_request("127.0.0.1:8080"), context)

    assert result is None


@pytest.mark.asyncio
async def test_ipv6_host_with_port():
    """IPv6 host [::1]:8080 — colon split takes first part which is bracket."""
    service = CustomerConfigService()
    service._cache = {}

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        # [::1]:8080 will split on first colon to "[", which won't match
        result = await router.process_request(_make_request("[::1]:8080"), context)

    assert result is None
    # Should not crash, just use default config


# --- SSRF validation ---


@pytest.mark.asyncio
async def test_ssrf_blocked_for_customer_config():
    """Customer config with private IP origin_url returns 502."""
    service = CustomerConfigService()
    service._cache = {
        "evil.example.com": {
            "customer_id": "cust-evil",
            "origin_url": "http://169.254.169.254/latest/meta-data/",
            "enabled_features": {},
            "settings": {},
        }
    }

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        result = await router.process_request(_make_request("evil.example.com"), context)

    assert result is not None
    assert result.status_code == 502


@pytest.mark.asyncio
async def test_ssrf_not_checked_for_default_config():
    """Default config (localhost) should not trigger SSRF validation."""
    service = CustomerConfigService()
    service._cache = {}

    router = TenantRouter()
    context = RequestContext()

    with patch("proxy.middleware.router.get_config_service", return_value=service):
        result = await router.process_request(_make_request("unknown.example.com"), context)

    # Default config uses localhost — should NOT be blocked
    assert result is None
