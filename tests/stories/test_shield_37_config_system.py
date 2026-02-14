"""SHIELD-37 — Build multi-tenant customer configuration system.

Acceptance Criteria:
  AC1: Customer configuration stored in PostgreSQL with JSON settings.
  AC2: Config CRUD API endpoints protected by API key authentication.
  AC3: Multi-tenant request routing: proxy identifies customer by Host header,
       loads correct config, attaches to request context.
  AC4: Fallback to default configuration if customer-specific config not found.
  AC5: Default config: all features enabled, standard timeouts, standard rate limits.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from proxy.config.customer_config import CustomerConfigService, _DEFAULT_CONFIG
from proxy.middleware.pipeline import RequestContext
from proxy.middleware.router import TenantRouter


_AUTH = {"Authorization": "Bearer test-api-key"}


class _MockHeaders(dict):
    """Dict subclass that allows attribute assignment (dict .get is read-only)."""
    pass


def _make_router_request(host: str) -> MagicMock:
    """Build a mock request with a Host header for router tests."""
    req = MagicMock()
    req.headers = _MockHeaders({"host": host})
    return req


@pytest.fixture
def api_client():
    """TestClient with lifespan for API tests."""
    import proxy.main as main_module
    main_module._pipeline = None
    main_module._http_client = None

    from proxy.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# AC1: Customer configuration stored in PostgreSQL with JSON settings
# ---------------------------------------------------------------------------


class TestAC1_PostgreSQLStorage:
    """Customer and app configs are stored in PostgreSQL with JSONB settings."""

    def test_create_customer_stores_settings(self, api_client):
        """POST /api/config/customers/ stores customer with settings."""
        mock_result = {
            "id": str(uuid4()),
            "name": "Acme Corp",
            "plan": "enterprise",
            "settings": {"theme": "dark"},
        }
        with patch(
            "proxy.api.config_routes.pg_store.create_customer",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            resp = api_client.post(
                "/api/config/customers/",
                json={"name": "Acme Corp", "api_key": "secret", "plan": "enterprise", "settings": {"theme": "dark"}},
                headers=_AUTH,
            )
        assert resp.status_code == 201
        assert resp.json()["settings"] == {"theme": "dark"}

    def test_create_app_stores_enabled_features_and_settings(self, api_client):
        """POST /api/config/customers/{id}/apps/ stores app with enabled_features JSONB."""
        cid = uuid4()
        mock_customer = {"id": str(cid), "name": "Acme"}
        mock_app = {
            "id": str(uuid4()),
            "customer_id": str(cid),
            "name": "My App",
            "origin_url": "https://example.com",
            "domain": "example.com",
            "enabled_features": {"waf": True, "rate_limiting": False},
            "settings": {},
        }
        with (
            patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer),
            patch("proxy.api.config_routes.pg_store.create_app", new_callable=AsyncMock, return_value=mock_app),
        ):
            resp = api_client.post(
                f"/api/config/customers/{cid}/apps/",
                json={
                    "name": "My App",
                    "origin_url": "https://example.com",
                    "domain": "example.com",
                    "enabled_features": {"waf": True, "rate_limiting": False},
                },
                headers=_AUTH,
            )
        assert resp.status_code == 201
        assert resp.json()["enabled_features"]["rate_limiting"] is False

    def test_update_app_settings_json(self, api_client):
        """PUT /api/config/apps/{id} updates settings JSONB."""
        aid = uuid4()
        mock_result = {"id": str(aid), "settings": {"rate_limits": {"auth_max": 100}}}
        with patch(
            "proxy.api.config_routes.pg_store.update_app",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            resp = api_client.put(
                f"/api/config/apps/{aid}",
                json={"settings": {"rate_limits": {"auth_max": 100}}},
                headers=_AUTH,
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# AC2: Config CRUD API protected by API key authentication
# ---------------------------------------------------------------------------


class TestAC2_APIKeyAuth:
    """Config API endpoints are protected by API key."""

    def test_no_auth_returns_401(self, api_client):
        """Request without Authorization header returns 401."""
        resp = api_client.get(f"/api/config/customers/{uuid4()}")
        assert resp.status_code == 401

    def test_wrong_key_returns_403(self, api_client):
        """Request with wrong API key returns 403."""
        resp = api_client.get(
            f"/api/config/customers/{uuid4()}",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 403

    def test_valid_key_allows_access(self, api_client):
        """Request with correct API key is allowed."""
        mock_customer = {"id": str(uuid4()), "name": "Acme", "plan": "starter"}
        with patch(
            "proxy.api.config_routes.pg_store.get_customer",
            new_callable=AsyncMock,
            return_value=mock_customer,
        ):
            resp = api_client.get(
                f"/api/config/customers/{mock_customer['id']}",
                headers=_AUTH,
            )
        assert resp.status_code == 200

    def test_bearer_prefix_case_insensitive(self, api_client):
        """Bearer prefix works case-insensitively."""
        mock_customer = {"id": str(uuid4()), "name": "Acme", "plan": "starter"}
        with patch(
            "proxy.api.config_routes.pg_store.get_customer",
            new_callable=AsyncMock,
            return_value=mock_customer,
        ):
            resp = api_client.get(
                f"/api/config/customers/{mock_customer['id']}",
                headers={"Authorization": "bearer test-api-key"},
            )
        assert resp.status_code == 200

    def test_crud_create_read_update_delete(self, api_client):
        """Full CRUD lifecycle for customers."""
        cid = uuid4()
        mock_customer = {"id": str(cid), "name": "Acme", "plan": "starter", "settings": {}}
        mock_updated = {**mock_customer, "name": "Acme v2"}

        # Create
        with patch("proxy.api.config_routes.pg_store.create_customer", new_callable=AsyncMock, return_value=mock_customer):
            resp = api_client.post("/api/config/customers/", json={"name": "Acme", "api_key": "k"}, headers=_AUTH)
        assert resp.status_code == 201

        # Read
        with patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer):
            resp = api_client.get(f"/api/config/customers/{cid}", headers=_AUTH)
        assert resp.status_code == 200

        # Update
        with patch("proxy.api.config_routes.pg_store.update_customer", new_callable=AsyncMock, return_value=mock_updated):
            resp = api_client.put(f"/api/config/customers/{cid}", json={"name": "Acme v2"}, headers=_AUTH)
        assert resp.status_code == 200
        assert resp.json()["name"] == "Acme v2"

        # Delete
        with patch("proxy.api.config_routes.pg_store.delete_customer", new_callable=AsyncMock, return_value=True):
            resp = api_client.delete(f"/api/config/customers/{cid}", headers=_AUTH)
        assert resp.status_code == 204


# ---------------------------------------------------------------------------
# AC3: Multi-tenant request routing by Host header
# ---------------------------------------------------------------------------


class TestAC3_MultiTenantRouting:
    """Proxy identifies customer by Host header and loads correct config."""

    @pytest.mark.asyncio
    async def test_known_domain_loads_customer_config(self):
        """Known domain resolves to customer config."""
        service = CustomerConfigService()
        service._cache = {
            "app.example.com": {
                "customer_id": "cust-123",
                "origin_url": "https://backend.example.com",
                "enabled_features": {"waf": True},
                "settings": {},
            }
        }
        service._cache_time = 999999999999.0

        router = TenantRouter()
        ctx = RequestContext()
        req = _make_router_request("app.example.com")

        with patch("proxy.middleware.router.get_config_service", return_value=service):
            with patch("proxy.middleware.router.validate_origin_url", return_value=None):
                await router.process_request(req, ctx)

        assert ctx.tenant_id == "cust-123"
        assert ctx.customer_config["origin_url"] == "https://backend.example.com"

    @pytest.mark.asyncio
    async def test_host_with_port_is_stripped(self):
        """Host header with port is handled correctly (port stripped for lookup)."""
        service = CustomerConfigService()
        service._cache = {
            "app.example.com": {
                "customer_id": "cust-456",
                "origin_url": "https://backend.example.com",
                "enabled_features": {},
                "settings": {},
            }
        }
        service._cache_time = 999999999999.0

        router = TenantRouter()
        ctx = RequestContext()
        req = _make_router_request("app.example.com:8080")

        with patch("proxy.middleware.router.get_config_service", return_value=service):
            with patch("proxy.middleware.router.validate_origin_url", return_value=None):
                await router.process_request(req, ctx)

        assert ctx.tenant_id == "cust-456"

    @pytest.mark.asyncio
    async def test_different_domains_different_configs(self):
        """Different Host headers route to different customer configs."""
        service = CustomerConfigService()
        service._cache = {
            "alpha.com": {"customer_id": "cust-a", "origin_url": "https://a.internal", "enabled_features": {}, "settings": {}},
            "beta.com": {"customer_id": "cust-b", "origin_url": "https://b.internal", "enabled_features": {}, "settings": {}},
        }
        service._cache_time = 999999999999.0
        router = TenantRouter()

        with patch("proxy.middleware.router.get_config_service", return_value=service):
            with patch("proxy.middleware.router.validate_origin_url", return_value=None):
                ctx_a = RequestContext()
                req_a = _make_router_request("alpha.com")
                await router.process_request(req_a, ctx_a)

                ctx_b = RequestContext()
                req_b = _make_router_request("beta.com")
                await router.process_request(req_b, ctx_b)

        assert ctx_a.tenant_id == "cust-a"
        assert ctx_b.tenant_id == "cust-b"
        assert ctx_a.customer_config["origin_url"] != ctx_b.customer_config["origin_url"]


# ---------------------------------------------------------------------------
# AC4: Fallback to default configuration
# ---------------------------------------------------------------------------


class TestAC4_DefaultFallback:
    """Proxy uses default config when customer-specific config not found."""

    @pytest.mark.asyncio
    async def test_unknown_domain_gets_default(self):
        """Unknown domain falls back to default config."""
        service = CustomerConfigService()
        service._cache = {}  # empty — no known domains
        service._cache_time = 999999999999.0

        router = TenantRouter()
        ctx = RequestContext()
        req = _make_router_request("unknown.com")

        with patch("proxy.middleware.router.get_config_service", return_value=service):
            await router.process_request(req, ctx)

        # Default config should be applied (no customer_id)
        assert "customer_id" not in ctx.customer_config
        assert ctx.customer_config["origin_url"] == "http://localhost:3000"

    def test_config_service_returns_default_for_miss(self):
        """CustomerConfigService.get_config returns defaults for unknown domain."""
        service = CustomerConfigService()
        config = service.get_config("nonexistent.com")
        assert config == _DEFAULT_CONFIG
        assert config["origin_url"] == "http://localhost:3000"


# ---------------------------------------------------------------------------
# AC5: Default config — all features enabled
# ---------------------------------------------------------------------------


class TestAC5_DefaultConfig:
    """Default config has all security features enabled."""

    def test_default_features_all_enabled(self):
        """Default config has waf, error_sanitization, session_validation, audit_logging, rate_limiting, security_headers all True."""
        features = _DEFAULT_CONFIG["enabled_features"]
        assert features["waf"] is True
        assert features["error_sanitization"] is True
        assert features["session_validation"] is True
        assert features["audit_logging"] is True
        assert features["rate_limiting"] is True
        assert features["security_headers"] is True

    def test_bot_protection_off_by_default(self):
        """Bot protection is disabled by default (premium feature)."""
        features = _DEFAULT_CONFIG["enabled_features"]
        assert features["bot_protection"] is False

    def test_default_settings_empty(self):
        """Default settings dict is empty (no customer overrides)."""
        assert _DEFAULT_CONFIG["settings"] == {}

    def test_default_origin_url(self):
        """Default origin URL is localhost:3000."""
        assert _DEFAULT_CONFIG["origin_url"] == "http://localhost:3000"

    def test_default_config_is_immutable(self):
        """Default config is immutable (MappingProxyType prevents mutation)."""
        service = CustomerConfigService()
        config = service.get_config("unknown1.com")
        with pytest.raises(TypeError):
            config["origin_url"] = "http://mutated"
        assert config["origin_url"] == "http://localhost:3000"

    def test_database_unavailable_returns_503(self, api_client):
        """API returns 503 when PostgreSQL is unavailable."""
        from proxy.store.postgres import StoreUnavailable

        with patch(
            "proxy.api.config_routes.pg_store.get_customer",
            new_callable=AsyncMock,
            side_effect=StoreUnavailable("no pool"),
        ):
            resp = api_client.get(
                f"/api/config/customers/{uuid4()}",
                headers=_AUTH,
            )
        assert resp.status_code == 503
