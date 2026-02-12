"""Config CRUD API and auth tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from proxy.main import app

_AUTH = {"Authorization": "Bearer test-api-key"}


@pytest.fixture
def api_client():
    """Test client for config API."""
    import proxy.main as main_module
    main_module._pipeline = None
    main_module._http_client = None
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    main_module._http_client = None
    main_module._pipeline = None


class TestAuth:
    """API key authentication tests."""

    def test_missing_auth_header(self, api_client):
        """Missing Authorization header returns 401."""
        resp = api_client.get("/api/config/customers/00000000-0000-0000-0000-000000000001")
        assert resp.status_code == 401

    def test_invalid_api_key(self, api_client):
        """Invalid API key returns 403."""
        resp = api_client.get(
            "/api/config/customers/00000000-0000-0000-0000-000000000001",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 403

    def test_valid_api_key(self, api_client):
        """Valid API key passes auth."""
        customer_id = uuid4()
        mock_customer = {
            "id": customer_id,
            "name": "Test",
            "plan": "starter",
            "settings": {},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        with patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer):
            resp = api_client.get(
                f"/api/config/customers/{customer_id}",
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 200

    def test_bearer_prefix_optional(self, api_client):
        """Bearer prefix is handled correctly."""
        customer_id = uuid4()
        mock_customer = {
            "id": customer_id,
            "name": "Test",
            "plan": "starter",
            "settings": {},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        with patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer):
            resp = api_client.get(
                f"/api/config/customers/{customer_id}",
                headers={"Authorization": "test-api-key"},
            )
        assert resp.status_code == 200


class TestCustomerCRUD:
    """Customer CRUD endpoint tests."""

    def test_create_customer(self, api_client):
        """POST /customers/ creates a customer."""
        customer_id = uuid4()
        mock_result = {
            "id": customer_id,
            "name": "Acme Corp",
            "plan": "starter",
            "settings": {},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        with patch("proxy.api.config_routes.pg_store.create_customer", new_callable=AsyncMock, return_value=mock_result):
            resp = api_client.post(
                "/api/config/customers/",
                json={"name": "Acme Corp", "api_key": "secret"},
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 201
        assert resp.json()["name"] == "Acme Corp"

    def test_get_customer_not_found(self, api_client):
        """GET /customers/{id} returns 404 for unknown ID."""
        with patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=None):
            resp = api_client.get(
                f"/api/config/customers/{uuid4()}",
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 404

    def test_update_customer(self, api_client):
        """PUT /customers/{id} updates a customer."""
        customer_id = uuid4()
        mock_result = {
            "id": customer_id,
            "name": "Updated Corp",
            "plan": "pro",
            "settings": {},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        with patch("proxy.api.config_routes.pg_store.update_customer", new_callable=AsyncMock, return_value=mock_result):
            resp = api_client.put(
                f"/api/config/customers/{customer_id}",
                json={"name": "Updated Corp", "plan": "pro"},
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated Corp"

    def test_delete_customer(self, api_client):
        """DELETE /customers/{id} returns 204."""
        with patch("proxy.api.config_routes.pg_store.delete_customer", new_callable=AsyncMock, return_value=True):
            resp = api_client.delete(
                f"/api/config/customers/{uuid4()}",
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 204

    def test_delete_customer_not_found(self, api_client):
        """DELETE /customers/{id} returns 404 for unknown."""
        with patch("proxy.api.config_routes.pg_store.delete_customer", new_callable=AsyncMock, return_value=False):
            resp = api_client.delete(
                f"/api/config/customers/{uuid4()}",
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 404


class TestAppCRUD:
    """App CRUD endpoint tests."""

    def test_create_app(self, api_client):
        """POST /customers/{id}/apps/ creates an app."""
        customer_id = uuid4()
        app_id = uuid4()
        mock_customer = {
            "id": customer_id,
            "name": "Test",
            "plan": "starter",
            "settings": {},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        mock_app = {
            "id": app_id,
            "customer_id": customer_id,
            "name": "My App",
            "origin_url": "http://myapp:3000",
            "domain": "myapp.example.com",
            "enabled_features": {"waf": True, "error_sanitization": True, "session_validation": True, "audit_logging": True},
            "settings": {},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        with (
            patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer),
            patch("proxy.api.config_routes.pg_store.create_app", new_callable=AsyncMock, return_value=mock_app),
        ):
            resp = api_client.post(
                f"/api/config/customers/{customer_id}/apps/",
                json={
                    "name": "My App",
                    "origin_url": "http://myapp:3000",
                    "domain": "myapp.example.com",
                },
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 201
        assert resp.json()["domain"] == "myapp.example.com"

    def test_get_app(self, api_client):
        """GET /apps/{id} returns app."""
        app_id = uuid4()
        mock_app = {
            "id": app_id,
            "customer_id": uuid4(),
            "name": "My App",
            "origin_url": "http://myapp:3000",
            "domain": "myapp.example.com",
            "enabled_features": {"waf": True},
            "settings": {},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        with patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=mock_app):
            resp = api_client.get(
                f"/api/config/apps/{app_id}",
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 200

    def test_delete_app(self, api_client):
        """DELETE /apps/{id} returns 204."""
        with patch("proxy.api.config_routes.pg_store.delete_app", new_callable=AsyncMock, return_value=True):
            resp = api_client.delete(
                f"/api/config/apps/{uuid4()}",
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 204

    def test_create_app_customer_not_found(self, api_client):
        """Creating app for non-existent customer returns 404."""
        with patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=None):
            resp = api_client.post(
                f"/api/config/customers/{uuid4()}/apps/",
                json={
                    "name": "My App",
                    "origin_url": "http://myapp:3000",
                    "domain": "myapp.example.com",
                },
                headers={"Authorization": "Bearer test-api-key"},
            )
        assert resp.status_code == 404


class TestAuthEdgeCases:
    """Edge cases for API key authentication."""

    def test_bearer_only_no_key(self, api_client):
        """'Bearer ' with no key returns 403."""
        resp = api_client.get(
            f"/api/config/customers/{uuid4()}",
            headers={"Authorization": "Bearer "},
        )
        assert resp.status_code == 403

    def test_bearer_case_insensitive(self, api_client):
        """'bearer' prefix is case-insensitive."""
        customer_id = uuid4()
        mock = {"id": customer_id, "name": "T", "plan": "s", "settings": {}, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
        with patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock):
            resp = api_client.get(
                f"/api/config/customers/{customer_id}",
                headers={"Authorization": "BEARER test-api-key"},
            )
        assert resp.status_code == 200

    def test_api_key_not_configured(self, api_client, monkeypatch):
        """Returns 500 when server API key is empty."""
        monkeypatch.setenv("PROXY_API_KEY", "")
        import proxy.config.loader as loader
        loader._settings = None

        resp = api_client.get(
            f"/api/config/customers/{uuid4()}",
            headers={"Authorization": "Bearer something"},
        )
        assert resp.status_code == 500

    def test_wrong_key_returns_403(self, api_client):
        """Completely wrong key returns 403, not 401."""
        resp = api_client.get(
            f"/api/config/customers/{uuid4()}",
            headers={"Authorization": "totally-wrong-key"},
        )
        assert resp.status_code == 403


class TestCustomerCRUDEdgeCases:
    """Error paths for customer CRUD."""

    def test_create_customer_db_unavailable(self, api_client):
        """Returns 503 when DB raises StoreUnavailable."""
        from proxy.store.postgres import StoreUnavailable

        with patch(
            "proxy.api.config_routes.pg_store.create_customer",
            new_callable=AsyncMock,
            side_effect=StoreUnavailable("no pool"),
        ):
            resp = api_client.post(
                "/api/config/customers/",
                json={"name": "X", "api_key": "k"},
                headers=_AUTH,
            )
        assert resp.status_code == 503

    def test_get_customer_db_unavailable(self, api_client):
        """Returns 503 when DB raises StoreUnavailable on get."""
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

    def test_update_customer_not_found(self, api_client):
        """Returns 404 when updating non-existent customer."""
        with patch("proxy.api.config_routes.pg_store.update_customer", new_callable=AsyncMock, return_value=None):
            resp = api_client.put(
                f"/api/config/customers/{uuid4()}",
                json={"name": "New Name"},
                headers=_AUTH,
            )
        assert resp.status_code == 404

    def test_update_customer_db_unavailable(self, api_client):
        """Returns 503 when DB raises StoreUnavailable on update."""
        from proxy.store.postgres import StoreUnavailable

        with patch(
            "proxy.api.config_routes.pg_store.update_customer",
            new_callable=AsyncMock,
            side_effect=StoreUnavailable("no pool"),
        ):
            resp = api_client.put(
                f"/api/config/customers/{uuid4()}",
                json={"name": "N"},
                headers=_AUTH,
            )
        assert resp.status_code == 503

    def test_update_customer_invalid_column(self, api_client):
        """Returns 422 when pg_store raises ValueError on invalid column."""
        with patch(
            "proxy.api.config_routes.pg_store.update_customer",
            new_callable=AsyncMock,
            side_effect=ValueError("Invalid column name: evil"),
        ):
            resp = api_client.put(
                f"/api/config/customers/{uuid4()}",
                json={"name": "N"},
                headers=_AUTH,
            )
        assert resp.status_code == 422

    def test_delete_customer_db_unavailable(self, api_client):
        """Returns 503 when DB raises StoreUnavailable on delete."""
        from proxy.store.postgres import StoreUnavailable

        with patch(
            "proxy.api.config_routes.pg_store.delete_customer",
            new_callable=AsyncMock,
            side_effect=StoreUnavailable("no pool"),
        ):
            resp = api_client.delete(
                f"/api/config/customers/{uuid4()}",
                headers=_AUTH,
            )
        assert resp.status_code == 503

    def test_update_customer_empty_body(self, api_client):
        """Empty update body still succeeds (no-op update)."""
        cid = uuid4()
        mock = {"id": cid, "name": "X", "plan": "s", "settings": {}, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
        with patch("proxy.api.config_routes.pg_store.update_customer", new_callable=AsyncMock, return_value=mock):
            resp = api_client.put(
                f"/api/config/customers/{cid}",
                json={},
                headers=_AUTH,
            )
        assert resp.status_code == 200


class TestAppCRUDEdgeCases:
    """Error paths for app CRUD."""

    def test_get_app_not_found(self, api_client):
        with patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=None):
            resp = api_client.get(f"/api/config/apps/{uuid4()}", headers=_AUTH)
        assert resp.status_code == 404

    def test_get_app_db_unavailable(self, api_client):
        """Returns 503 when DB raises StoreUnavailable on get_app."""
        from proxy.store.postgres import StoreUnavailable

        with patch(
            "proxy.api.config_routes.pg_store.get_app",
            new_callable=AsyncMock,
            side_effect=StoreUnavailable("no pool"),
        ):
            resp = api_client.get(f"/api/config/apps/{uuid4()}", headers=_AUTH)
        assert resp.status_code == 503

    def test_update_app(self, api_client):
        """PUT /apps/{id} updates an app."""
        aid = uuid4()
        mock = {
            "id": aid, "customer_id": uuid4(), "name": "Updated",
            "origin_url": "http://x:3000", "domain": "x.com",
            "enabled_features": {}, "settings": {},
            "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z",
        }
        with patch("proxy.api.config_routes.pg_store.update_app", new_callable=AsyncMock, return_value=mock):
            resp = api_client.put(
                f"/api/config/apps/{aid}",
                json={"name": "Updated"},
                headers=_AUTH,
            )
        assert resp.status_code == 200

    def test_update_app_not_found(self, api_client):
        with patch("proxy.api.config_routes.pg_store.update_app", new_callable=AsyncMock, return_value=None):
            resp = api_client.put(
                f"/api/config/apps/{uuid4()}",
                json={"name": "X"},
                headers=_AUTH,
            )
        assert resp.status_code == 404

    def test_update_app_invalid_column(self, api_client):
        """Returns 422 when pg_store raises ValueError on update_app."""
        with patch(
            "proxy.api.config_routes.pg_store.update_app",
            new_callable=AsyncMock,
            side_effect=ValueError("Invalid column name: evil"),
        ):
            resp = api_client.put(
                f"/api/config/apps/{uuid4()}",
                json={"name": "X"},
                headers=_AUTH,
            )
        assert resp.status_code == 422

    def test_delete_app_not_found(self, api_client):
        with patch("proxy.api.config_routes.pg_store.delete_app", new_callable=AsyncMock, return_value=False):
            resp = api_client.delete(f"/api/config/apps/{uuid4()}", headers=_AUTH)
        assert resp.status_code == 404

    def test_create_app_db_unavailable(self, api_client):
        """Returns 503 when DB raises StoreUnavailable for app creation."""
        from proxy.store.postgres import StoreUnavailable

        cid = uuid4()
        mock_cust = {"id": cid, "name": "C", "plan": "s", "settings": {}, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
        with (
            patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_cust),
            patch("proxy.api.config_routes.pg_store.create_app", new_callable=AsyncMock, side_effect=StoreUnavailable("no pool")),
        ):
            resp = api_client.post(
                f"/api/config/customers/{cid}/apps/",
                json={"name": "A", "origin_url": "https://example.com", "domain": "a.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 503

    def test_create_app_ssrf_private_ip(self, api_client):
        """Returns 422 when origin_url points to a private IP."""
        cid = uuid4()
        mock_cust = {"id": cid, "name": "C", "plan": "s", "settings": {}, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
        with patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_cust):
            resp = api_client.post(
                f"/api/config/customers/{cid}/apps/",
                json={"name": "A", "origin_url": "http://169.254.169.254/latest", "domain": "a.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 422
        assert "origin_url" in resp.json()["detail"].lower()

    def test_create_app_ssrf_localhost(self, api_client):
        """Returns 422 when origin_url is localhost."""
        cid = uuid4()
        mock_cust = {"id": cid, "name": "C", "plan": "s", "settings": {}, "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
        with patch("proxy.api.config_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_cust):
            resp = api_client.post(
                f"/api/config/customers/{cid}/apps/",
                json={"name": "A", "origin_url": "http://127.0.0.1:8080", "domain": "a.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 422

    def test_update_app_ssrf_blocked(self, api_client):
        """Returns 422 when updating origin_url to a private IP."""
        resp = api_client.put(
            f"/api/config/apps/{uuid4()}",
            json={"origin_url": "http://10.0.0.1:3000"},
            headers=_AUTH,
        )
        assert resp.status_code == 422


class TestRateLimitsEndpoint:
    """Tests for PUT /apps/{app_id}/rate-limits convenience endpoint."""

    def test_update_rate_limits(self, api_client):
        aid = uuid4()
        mock_app = {"id": aid, "settings": {}, "enabled_features": {}}
        mock_updated = {**mock_app, "settings": {"rate_limits": {"auth_max": 100}}}
        with (
            patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=mock_app),
            patch("proxy.api.config_routes.pg_store.update_app", new_callable=AsyncMock, return_value=mock_updated),
        ):
            resp = api_client.put(
                f"/api/config/apps/{aid}/rate-limits",
                json={"auth_max": 100},
                headers=_AUTH,
            )
        assert resp.status_code == 200

    def test_update_rate_limits_app_not_found(self, api_client):
        with patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=None):
            resp = api_client.put(
                f"/api/config/apps/{uuid4()}/rate-limits",
                json={"auth_max": 100},
                headers=_AUTH,
            )
        assert resp.status_code == 404

    def test_update_rate_limits_rejects_negative(self, api_client):
        resp = api_client.put(
            f"/api/config/apps/{uuid4()}/rate-limits",
            json={"auth_max": -1},
            headers=_AUTH,
        )
        assert resp.status_code == 422


class TestHeaderSettingsEndpoint:
    """Tests for PUT /apps/{app_id}/headers convenience endpoint."""

    def test_update_header_settings(self, api_client):
        aid = uuid4()
        mock_app = {"id": aid, "settings": {}}
        mock_updated = {**mock_app, "settings": {"header_preset": "strict"}}
        with (
            patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=mock_app),
            patch("proxy.api.config_routes.pg_store.update_app", new_callable=AsyncMock, return_value=mock_updated),
        ):
            resp = api_client.put(
                f"/api/config/apps/{aid}/headers",
                json={"header_preset": "strict"},
                headers=_AUTH,
            )
        assert resp.status_code == 200

    def test_update_headers_invalid_preset(self, api_client):
        resp = api_client.put(
            f"/api/config/apps/{uuid4()}/headers",
            json={"header_preset": "invalid"},
            headers=_AUTH,
        )
        assert resp.status_code == 422

    def test_update_headers_app_not_found(self, api_client):
        with patch("proxy.api.config_routes.pg_store.get_app", new_callable=AsyncMock, return_value=None):
            resp = api_client.put(
                f"/api/config/apps/{uuid4()}/headers",
                json={"header_preset": "strict"},
                headers=_AUTH,
            )
        assert resp.status_code == 404
