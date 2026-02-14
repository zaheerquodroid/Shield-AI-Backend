"""Config loading and customer config tests."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from proxy.config.loader import ProxySettings, load_settings
from proxy.config.customer_config import CustomerConfigService


class TestProxySettings:
    """Test YAML + env var config loading."""

    def test_default_values(self, monkeypatch):
        """Settings have sensible defaults."""
        # Clear env vars that conftest sets, so we test true defaults
        for key in list(os.environ):
            if key.startswith("PROXY_"):
                monkeypatch.delenv(key, raising=False)
        settings = ProxySettings()
        assert settings.listen_port == 8080
        assert settings.log_level == "info"
        assert settings.redis_pool_size == 10
        assert settings.proxy_timeout == 30.0

    def test_env_override(self, monkeypatch):
        """Environment variables override defaults."""
        monkeypatch.setenv("PROXY_LISTEN_PORT", "9090")
        monkeypatch.setenv("PROXY_LOG_LEVEL", "debug")
        settings = ProxySettings()
        assert settings.listen_port == 9090
        assert settings.log_level == "debug"

    def test_upstream_url_from_env(self, monkeypatch):
        """PROXY_UPSTREAM_URL overrides default upstream."""
        monkeypatch.setenv("PROXY_UPSTREAM_URL", "http://my-app:5000")
        settings = ProxySettings()
        assert settings.upstream_url == "http://my-app:5000"

    def test_load_settings_returns_instance(self):
        """load_settings returns a ProxySettings instance."""
        settings = load_settings()
        assert isinstance(settings, ProxySettings)


class TestCustomerConfigService:
    """Test multi-tenant config service."""

    @pytest.mark.asyncio
    async def test_load_all_populates_cache(self):
        """load_all builds domain->config map."""
        service = CustomerConfigService()
        mock_apps = [
            {
                "id": "app-1",
                "customer_id": "cust-1",
                "domain": "app1.example.com",
                "origin_url": "http://app1:3000",
                "enabled_features": {"waf": True},
                "settings": {},
            },
            {
                "id": "app-2",
                "customer_id": "cust-2",
                "domain": "app2.example.com",
                "origin_url": "http://app2:3000",
                "enabled_features": {"waf": False},
                "settings": {},
            },
        ]
        with patch("proxy.config.customer_config.pg_store.get_all_apps", new_callable=AsyncMock, return_value=mock_apps):
            await service.load_all()

        config1 = service.get_config("app1.example.com")
        assert config1["origin_url"] == "http://app1:3000"
        assert config1["customer_id"] == "cust-1"

        config2 = service.get_config("app2.example.com")
        assert config2["origin_url"] == "http://app2:3000"

    def test_get_config_returns_default_for_unknown(self):
        """Unknown domains get default config."""
        service = CustomerConfigService()
        config = service.get_config("unknown.example.com")
        assert config["origin_url"] == "http://localhost:3000"
        assert config["enabled_features"]["waf"] is True

    def test_cache_staleness(self):
        """Cache is stale after TTL expires."""
        service = CustomerConfigService(cache_ttl=0)
        assert service.is_stale()

    @pytest.mark.asyncio
    async def test_load_all_handles_json_string_features(self):
        """JSON string enabled_features are parsed correctly."""
        service = CustomerConfigService()
        mock_apps = [
            {
                "id": "app-1",
                "customer_id": "cust-1",
                "domain": "test.example.com",
                "origin_url": "http://test:3000",
                "enabled_features": '{"waf": true}',
                "settings": {},
            },
        ]
        with patch("proxy.config.customer_config.pg_store.get_all_apps", new_callable=AsyncMock, return_value=mock_apps):
            await service.load_all()

        config = service.get_config("test.example.com")
        assert config["enabled_features"]["waf"] is True


class TestProxySettingsNewFields:
    """Test Sprint 2 settings additions."""

    def test_rate_limit_defaults(self, monkeypatch):
        for key in list(os.environ):
            if key.startswith("PROXY_"):
                monkeypatch.delenv(key, raising=False)
        settings = ProxySettings()
        assert settings.rate_limit_auth_max == 500
        assert settings.rate_limit_global_max == 2000
        assert settings.rate_limit_window_seconds == 300
        assert settings.header_preset == "balanced"

    def test_rate_limit_env_override(self, monkeypatch):
        monkeypatch.setenv("PROXY_RATE_LIMIT_AUTH_MAX", "100")
        monkeypatch.setenv("PROXY_RATE_LIMIT_GLOBAL_MAX", "500")
        settings = ProxySettings()
        assert settings.rate_limit_auth_max == 100
        assert settings.rate_limit_global_max == 500

    def test_header_preset_env_override(self, monkeypatch):
        monkeypatch.setenv("PROXY_HEADER_PRESET", "strict")
        settings = ProxySettings()
        assert settings.header_preset == "strict"

    def test_max_body_bytes_default(self, monkeypatch):
        for key in list(os.environ):
            if key.startswith("PROXY_"):
                monkeypatch.delenv(key, raising=False)
        settings = ProxySettings()
        assert settings.max_body_bytes == 10 * 1024 * 1024  # 10MB

    def test_http_client_settings_defaults(self, monkeypatch):
        for key in list(os.environ):
            if key.startswith("PROXY_"):
                monkeypatch.delenv(key, raising=False)
        settings = ProxySettings()
        assert settings.upstream_max_connections == 100
        assert settings.upstream_max_keepalive == 20
        assert settings.upstream_follow_redirects is False


class TestCustomerConfigEdgeCases:
    """Edge cases for customer config service."""

    @pytest.mark.asyncio
    async def test_load_all_empty_apps(self):
        """Empty app list results in empty cache."""
        service = CustomerConfigService()
        with patch("proxy.config.customer_config.pg_store.get_all_apps", new_callable=AsyncMock, return_value=[]):
            await service.load_all()
        config = service.get_config("any.domain.com")
        assert config["origin_url"] == "http://localhost:3000"

    @pytest.mark.asyncio
    async def test_load_all_missing_settings_key(self):
        """Apps with missing settings key default to empty dict."""
        service = CustomerConfigService()
        mock_apps = [
            {
                "id": "app-1", "customer_id": "cust-1",
                "domain": "x.com", "origin_url": "http://x:3000",
                "enabled_features": {},
            },
        ]
        with patch("proxy.config.customer_config.pg_store.get_all_apps", new_callable=AsyncMock, return_value=mock_apps):
            await service.load_all()
        config = service.get_config("x.com")
        assert config["settings"] == {}

    @pytest.mark.asyncio
    async def test_load_all_overwrites_stale_cache(self):
        """Second load_all replaces old cache."""
        service = CustomerConfigService()
        apps_v1 = [{"id": "1", "customer_id": "c1", "domain": "a.com", "origin_url": "http://old:3000", "enabled_features": {}, "settings": {}}]
        apps_v2 = [{"id": "1", "customer_id": "c1", "domain": "a.com", "origin_url": "http://new:3000", "enabled_features": {}, "settings": {}}]

        with patch("proxy.config.customer_config.pg_store.get_all_apps", new_callable=AsyncMock, return_value=apps_v1):
            await service.load_all()
        assert service.get_config("a.com")["origin_url"] == "http://old:3000"

        with patch("proxy.config.customer_config.pg_store.get_all_apps", new_callable=AsyncMock, return_value=apps_v2):
            await service.load_all()
        assert service.get_config("a.com")["origin_url"] == "http://new:3000"

    def test_default_config_includes_new_features(self):
        """Default config should include Sprint 2 feature flags."""
        service = CustomerConfigService()
        config = service.get_config("unknown.example.com")
        assert config["enabled_features"]["rate_limiting"] is True
        assert config["enabled_features"]["security_headers"] is True
        assert config["enabled_features"]["bot_protection"] is False

    @pytest.mark.asyncio
    async def test_stop_polling_when_not_started(self):
        """stop_polling is safe to call without start_polling."""
        service = CustomerConfigService()
        await service.stop_polling()  # should not raise

    def test_cache_not_stale_immediately_after_load(self):
        """After a load, cache should not be stale for positive TTL."""
        service = CustomerConfigService(cache_ttl=60)
        import time
        service._cache_time = time.monotonic()
        assert not service.is_stale()

    def test_default_config_immutable(self):
        """Default config is immutable (MappingProxyType prevents mutation)."""
        service = CustomerConfigService()
        config = service.get_config("unknown-1.com")
        # Attempting to mutate raises TypeError
        with pytest.raises(TypeError):
            config["enabled_features"]["waf"] = False
        with pytest.raises(TypeError):
            config["settings"]["injected"] = "evil"
        # Values remain correct
        assert config["enabled_features"]["waf"] is True
        assert config["settings"] == {}
