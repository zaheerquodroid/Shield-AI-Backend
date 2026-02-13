"""Unit tests for proxy.config.secrets module."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from proxy.config.secrets import (
    SETTINGS_FIELD_MAP,
    AwsSecretsBackend,
    EnvSecretsBackend,
    GcpSecretsBackend,
    SecretsProvider,
    VaultSecretsBackend,
    _SecretsCache,
    create_backend,
    create_provider,
    get_provider,
    init_provider,
    resolve_settings,
)


# ---------------------------------------------------------------------------
# TestSecretsCache
# ---------------------------------------------------------------------------

class TestSecretsCache:
    def test_new_cache_is_stale(self):
        cache = _SecretsCache(ttl=60)
        assert cache.is_stale is True

    def test_set_all_makes_fresh(self):
        cache = _SecretsCache(ttl=60)
        cache.set_all({"a": "1"})
        assert cache.is_stale is False

    def test_stale_after_ttl(self):
        cache = _SecretsCache(ttl=60)
        cache.set_all({"a": "1"})
        cache._ts = time.monotonic() - 61
        assert cache.is_stale is True

    def test_get_returns_value(self):
        cache = _SecretsCache(ttl=60)
        cache.set_all({"key": "val"})
        assert cache.get("key") == "val"

    def test_get_missing_returns_none(self):
        cache = _SecretsCache(ttl=60)
        cache.set_all({"key": "val"})
        assert cache.get("other") is None

    def test_get_all_returns_copy(self):
        cache = _SecretsCache(ttl=60)
        cache.set_all({"a": "1", "b": "2"})
        result = cache.get_all()
        assert result == {"a": "1", "b": "2"}
        result["c"] = "3"
        assert cache.get("c") is None

    def test_clear(self):
        cache = _SecretsCache(ttl=60)
        cache.set_all({"a": "1"})
        cache.clear()
        assert cache.is_stale is True
        assert cache.get_all() == {}

    def test_ttl_clamped_minimum(self):
        cache = _SecretsCache(ttl=10)
        assert cache.ttl == 60

    def test_ttl_clamped_maximum(self):
        cache = _SecretsCache(ttl=9999)
        assert cache.ttl == 3600

    def test_ttl_within_range(self):
        cache = _SecretsCache(ttl=300)
        assert cache.ttl == 300


# ---------------------------------------------------------------------------
# TestEnvSecretsBackend
# ---------------------------------------------------------------------------

class TestEnvSecretsBackend:
    def test_returns_empty_dict(self):
        backend = EnvSecretsBackend()
        assert backend.fetch_secrets() == {}

    def test_name(self):
        backend = EnvSecretsBackend()
        assert backend.name() == "env"


# ---------------------------------------------------------------------------
# TestAwsSecretsBackend
# ---------------------------------------------------------------------------

class TestAwsSecretsBackend:
    def test_parses_json_secret(self):
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"redis_url": "redis://prod:6379", "api_key": "secret123"}),
        }
        backend._client = mock_client
        result = backend.fetch_secrets()
        assert result == {"redis_url": "redis://prod:6379", "api_key": "secret123"}

    def test_rejects_non_dict(self):
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps(["not", "a", "dict"]),
        }
        backend._client = mock_client
        with pytest.raises(ValueError, match="JSON object"):
            backend.fetch_secrets()

    def test_import_error_message(self):
        backend = AwsSecretsBackend(secret_id="test/secret")
        with patch.dict("sys.modules", {"boto3": None}):
            with pytest.raises(RuntimeError, match="boto3 is required"):
                backend._client = None
                backend._get_client()

    def test_api_error_propagates(self):
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = Exception("AccessDenied")
        backend._client = mock_client
        with pytest.raises(Exception, match="AccessDenied"):
            backend.fetch_secrets()

    def test_values_converted_to_strings(self):
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"port": 6379, "enabled": True}),
        }
        backend._client = mock_client
        result = backend.fetch_secrets()
        assert result == {"port": "6379", "enabled": "True"}

    def test_null_values_filtered(self):
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"redis_url": "redis://ok:6379", "api_key": None}),
        }
        backend._client = mock_client
        result = backend.fetch_secrets()
        assert result == {"redis_url": "redis://ok:6379"}
        assert "api_key" not in result

    def test_name(self):
        backend = AwsSecretsBackend(secret_id="x")
        assert backend.name() == "aws"

    def test_region_passed_to_client(self):
        backend = AwsSecretsBackend(secret_id="x", region="eu-west-1")
        assert backend._region == "eu-west-1"


# ---------------------------------------------------------------------------
# TestGcpSecretsBackend
# ---------------------------------------------------------------------------

class TestGcpSecretsBackend:
    def test_parses_payload(self):
        backend = GcpSecretsBackend(project_id="proj", secret_id="sec")
        mock_client = MagicMock()
        payload_data = json.dumps({"redis_url": "redis://gcp:6379"}).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.payload.data = payload_data
        mock_client.access_secret_version.return_value = mock_resp
        backend._client = mock_client
        result = backend.fetch_secrets()
        assert result == {"redis_url": "redis://gcp:6379"}

    def test_rejects_non_dict(self):
        backend = GcpSecretsBackend(project_id="proj", secret_id="sec")
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.payload.data = json.dumps("just a string").encode("utf-8")
        mock_client.access_secret_version.return_value = mock_resp
        backend._client = mock_client
        with pytest.raises(ValueError, match="JSON object"):
            backend.fetch_secrets()

    def test_import_error_message(self):
        backend = GcpSecretsBackend(project_id="proj", secret_id="sec")
        with patch.dict("sys.modules", {"google": None, "google.cloud": None, "google.cloud.secretmanager": None}):
            with pytest.raises(RuntimeError, match="google-cloud-secret-manager is required"):
                backend._client = None
                backend._get_client()

    def test_null_values_filtered(self):
        backend = GcpSecretsBackend(project_id="proj", secret_id="sec")
        mock_client = MagicMock()
        payload = json.dumps({"redis_url": "redis://ok:6379", "api_key": None}).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.payload.data = payload
        mock_client.access_secret_version.return_value = mock_resp
        backend._client = mock_client
        result = backend.fetch_secrets()
        assert result == {"redis_url": "redis://ok:6379"}
        assert "api_key" not in result

    def test_name(self):
        backend = GcpSecretsBackend(project_id="p", secret_id="s")
        assert backend.name() == "gcp"

    def test_version_default(self):
        backend = GcpSecretsBackend(project_id="p", secret_id="s")
        assert backend._version == "latest"


# ---------------------------------------------------------------------------
# TestVaultSecretsBackend
# ---------------------------------------------------------------------------

class TestVaultSecretsBackend:
    def test_reads_kv_v2(self):
        backend = VaultSecretsBackend(url="http://vault:8200", path="proxy/config")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"redis_url": "redis://vault:6379", "api_key": "vault-key"}},
        }
        backend._client = mock_client
        result = backend.fetch_secrets()
        assert result == {"redis_url": "redis://vault:6379", "api_key": "vault-key"}

    def test_import_error_message(self):
        backend = VaultSecretsBackend(url="http://vault:8200", path="proxy/config")
        with patch.dict("sys.modules", {"hvac": None}):
            with pytest.raises(RuntimeError, match="hvac is required"):
                backend._client = None
                backend._get_client()

    def test_custom_mount_point(self):
        backend = VaultSecretsBackend(
            url="http://vault:8200", path="proxy/config", mount_point="kv"
        )
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"api_key": "k"}},
        }
        backend._client = mock_client
        backend.fetch_secrets()
        mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path="proxy/config", mount_point="kv"
        )

    def test_rejects_non_dict(self):
        backend = VaultSecretsBackend(url="http://vault:8200", path="proxy/config")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": ["not", "a", "dict"]},
        }
        backend._client = mock_client
        with pytest.raises(ValueError, match="must be a dict"):
            backend.fetch_secrets()

    def test_null_values_filtered(self):
        backend = VaultSecretsBackend(url="http://vault:8200", path="proxy/config")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"redis_url": "redis://ok:6379", "api_key": None}},
        }
        backend._client = mock_client
        result = backend.fetch_secrets()
        assert result == {"redis_url": "redis://ok:6379"}
        assert "api_key" not in result

    def test_name(self):
        backend = VaultSecretsBackend(url="http://v:8200", path="p")
        assert backend.name() == "vault"


# ---------------------------------------------------------------------------
# TestSecretsProvider
# ---------------------------------------------------------------------------

class TestSecretsProvider:
    def test_refresh_when_stale(self):
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"redis_url": "redis://new:6379"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        result = provider.get_all()
        backend.fetch_secrets.assert_called_once()
        assert result == {"redis_url": "redis://new:6379"}

    def test_cache_when_fresh(self):
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"a": "1"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        backend.fetch_secrets.reset_mock()
        result = provider.get_all()
        backend.fetch_secrets.assert_not_called()
        assert result == {"a": "1"}

    def test_stale_cache_on_failure(self):
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"a": "original"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()

        backend.fetch_secrets.side_effect = Exception("network error")
        provider._cache._ts = time.monotonic() - 61
        result = provider.get_all()
        assert result == {"a": "original"}

    def test_get_secret(self):
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"a": "1", "b": "2"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        assert provider.get_secret("a") == "1"
        assert provider.get_secret("b") == "2"
        assert provider.get_secret("c") is None


# ---------------------------------------------------------------------------
# TestCreateBackend
# ---------------------------------------------------------------------------

class TestCreateBackend:
    def test_env_backend(self):
        backend = create_backend("env")
        assert isinstance(backend, EnvSecretsBackend)

    def test_aws_backend(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "my/secret")
        backend = create_backend("aws")
        assert isinstance(backend, AwsSecretsBackend)

    def test_gcp_backend(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_GCP_PROJECT_ID", "proj")
        monkeypatch.setenv("PROXY_SECRETS_GCP_SECRET_ID", "sec")
        backend = create_backend("gcp")
        assert isinstance(backend, GcpSecretsBackend)

    def test_vault_backend(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_VAULT_URL", "http://vault:8200")
        monkeypatch.setenv("PROXY_SECRETS_VAULT_PATH", "proxy/config")
        backend = create_backend("vault")
        assert isinstance(backend, VaultSecretsBackend)

    def test_aws_missing_config_raises(self, monkeypatch):
        monkeypatch.delenv("PROXY_SECRETS_AWS_SECRET_ID", raising=False)
        with pytest.raises(ValueError, match="PROXY_SECRETS_AWS_SECRET_ID"):
            create_backend("aws")

    def test_gcp_missing_config_raises(self, monkeypatch):
        monkeypatch.delenv("PROXY_SECRETS_GCP_PROJECT_ID", raising=False)
        monkeypatch.delenv("PROXY_SECRETS_GCP_SECRET_ID", raising=False)
        with pytest.raises(ValueError, match="PROXY_SECRETS_GCP_PROJECT_ID"):
            create_backend("gcp")

    def test_vault_missing_config_raises(self, monkeypatch):
        monkeypatch.delenv("PROXY_SECRETS_VAULT_URL", raising=False)
        monkeypatch.delenv("PROXY_SECRETS_VAULT_PATH", raising=False)
        with pytest.raises(ValueError, match="PROXY_SECRETS_VAULT_URL"):
            create_backend("vault")

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown secrets provider"):
            create_backend("oracle")


# ---------------------------------------------------------------------------
# TestResolveSettings
# ---------------------------------------------------------------------------

class TestResolveSettings:
    def _make_settings(self, **kwargs):
        defaults = {
            "redis_url": "redis://env:6379",
            "postgres_url": "postgresql://env:5432/db",
            "api_key": "env-key",
            "listen_port": 8080,
        }
        defaults.update(kwargs)
        return SimpleNamespace(**defaults)

    def test_overrides_mapped_fields(self):
        settings = self._make_settings()
        backend = MagicMock()
        backend.fetch_secrets.return_value = {
            "redis_url": "redis://secret:6379",
            "postgres_url": "postgresql://secret:5432/db",
            "api_key": "secret-key",
        }
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        resolve_settings(settings, provider)
        assert settings.redis_url == "redis://secret:6379"
        assert settings.postgres_url == "postgresql://secret:5432/db"
        assert settings.api_key == "secret-key"

    def test_ignores_non_mapped_fields(self):
        settings = self._make_settings()
        backend = MagicMock()
        backend.fetch_secrets.return_value = {
            "listen_port": "9999",
            "redis_url": "redis://secret:6379",
        }
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        resolve_settings(settings, provider)
        assert settings.listen_port == 8080
        assert settings.redis_url == "redis://secret:6379"

    def test_keeps_env_on_missing(self):
        settings = self._make_settings()
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"redis_url": "redis://secret:6379"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        resolve_settings(settings, provider)
        assert settings.redis_url == "redis://secret:6379"
        assert settings.postgres_url == "postgresql://env:5432/db"
        assert settings.api_key == "env-key"

    def test_empty_string_keeps_env(self):
        settings = self._make_settings()
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"redis_url": "", "api_key": "   "}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        resolve_settings(settings, provider)
        assert settings.redis_url == "redis://env:6379"
        assert settings.api_key == "env-key"

    def test_field_map_only_contains_expected_keys(self):
        assert set(SETTINGS_FIELD_MAP.keys()) == {"redis_url", "postgres_url", "api_key"}


# ---------------------------------------------------------------------------
# TestInitProvider
# ---------------------------------------------------------------------------

class TestInitProvider:
    def test_env_returns_none(self):
        result = init_provider("env")
        assert result is None

    def test_aws_returns_instance(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"redis_url": "redis://aws:6379"}),
        }
        with patch("proxy.config.secrets.AwsSecretsBackend._get_client", return_value=mock_client):
            provider = init_provider("aws", 300)
        assert provider is not None
        assert isinstance(provider, SecretsProvider)

    def test_get_provider_returns_singleton(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"api_key": "k"}),
        }
        with patch("proxy.config.secrets.AwsSecretsBackend._get_client", return_value=mock_client):
            provider = init_provider("aws", 300)
        assert get_provider() is provider
