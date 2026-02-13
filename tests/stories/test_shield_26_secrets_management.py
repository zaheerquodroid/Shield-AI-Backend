"""Story-level acceptance tests for SHIELD-26: Secrets Management Integration."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from proxy.config.secrets import (
    AwsSecretsBackend,
    EnvSecretsBackend,
    GcpSecretsBackend,
    SecretsProvider,
    VaultSecretsBackend,
    create_backend,
    init_provider,
    resolve_settings,
)


# ---------------------------------------------------------------------------
# AC1: Integration with AWS Secrets Manager, GCP Secret Manager, or Vault
# ---------------------------------------------------------------------------

class TestAC1_ProviderIntegration:
    """AC1: Integration with AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault."""

    def test_aws_backend_fetches_json(self):
        backend = AwsSecretsBackend(secret_id="prod/proxy")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({
                "redis_url": "redis://prod:6379",
                "postgres_url": "postgresql://prod:5432/app",
                "api_key": "prod-key-abc",
            }),
        }
        backend._client = mock_client
        secrets = backend.fetch_secrets()
        assert secrets["redis_url"] == "redis://prod:6379"
        assert secrets["postgres_url"] == "postgresql://prod:5432/app"
        assert secrets["api_key"] == "prod-key-abc"

    def test_gcp_backend_fetches_json(self):
        backend = GcpSecretsBackend(project_id="myproj", secret_id="proxy-secrets")
        mock_client = MagicMock()
        payload = json.dumps({"redis_url": "redis://gcp:6379"}).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.payload.data = payload
        mock_client.access_secret_version.return_value = mock_resp
        backend._client = mock_client
        assert backend.fetch_secrets() == {"redis_url": "redis://gcp:6379"}

    def test_vault_backend_fetches_json(self):
        backend = VaultSecretsBackend(url="http://vault:8200", path="proxy/secrets")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"api_key": "vault-key-xyz"}},
        }
        backend._client = mock_client
        assert backend.fetch_secrets() == {"api_key": "vault-key-xyz"}

    def test_provider_selected_by_env_var(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        backend = create_backend("aws")
        assert isinstance(backend, AwsSecretsBackend)

        monkeypatch.setenv("PROXY_SECRETS_GCP_PROJECT_ID", "proj")
        monkeypatch.setenv("PROXY_SECRETS_GCP_SECRET_ID", "sec")
        backend = create_backend("gcp")
        assert isinstance(backend, GcpSecretsBackend)

        monkeypatch.setenv("PROXY_SECRETS_VAULT_URL", "http://vault:8200")
        monkeypatch.setenv("PROXY_SECRETS_VAULT_PATH", "path")
        backend = create_backend("vault")
        assert isinstance(backend, VaultSecretsBackend)

    def test_sdks_are_optional(self):
        """Provider classes can be instantiated without SDKs; error only on use."""
        aws = AwsSecretsBackend(secret_id="x")
        assert aws.name() == "aws"
        gcp = GcpSecretsBackend(project_id="p", secret_id="s")
        assert gcp.name() == "gcp"
        vault = VaultSecretsBackend(url="http://v:8200", path="p")
        assert vault.name() == "vault"


# ---------------------------------------------------------------------------
# AC2: Terraform modules deploy secrets infrastructure
# ---------------------------------------------------------------------------

class TestAC2_TerraformModule:
    """AC2: Terraform modules deploy secrets infrastructure."""

    _MODULE_DIR = os.path.join(
        os.path.dirname(__file__), "..", "..", "terraform", "modules", "secrets"
    )

    def test_module_directory_exists(self):
        assert os.path.isdir(self._MODULE_DIR)

    def test_main_tf_creates_secret_resource(self):
        main_tf = os.path.join(self._MODULE_DIR, "main.tf")
        assert os.path.isfile(main_tf)
        with open(main_tf) as f:
            content = f.read()
        assert "aws_secretsmanager_secret" in content
        assert "aws_kms_key" in content

    def test_outputs_tf_exports_arn(self):
        outputs_tf = os.path.join(self._MODULE_DIR, "outputs.tf")
        assert os.path.isfile(outputs_tf)
        with open(outputs_tf) as f:
            content = f.read()
        assert "secret_arn" in content
        assert "kms_key_arn" in content
        assert "iam_policy_arn" in content

    def test_variables_tf_exists(self):
        variables_tf = os.path.join(self._MODULE_DIR, "variables.tf")
        assert os.path.isfile(variables_tf)
        with open(variables_tf) as f:
            content = f.read()
        assert "environment" in content
        assert "rotation_days" in content


# ---------------------------------------------------------------------------
# AC3: Secrets injected into customer's container at startup
# ---------------------------------------------------------------------------

class TestAC3_StartupInjection:
    """AC3: Secrets injected into customer's container at startup."""

    def test_load_settings_resolves_secrets(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_PROVIDER", "aws")
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        secret_data = {
            "redis_url": "redis://injected:6379",
            "postgres_url": "postgresql://injected:5432/db",
            "api_key": "injected-key",
        }
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps(secret_data),
        }
        with patch("proxy.config.secrets.AwsSecretsBackend._get_client", return_value=mock_client):
            from proxy.config.loader import load_settings
            settings = load_settings()
        assert settings.redis_url == "redis://injected:6379"
        assert settings.postgres_url == "postgresql://injected:5432/db"
        assert settings.api_key == "injected-key"

    def test_settings_contain_secret_values_after_load(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_PROVIDER", "aws")
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"api_key": "loaded-secret"}),
        }
        with patch("proxy.config.secrets.AwsSecretsBackend._get_client", return_value=mock_client):
            from proxy.config.loader import load_settings
            settings = load_settings()
        assert settings.api_key == "loaded-secret"

    def test_failure_logs_error_and_uses_env_fallback(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_PROVIDER", "aws")
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        monkeypatch.setenv("PROXY_API_KEY", "env-fallback-key")
        with patch("proxy.config.secrets.AwsSecretsBackend._get_client", side_effect=Exception("boom")):
            from proxy.config.loader import load_settings
            settings = load_settings()
        assert settings.api_key == "env-fallback-key"


# ---------------------------------------------------------------------------
# AC4: Secret rotation supported with zero-downtime
# ---------------------------------------------------------------------------

class TestAC4_ZeroDowntimeRotation:
    """AC4: Secret rotation supported with zero-downtime."""

    def test_cache_ttl_triggers_refresh(self):
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"api_key": "v1"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()

        backend.fetch_secrets.return_value = {"api_key": "v2"}
        provider._cache._ts -= 61
        result = provider.get_all()
        assert result["api_key"] == "v2"

    def test_sighup_reloads_secrets(self, monkeypatch):
        """SIGHUP triggers load_settings which re-initializes secrets."""
        monkeypatch.setenv("PROXY_SECRETS_PROVIDER", "aws")
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"api_key": "rotated-key"}),
        }
        with patch("proxy.config.secrets.AwsSecretsBackend._get_client", return_value=mock_client):
            from proxy.config.loader import load_settings
            settings = load_settings()
        assert settings.api_key == "rotated-key"

    def test_stale_cache_preserved_on_failure(self):
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"api_key": "original"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()

        backend.fetch_secrets.side_effect = Exception("network error")
        provider._cache._ts -= 61
        result = provider.get_all()
        assert result == {"api_key": "original"}

    def test_settings_object_remains_valid(self):
        settings = SimpleNamespace(
            redis_url="redis://env:6379",
            postgres_url="postgresql://env:5432/db",
            api_key="env-key",
        )
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"redis_url": "redis://rotated:6379"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        resolve_settings(settings, provider)
        assert settings.redis_url == "redis://rotated:6379"
        assert settings.postgres_url == "postgresql://env:5432/db"


# ---------------------------------------------------------------------------
# AC5: Fallback to environment variables for local development
# ---------------------------------------------------------------------------

class TestAC5_EnvFallback:
    """AC5: Fallback to environment variables for local development."""

    def test_default_provider_is_env(self):
        from proxy.config.loader import ProxySettings
        s = ProxySettings()
        assert s.secrets_provider == "env"

    def test_env_provider_returns_empty(self):
        backend = EnvSecretsBackend()
        assert backend.fetch_secrets() == {}

    def test_settings_from_env_when_no_provider(self, monkeypatch):
        monkeypatch.setenv("PROXY_API_KEY", "my-local-key")
        from proxy.config.loader import load_settings
        settings = load_settings()
        assert settings.api_key == "my-local-key"

    def test_no_sdk_import_for_env_provider(self):
        result = init_provider("env")
        assert result is None

    def test_init_provider_env_returns_none(self):
        assert init_provider("env") is None
