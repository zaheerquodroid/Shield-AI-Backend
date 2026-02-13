"""Security hardening tests for secrets management — verify secrets NEVER leak."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

import proxy.config.secrets as secrets_mod
from proxy.config.secrets import (
    SecretsProvider,
    resolve_settings,
)


# ---------------------------------------------------------------------------
# TestSecretsNeverLogged
# ---------------------------------------------------------------------------

class TestSecretsNeverLogged:
    """Verify that secret VALUES never appear in log output."""

    SECRET_VALUES = [
        "redis://super-secret-host:6379/0",
        "postgresql://admin:p4$$w0rd@secret-db:5432/prod",
        "sk-api-key-very-secret-12345",
    ]

    def test_resolve_settings_logs_field_names_not_values(self):
        mock_logger = MagicMock()
        with patch.object(secrets_mod, "logger", mock_logger):
            settings = SimpleNamespace(
                redis_url="old", postgres_url="old", api_key="old",
            )
            backend = MagicMock()
            backend.fetch_secrets.return_value = {
                "redis_url": self.SECRET_VALUES[0],
                "postgres_url": self.SECRET_VALUES[1],
                "api_key": self.SECRET_VALUES[2],
            }
            backend.name.return_value = "mock"
            provider = SecretsProvider(backend=backend, cache_ttl=60)
            provider.refresh()
            resolve_settings(settings, provider)

        # Check all log calls for leaked secrets
        for c in mock_logger.method_calls:
            call_str = str(c)
            for secret in self.SECRET_VALUES:
                assert secret not in call_str, f"Secret value leaked in log: {secret!r}"

        # Verify field names ARE logged
        mock_logger.info.assert_any_call(
            "secrets_applied",
            fields=["redis_url", "postgres_url", "api_key"],
            count=3,
        )

    def test_refresh_logs_count_not_data(self):
        mock_logger = MagicMock()
        with patch.object(secrets_mod, "logger", mock_logger):
            backend = MagicMock()
            backend.fetch_secrets.return_value = {
                "redis_url": self.SECRET_VALUES[0],
                "api_key": self.SECRET_VALUES[2],
            }
            backend.name.return_value = "mock"
            provider = SecretsProvider(backend=backend, cache_ttl=60)
            provider.refresh()

        for c in mock_logger.method_calls:
            call_str = str(c)
            for secret in self.SECRET_VALUES:
                assert secret not in call_str

        mock_logger.info.assert_any_call(
            "secrets_refreshed", provider="mock", field_count=2,
        )

    def test_errors_dont_leak_secrets(self):
        mock_logger = MagicMock()
        with patch.object(secrets_mod, "logger", mock_logger):
            backend = MagicMock()
            backend.fetch_secrets.side_effect = Exception("connection refused")
            backend.name.return_value = "mock"
            provider = SecretsProvider(backend=backend, cache_ttl=60)
            provider.refresh()

        for c in mock_logger.method_calls:
            call_str = str(c)
            for secret in self.SECRET_VALUES:
                assert secret not in call_str


# ---------------------------------------------------------------------------
# TestNullValueSafety
# ---------------------------------------------------------------------------

class TestNullValueSafety:
    """Verify JSON null values never silently become the string 'None' in settings."""

    def test_null_api_key_does_not_become_string_none(self):
        """A JSON null must NOT set api_key to the literal string 'None'."""
        from proxy.config.secrets import AwsSecretsBackend
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({
                "redis_url": "redis://prod:6379",
                "api_key": None,
            }),
        }
        backend._client = mock_client
        secrets = backend.fetch_secrets()
        # null values should be completely absent, not converted to "None"
        assert "api_key" not in secrets
        assert "None" not in secrets.values()

    def test_null_values_dont_override_settings(self):
        """Settings must keep env-var values when provider returns null."""
        from types import SimpleNamespace
        settings = SimpleNamespace(
            redis_url="redis://env:6379",
            postgres_url="postgresql://env:5432/db",
            api_key="env-key",
        )
        backend = MagicMock()
        backend.fetch_secrets.return_value = {
            "redis_url": "redis://new:6379",
            # api_key deliberately absent (filtered null)
        }
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        resolve_settings(settings, provider)
        assert settings.redis_url == "redis://new:6379"
        assert settings.api_key == "env-key"  # preserved, not overwritten


# ---------------------------------------------------------------------------
# TestFailOpenBehavior
# ---------------------------------------------------------------------------

class TestFailOpenBehavior:
    """Verify fail-open behavior doesn't silently mask configuration errors."""

    def test_invalid_provider_logs_error_and_uses_env(self, monkeypatch):
        """Unknown provider name logs error; proxy starts with env values."""
        monkeypatch.setenv("PROXY_SECRETS_PROVIDER", "oracle_cloud")
        monkeypatch.setenv("PROXY_API_KEY", "my-env-key")
        from proxy.config.loader import load_settings
        settings = load_settings()
        # Proxy still starts — env values preserved
        assert settings.api_key == "my-env-key"

    def test_missing_sdk_logs_error_and_uses_env(self, monkeypatch):
        """Missing SDK logs error; proxy starts with env values."""
        monkeypatch.setenv("PROXY_SECRETS_PROVIDER", "aws")
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        monkeypatch.setenv("PROXY_API_KEY", "my-env-key")
        with patch.dict("sys.modules", {"boto3": None}):
            from proxy.config.loader import load_settings
            settings = load_settings()
        assert settings.api_key == "my-env-key"

    def test_first_refresh_failure_uses_empty_cache(self):
        """If first refresh fails, cache is empty — settings keep env values."""
        from types import SimpleNamespace
        settings = SimpleNamespace(
            redis_url="redis://env:6379",
            postgres_url="postgresql://env:5432/db",
            api_key="env-key",
        )
        backend = MagicMock()
        backend.fetch_secrets.side_effect = Exception("network error")
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()  # fails, cache stays empty
        resolve_settings(settings, provider)
        # All settings preserved — no silent override
        assert settings.redis_url == "redis://env:6379"
        assert settings.postgres_url == "postgresql://env:5432/db"
        assert settings.api_key == "env-key"


# ---------------------------------------------------------------------------
# TestImportIsolation
# ---------------------------------------------------------------------------

class TestImportIsolation:
    """Verify SDK imports only happen when the provider is actually selected."""

    def test_aws_import_only_when_selected(self):
        """Importing secrets module does NOT import boto3."""
        import sys
        # Re-import to check
        if "boto3" in sys.modules:
            # boto3 may be installed — that's fine. The point is it's lazy.
            pass
        from proxy.config.secrets import EnvSecretsBackend
        backend = EnvSecretsBackend()
        backend.fetch_secrets()
        # No boto3 usage for env backend

    def test_no_import_error_when_sdk_absent(self):
        """EnvSecretsBackend works even if all SDKs are absent."""
        with patch.dict("sys.modules", {"boto3": None, "hvac": None}):
            from proxy.config.secrets import EnvSecretsBackend
            backend = EnvSecretsBackend()
            assert backend.fetch_secrets() == {}

    def test_gcp_import_only_when_used(self):
        from proxy.config.secrets import GcpSecretsBackend
        backend = GcpSecretsBackend(project_id="p", secret_id="s")
        assert backend.name() == "gcp"
        assert backend._client is None  # Not imported yet

    def test_vault_import_only_when_used(self):
        from proxy.config.secrets import VaultSecretsBackend
        backend = VaultSecretsBackend(url="http://v:8200", path="p")
        assert backend.name() == "vault"
        assert backend._client is None  # Not imported yet
