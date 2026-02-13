"""Attack simulation tests for secrets management — security hardening round 2.

Tests simulate real-world attack vectors including:
- Path traversal / mount escape
- Null byte injection
- CRLF injection
- JSON injection with nested objects
- Provider name confusion
- repr/str secret leakage
- Traceback secret leakage
- Cache poisoning
- TOCTOU on settings swap
- Fail-open exploitation
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import proxy.config.secrets as secrets_mod
from proxy.config.secrets import (
    SETTINGS_FIELD_MAP,
    AwsSecretsBackend,
    EnvSecretsBackend,
    GcpSecretsBackend,
    SecretsBackend,
    SecretsProvider,
    VaultSecretsBackend,
    _SecretsCache,
    _parse_secret_json,
    _validate_config_param,
    _validate_provider_name,
    create_backend,
    resolve_settings,
)


# ===================================================================
# 1. PATH TRAVERSAL ATTACKS
# ===================================================================

class TestPathTraversalAttacks:
    """Simulate path traversal attempts on all provider config params."""

    TRAVERSAL_PAYLOADS = [
        "../other-project",
        "app/../../admin/secrets",
        "config/../../../etc/passwd",
        "secret/..\\..\\admin",
        "a/../b/../c/../d",
    ]

    def test_aws_secret_id_rejects_traversal(self):
        for payload in self.TRAVERSAL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                AwsSecretsBackend(secret_id=payload)

    def test_aws_region_rejects_traversal(self):
        for payload in self.TRAVERSAL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                AwsSecretsBackend(secret_id="valid-secret", region=payload)

    def test_gcp_project_id_rejects_traversal(self):
        for payload in self.TRAVERSAL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                GcpSecretsBackend(project_id=payload, secret_id="config")

    def test_gcp_secret_id_rejects_traversal(self):
        for payload in self.TRAVERSAL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                GcpSecretsBackend(project_id="my-project", secret_id=payload)

    def test_gcp_version_rejects_traversal(self):
        for payload in self.TRAVERSAL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                GcpSecretsBackend(
                    project_id="my-project", secret_id="config", version=payload
                )

    def test_vault_path_rejects_traversal(self):
        for payload in self.TRAVERSAL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                VaultSecretsBackend(url="http://vault:8200", path=payload)

    def test_vault_mount_rejects_traversal(self):
        for payload in self.TRAVERSAL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                VaultSecretsBackend(
                    url="http://vault:8200", path="config", mount_point=payload
                )

    def test_vault_url_rejects_traversal(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            VaultSecretsBackend(url="http://vault:8200/../admin", path="config")

    def test_factory_rejects_traversal_in_env_vars(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "prod/../admin-secret")
        with pytest.raises(ValueError, match="unsafe characters"):
            create_backend("aws")

    def test_factory_rejects_gcp_traversal_in_env_vars(self, monkeypatch):
        monkeypatch.setenv("PROXY_SECRETS_GCP_PROJECT_ID", "../other-project")
        monkeypatch.setenv("PROXY_SECRETS_GCP_SECRET_ID", "config")
        with pytest.raises(ValueError, match="unsafe characters"):
            create_backend("gcp")


# ===================================================================
# 2. NULL BYTE INJECTION ATTACKS
# ===================================================================

class TestNullByteInjection:
    """Simulate null byte injection to truncate or bypass path validation."""

    NULL_PAYLOADS = [
        "config\x00../../admin",
        "\x00secret",
        "secret\x00",
        "legit\x00.evil",
    ]

    def test_aws_secret_id_rejects_null_bytes(self):
        for payload in self.NULL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                AwsSecretsBackend(secret_id=payload)

    def test_gcp_project_id_rejects_null_bytes(self):
        for payload in self.NULL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                GcpSecretsBackend(project_id=payload, secret_id="config")

    def test_gcp_secret_id_rejects_null_bytes(self):
        for payload in self.NULL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                GcpSecretsBackend(project_id="proj", secret_id=payload)

    def test_vault_path_rejects_null_bytes(self):
        for payload in self.NULL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                VaultSecretsBackend(url="http://vault:8200", path=payload)

    def test_vault_mount_rejects_null_bytes(self):
        for payload in self.NULL_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                VaultSecretsBackend(
                    url="http://vault:8200", path="config", mount_point=payload
                )


# ===================================================================
# 3. CRLF / CONTROL CHARACTER INJECTION
# ===================================================================

class TestCRLFInjection:
    """Simulate CRLF and control character injection for log/header injection."""

    CRLF_PAYLOADS = [
        "config\r\nX-Injected: true",
        "config\nContent-Length: 0",
        "config\rEvil-Header: yes",
        "config\x08backspace",
        "config\x1b[31mred",  # ANSI escape
    ]

    def test_aws_secret_id_rejects_crlf(self):
        for payload in self.CRLF_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                AwsSecretsBackend(secret_id=payload)

    def test_gcp_rejects_crlf(self):
        for payload in self.CRLF_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                GcpSecretsBackend(project_id=payload, secret_id="config")

    def test_vault_url_rejects_crlf(self):
        for payload in self.CRLF_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                VaultSecretsBackend(url=payload, path="config")

    def test_vault_path_rejects_crlf(self):
        for payload in self.CRLF_PAYLOADS:
            with pytest.raises(ValueError, match="unsafe characters"):
                VaultSecretsBackend(url="http://vault:8200", path=payload)


# ===================================================================
# 4. JSON INJECTION — NESTED OBJECTS & TYPE CONFUSION
# ===================================================================

class TestJSONInjection:
    """Simulate JSON injection with nested objects, lists, and type confusion."""

    def test_aws_nested_dict_rejected(self):
        """Nested dict must not silently become str({'host':'evil'})."""
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({
                "redis_url": {"host": "evil.com", "port": 6379},
            }),
        }
        backend._client = mock_client
        with pytest.raises(ValueError, match="non-scalar"):
            backend.fetch_secrets()

    def test_aws_nested_list_rejected(self):
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({
                "api_key": ["key1", "key2"],
            }),
        }
        backend._client = mock_client
        with pytest.raises(ValueError, match="non-scalar"):
            backend.fetch_secrets()

    def test_gcp_nested_dict_rejected(self):
        backend = GcpSecretsBackend(project_id="proj", secret_id="sec")
        mock_client = MagicMock()
        payload = json.dumps({
            "postgres_url": {"host": "evil.com", "db": "pwned"},
        }).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.payload.data = payload
        mock_client.access_secret_version.return_value = mock_resp
        backend._client = mock_client
        with pytest.raises(ValueError, match="non-scalar"):
            backend.fetch_secrets()

    def test_vault_nested_dict_rejected(self):
        backend = VaultSecretsBackend(url="http://vault:8200", path="config")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"redis_url": {"host": "evil.com"}}},
        }
        backend._client = mock_client
        with pytest.raises(ValueError, match="non-scalar"):
            backend.fetch_secrets()

    def test_vault_nested_list_rejected(self):
        backend = VaultSecretsBackend(url="http://vault:8200", path="config")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"api_key": [1, 2, 3]}},
        }
        backend._client = mock_client
        with pytest.raises(ValueError, match="non-scalar"):
            backend.fetch_secrets()

    def test_parse_secret_json_rejects_deeply_nested(self):
        raw = json.dumps({
            "api_key": "legit",
            "extra": {"nested": {"deep": "value"}},
        })
        with pytest.raises(ValueError, match="non-scalar"):
            _parse_secret_json(raw, "TEST")

    def test_parse_secret_json_allows_scalar_types(self):
        """Strings, numbers, booleans are valid scalar types."""
        raw = json.dumps({
            "redis_url": "redis://host:6379",
            "port": 6379,
            "enabled": True,
        })
        result = _parse_secret_json(raw, "TEST")
        assert result == {
            "redis_url": "redis://host:6379",
            "port": "6379",
            "enabled": "True",
        }


# ===================================================================
# 5. PROVIDER NAME CONFUSION ATTACKS
# ===================================================================

class TestProviderNameConfusion:
    """Simulate provider name injection and confusion attacks."""

    def test_case_sensitivity(self):
        """'AWS', 'Aws', 'ENV' should all normalize to lowercase."""
        assert _validate_provider_name("AWS") == "aws"
        assert _validate_provider_name("Env") == "env"
        assert _validate_provider_name("GCP") == "gcp"
        assert _validate_provider_name("VAULT") == "vault"

    def test_whitespace_stripped(self):
        assert _validate_provider_name("  aws  ") == "aws"
        assert _validate_provider_name("\tenv\n") == "env"

    def test_unknown_provider_rejected(self):
        invalid_names = [
            "oracle", "custom", "azure", "local",
            "", "vault;echo pwned",
            "vault\x00env",  # null byte
        ]
        for name in invalid_names:
            with pytest.raises(ValueError, match="Unknown secrets provider"):
                _validate_provider_name(name)

    def test_factory_normalizes_provider_name(self, monkeypatch):
        """create_backend should accept case-insensitive names."""
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        backend = create_backend("AWS")
        assert isinstance(backend, AwsSecretsBackend)

    def test_factory_rejects_command_injection(self):
        with pytest.raises(ValueError, match="Unknown secrets provider"):
            create_backend("env; rm -rf /")

    def test_factory_rejects_empty_string(self):
        with pytest.raises(ValueError, match="Unknown secrets provider"):
            create_backend("")


# ===================================================================
# 6. REPR / STR SECRET LEAKAGE
# ===================================================================

class TestReprStrLeakage:
    """Ensure repr() and str() of backend objects never expose secrets."""

    def test_vault_token_not_in_repr(self):
        token = "s.SUPER_SECRET_VAULT_TOKEN_XYZ"
        backend = VaultSecretsBackend(
            url="http://vault:8200", path="config", token=token
        )
        assert token not in repr(backend)
        assert token not in str(backend)
        assert "*****" in repr(backend)

    def test_vault_token_not_in_provider_repr(self):
        token = "s.SECRET_TOKEN_ABC"
        backend = VaultSecretsBackend(
            url="http://vault:8200", path="config", token=token
        )
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        assert token not in repr(provider)
        assert token not in str(provider)

    def test_aws_secret_id_masked_in_repr(self):
        backend = AwsSecretsBackend(
            secret_id="arn:aws:secretsmanager:us-east-1:123456789:secret:prod-secrets"
        )
        r = repr(backend)
        assert "prod-secrets" not in r
        assert "*****" in r

    def test_gcp_secret_id_masked_in_repr(self):
        backend = GcpSecretsBackend(project_id="my-project", secret_id="admin-creds")
        r = repr(backend)
        assert "admin-creds" not in r
        assert "*****" in r

    def test_cache_repr_shows_keys_not_values(self):
        cache = _SecretsCache(ttl=60)
        cache.set_all({
            "api_key": "sk-super-secret-key-12345",
            "redis_url": "redis://admin:password@host:6379",
        })
        r = repr(cache)
        assert "sk-super-secret-key-12345" not in r
        assert "password" not in r
        assert "api_key" in r
        assert "redis_url" in r

    def test_env_backend_repr_safe(self):
        backend = EnvSecretsBackend()
        assert repr(backend) == "EnvSecretsBackend()"


# ===================================================================
# 7. TRACEBACK SECRET LEAKAGE
# ===================================================================

class TestTracebackLeakage:
    """Ensure secrets do not leak through exception tracebacks or error messages."""

    def test_malformed_json_does_not_leak_raw_secret(self):
        """json.JSONDecodeError.doc contains the raw string — must not propagate."""
        raw_secret = "NOT_JSON_but_contains_password=s3cret!"
        backend = AwsSecretsBackend(secret_id="test/secret")
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {"SecretString": raw_secret}
        backend._client = mock_client
        with pytest.raises(ValueError, match="not valid JSON") as exc_info:
            backend.fetch_secrets()
        # The raw secret must NOT appear in the exception
        assert raw_secret not in str(exc_info.value)
        assert "s3cret" not in str(exc_info.value)

    def test_gcp_malformed_json_does_not_leak(self):
        raw_secret = "INVALID{password:hunter2}"
        backend = GcpSecretsBackend(project_id="proj", secret_id="sec")
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.payload.data = raw_secret.encode("utf-8")
        mock_client.access_secret_version.return_value = mock_resp
        backend._client = mock_client
        with pytest.raises(ValueError, match="not valid JSON") as exc_info:
            backend.fetch_secrets()
        assert "hunter2" not in str(exc_info.value)

    def test_refresh_error_log_does_not_contain_exc_info(self):
        """refresh() must NOT pass exc_info=True to prevent traceback leakage."""
        mock_logger = MagicMock()
        with patch.object(secrets_mod, "logger", mock_logger):
            backend = MagicMock()
            backend.fetch_secrets.side_effect = Exception("secret-data-in-error")
            backend.name.return_value = "mock"
            provider = SecretsProvider(backend=backend, cache_ttl=60)
            provider.refresh()

        # Verify exc_info was NOT passed
        error_call = mock_logger.error.call_args
        assert error_call is not None
        _, kwargs = error_call
        assert "exc_info" not in kwargs

    def test_loader_error_does_not_contain_exc_info(self, monkeypatch):
        """load_settings() must NOT pass exc_info=True."""
        monkeypatch.setenv("PROXY_SECRETS_PROVIDER", "aws")
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        import proxy.config.loader as loader_mod
        mock_logger = MagicMock()
        with (
            patch.object(loader_mod, "logger", mock_logger),
            patch("proxy.config.secrets.AwsSecretsBackend._get_client", side_effect=Exception("boom")),
        ):
            from proxy.config.loader import load_settings
            load_settings()

        # Check the error call doesn't have exc_info
        for call in mock_logger.error.call_args_list:
            _, kwargs = call
            assert "exc_info" not in kwargs, "exc_info=True found in load_settings error log"

    def test_refresh_logs_sanitized_error_type(self):
        """Error logs should contain error_type but not raw traceback."""
        mock_logger = MagicMock()
        with patch.object(secrets_mod, "logger", mock_logger):
            backend = MagicMock()
            backend.fetch_secrets.side_effect = ConnectionError("host=secret.internal")
            backend.name.return_value = "mock"
            provider = SecretsProvider(backend=backend, cache_ttl=60)
            provider.refresh()

        mock_logger.error.assert_called_once()
        _, kwargs = mock_logger.error.call_args
        assert kwargs["error_type"] == "ConnectionError"
        assert "error_message" in kwargs

    def test_long_error_message_truncated(self):
        """Error messages longer than 200 chars are truncated to prevent leakage."""
        mock_logger = MagicMock()
        long_secret = "A" * 500
        with patch.object(secrets_mod, "logger", mock_logger):
            backend = MagicMock()
            backend.fetch_secrets.side_effect = ValueError(long_secret)
            backend.name.return_value = "mock"
            provider = SecretsProvider(backend=backend, cache_ttl=60)
            provider.refresh()

        _, kwargs = mock_logger.error.call_args
        assert len(kwargs["error_message"]) <= 215  # 200 + "...(truncated)"
        assert kwargs["error_message"].endswith("...(truncated)")


# ===================================================================
# 8. CACHE POISONING ATTACKS
# ===================================================================

class TestCachePoisoning:
    """Simulate cache poisoning and verify TTL-based expiry."""

    def test_poisoned_cache_expires_after_ttl(self):
        """Poisoned values from a compromised backend must expire with TTL."""

        class PoisonThenFixBackend(SecretsBackend):
            def __init__(self):
                self.call_count = 0

            def fetch_secrets(self):
                self.call_count += 1
                if self.call_count == 1:
                    return {"redis_url": "redis://evil.com:6379"}
                return {"redis_url": "redis://legit.com:6379"}

            def name(self):
                return "test"

        provider = SecretsProvider(PoisonThenFixBackend(), cache_ttl=60)
        assert provider.get_secret("redis_url") == "redis://evil.com:6379"
        # Simulate TTL expiry
        provider._cache._ts = 0.0
        assert provider.get_secret("redis_url") == "redis://legit.com:6379"

    def test_resolve_settings_ignores_extra_keys(self):
        """Secrets with extra keys (prototype pollution attempt) are ignored."""
        settings = SimpleNamespace(
            redis_url="redis://env:6379",
            postgres_url="postgresql://env:5432/db",
            api_key="env-key",
            listen_port=8080,
            target_url="http://legit.com",
        )
        backend = MagicMock()
        backend.fetch_secrets.return_value = {
            "redis_url": "redis://legit:6379",
            "__proto__": "polluted",
            "constructor": "attack",
            "listen_port": "9999",
            "target_url": "http://evil.com",
            "__class__": "evil",
        }
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        resolve_settings(settings, provider)
        # Only SETTINGS_FIELD_MAP keys applied
        assert settings.redis_url == "redis://legit:6379"
        assert settings.listen_port == 8080
        assert settings.target_url == "http://legit.com"

    def test_field_map_is_frozen(self):
        """SETTINGS_FIELD_MAP must only contain the expected keys."""
        assert set(SETTINGS_FIELD_MAP.keys()) == {"redis_url", "postgres_url", "api_key"}


# ===================================================================
# 9. TOCTOU — SETTINGS SWAP ATOMICITY
# ===================================================================

class TestTOCTOU:
    """Verify atomic settings swap prevents partially-initialized state."""

    def test_settings_not_visible_before_secrets_resolved(self, monkeypatch):
        """During load_settings, the global _settings must not be updated
        until secrets are fully resolved."""
        monkeypatch.setenv("PROXY_SECRETS_PROVIDER", "aws")
        monkeypatch.setenv("PROXY_SECRETS_AWS_SECRET_ID", "test/secret")
        monkeypatch.setenv("PROXY_API_KEY", "env-key")

        import proxy.config.loader as loader

        captured_settings = []

        # Intercept init_provider to capture _settings at that point
        original_init = secrets_mod.init_provider

        def spying_init(*args, **kwargs):
            # At this point, _settings should still be the OLD value (or None)
            captured_settings.append(loader._settings)
            return original_init(*args, **kwargs)

        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": json.dumps({"api_key": "secret-key"}),
        }
        with (
            patch("proxy.config.secrets.init_provider", side_effect=spying_init),
            patch("proxy.config.secrets.AwsSecretsBackend._get_client", return_value=mock_client),
        ):
            loader._settings = None
            loader.load_settings()

        # _settings should have been None (not partially initialized)
        # when init_provider was called
        assert captured_settings[0] is None


# ===================================================================
# 10. FAIL-OPEN EXPLOITATION
# ===================================================================

class TestFailOpenExploitation:
    """Verify fail-open behavior and its limitations."""

    def test_consecutive_failures_preserve_stale_cache(self):
        """After N consecutive failures, stale cache is still served (documented risk)."""
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"api_key": "original"}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()

        # Now backend starts failing
        backend.fetch_secrets.side_effect = ConnectionError("unavailable")
        for _ in range(10):
            provider._cache._ts = 0.0  # force stale
            result = provider.get_secret("api_key")
        # Stale cache preserved — this is the documented fail-open behavior
        assert result == "original"

    def test_first_startup_failure_returns_empty(self):
        """If first refresh fails, no stale cache exists — empty dict returned."""
        backend = MagicMock()
        backend.fetch_secrets.side_effect = ConnectionError("unavailable")
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        result = provider.refresh()
        assert result == {}

    def test_empty_api_key_not_applied(self):
        """If provider returns empty api_key, env value is preserved."""
        settings = SimpleNamespace(
            redis_url="redis://env:6379",
            postgres_url="postgresql://env:5432/db",
            api_key="env-key",
        )
        backend = MagicMock()
        backend.fetch_secrets.return_value = {"api_key": ""}
        backend.name.return_value = "mock"
        provider = SecretsProvider(backend=backend, cache_ttl=60)
        provider.refresh()
        resolve_settings(settings, provider)
        assert settings.api_key == "env-key"


# ===================================================================
# 11. VALIDATE_CONFIG_PARAM EDGE CASES
# ===================================================================

class TestValidateConfigParam:
    """Direct tests of the input validation function."""

    def test_accepts_normal_values(self):
        assert _validate_config_param("test", "my-project-123") == "my-project-123"
        assert _validate_config_param("test", "us-east-1") == "us-east-1"
        assert _validate_config_param("test", "prod/proxy/secrets") == "prod/proxy/secrets"
        assert _validate_config_param("test", "http://vault:8200") == "http://vault:8200"
        assert _validate_config_param("test", "latest") == "latest"

    def test_rejects_dot_dot(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_config_param("test", "a/../b")

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_config_param("test", "a\x00b")

    def test_rejects_newline(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_config_param("test", "a\nb")

    def test_rejects_carriage_return(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_config_param("test", "a\rb")

    def test_rejects_tab(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_config_param("test", "a\tb")

    def test_rejects_ansi_escape(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_config_param("test", "\x1b[31mred")

    def test_rejects_del_character(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            _validate_config_param("test", "test\x7fvalue")


# ===================================================================
# 12. PARSE_SECRET_JSON EDGE CASES
# ===================================================================

class TestParseSecretJSON:
    """Direct tests of the centralized JSON parsing function."""

    def test_valid_flat_dict(self):
        result = _parse_secret_json('{"a":"1","b":"2"}', "TEST")
        assert result == {"a": "1", "b": "2"}

    def test_rejects_array_top_level(self):
        with pytest.raises(ValueError, match="JSON object"):
            _parse_secret_json('["a","b"]', "TEST")

    def test_rejects_string_top_level(self):
        with pytest.raises(ValueError, match="JSON object"):
            _parse_secret_json('"just a string"', "TEST")

    def test_rejects_nested_dict(self):
        with pytest.raises(ValueError, match="non-scalar"):
            _parse_secret_json('{"key":{"nested":"value"}}', "TEST")

    def test_rejects_nested_list(self):
        with pytest.raises(ValueError, match="non-scalar"):
            _parse_secret_json('{"key":["a","b"]}', "TEST")

    def test_filters_null_values(self):
        result = _parse_secret_json('{"a":"1","b":null}', "TEST")
        assert result == {"a": "1"}

    def test_converts_numbers_to_strings(self):
        result = _parse_secret_json('{"port":6379,"enabled":true}', "TEST")
        assert result == {"port": "6379", "enabled": "True"}

    def test_malformed_json_error_does_not_contain_raw_input(self):
        raw = "this_is_a_secret_value_not_json"
        with pytest.raises(ValueError, match="not valid JSON") as exc_info:
            _parse_secret_json(raw, "TEST")
        assert raw not in str(exc_info.value)

    def test_empty_dict_is_valid(self):
        result = _parse_secret_json('{}', "TEST")
        assert result == {}
