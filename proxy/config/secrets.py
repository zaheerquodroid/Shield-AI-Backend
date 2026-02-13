"""Pluggable secrets management with caching and zero-downtime rotation."""

from __future__ import annotations

import abc
import json
import os
import re
import time

import structlog

logger = structlog.get_logger()

# Only these ProxySettings fields can be overridden from external secrets.
SETTINGS_FIELD_MAP: dict[str, str] = {
    "redis_url": "redis_url",
    "postgres_url": "postgres_url",
    "api_key": "api_key",
}

# Valid provider names (strict allowlist).
_VALID_PROVIDERS = frozenset({"env", "aws", "gcp", "vault"})

# Cache TTL bounds (seconds).
_MIN_TTL = 60
_MAX_TTL = 3600

# Validation patterns for provider config parameters.
# Reject path traversal, null bytes, control characters.
_UNSAFE_PATTERN = re.compile(r"\.\.|[\x00-\x1f\x7f]")


def _validate_config_param(name: str, value: str) -> str:
    """Validate a provider configuration parameter.

    Rejects path traversal sequences (..), null bytes, and control characters.
    """
    if _UNSAFE_PATTERN.search(value):
        raise ValueError(
            f"{name} contains unsafe characters "
            "(path traversal, null bytes, or control characters)"
        )
    return value


def _parse_secret_json(raw: str, provider_label: str) -> dict[str, str]:
    """Parse a JSON secret blob into a flat string dict.

    Rejects non-dict top-level values. Filters out None values.
    Rejects non-scalar values (nested dicts/lists) to prevent
    str({"host":"evil"}) injection.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Re-raise without the raw document to prevent secret leakage.
        # json.JSONDecodeError stores the raw string in its .doc attribute.
        raise ValueError(f"{provider_label} secret is not valid JSON")
    if not isinstance(data, dict):
        raise ValueError(
            f"{provider_label} secret must be a JSON object, got {type(data).__name__}"
        )
    result: dict[str, str] = {}
    for k, v in data.items():
        if v is None:
            continue
        if isinstance(v, (dict, list)):
            raise ValueError(
                f"{provider_label} secret key {k!r} has non-scalar value "
                f"(type {type(v).__name__}); only strings, numbers, and booleans allowed"
            )
        result[k] = str(v)
    return result


# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------

class _SecretsCache:
    """Simple in-memory cache with monotonic-clock TTL."""

    def __init__(self, ttl: int = 300) -> None:
        self.ttl = max(_MIN_TTL, min(_MAX_TTL, ttl))
        self._data: dict[str, str] = {}
        self._ts: float = 0.0  # monotonic timestamp of last refresh

    @property
    def is_stale(self) -> bool:
        return (time.monotonic() - self._ts) >= self.ttl

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def get_all(self) -> dict[str, str]:
        return dict(self._data)

    def set_all(self, data: dict[str, str]) -> None:
        self._data = dict(data)
        self._ts = time.monotonic()

    def clear(self) -> None:
        self._data.clear()
        self._ts = 0.0

    def __repr__(self) -> str:
        return f"_SecretsCache(ttl={self.ttl}, keys={list(self._data.keys())}, stale={self.is_stale})"


# ---------------------------------------------------------------------------
# Abstract backend
# ---------------------------------------------------------------------------

class SecretsBackend(abc.ABC):
    """Interface for fetching secrets from an external provider."""

    @abc.abstractmethod
    def fetch_secrets(self) -> dict[str, str]:
        """Return a dict of secret field-name -> value."""

    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable backend name."""


# ---------------------------------------------------------------------------
# Env backend (no-op default)
# ---------------------------------------------------------------------------

class EnvSecretsBackend(SecretsBackend):
    """Default backend — returns empty dict, secrets come from env vars."""

    def fetch_secrets(self) -> dict[str, str]:
        return {}

    def name(self) -> str:
        return "env"

    def __repr__(self) -> str:
        return "EnvSecretsBackend()"


# ---------------------------------------------------------------------------
# AWS Secrets Manager backend
# ---------------------------------------------------------------------------

class AwsSecretsBackend(SecretsBackend):
    """Fetch secrets from AWS Secrets Manager."""

    def __init__(self, secret_id: str, region: str | None = None) -> None:
        self._secret_id = _validate_config_param("PROXY_SECRETS_AWS_SECRET_ID", secret_id)
        if region is not None:
            _validate_config_param("PROXY_SECRETS_AWS_REGION", region)
        self._region = region
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import boto3  # noqa: WPS433
            except ImportError:
                raise RuntimeError(
                    "boto3 is required for AWS secrets provider. "
                    "Install with: pip install shieldai-proxy[aws]"
                )
            kwargs = {}
            if self._region:
                kwargs["region_name"] = self._region
            self._client = boto3.client("secretsmanager", **kwargs)
        return self._client

    def fetch_secrets(self) -> dict[str, str]:
        client = self._get_client()
        resp = client.get_secret_value(SecretId=self._secret_id)
        return _parse_secret_json(resp["SecretString"], "AWS")

    def name(self) -> str:
        return "aws"

    def __repr__(self) -> str:
        return f"AwsSecretsBackend(secret_id=*****, region={self._region!r})"


# ---------------------------------------------------------------------------
# GCP Secret Manager backend
# ---------------------------------------------------------------------------

class GcpSecretsBackend(SecretsBackend):
    """Fetch secrets from GCP Secret Manager."""

    def __init__(self, project_id: str, secret_id: str, version: str = "latest") -> None:
        self._project_id = _validate_config_param("PROXY_SECRETS_GCP_PROJECT_ID", project_id)
        self._secret_id = _validate_config_param("PROXY_SECRETS_GCP_SECRET_ID", secret_id)
        self._version = _validate_config_param("PROXY_SECRETS_GCP_VERSION", version)
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from google.cloud import secretmanager  # noqa: WPS433
            except ImportError:
                raise RuntimeError(
                    "google-cloud-secret-manager is required for GCP secrets provider. "
                    "Install with: pip install shieldai-proxy[gcp]"
                )
            self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    def fetch_secrets(self) -> dict[str, str]:
        client = self._get_client()
        resource_name = (
            f"projects/{self._project_id}/secrets/{self._secret_id}"
            f"/versions/{self._version}"
        )
        resp = client.access_secret_version(request={"name": resource_name})
        payload = resp.payload.data.decode("utf-8")
        return _parse_secret_json(payload, "GCP")

    def name(self) -> str:
        return "gcp"

    def __repr__(self) -> str:
        return (
            f"GcpSecretsBackend(project_id={self._project_id!r}, "
            f"secret_id=*****, version={self._version!r})"
        )


# ---------------------------------------------------------------------------
# HashiCorp Vault backend
# ---------------------------------------------------------------------------

class VaultSecretsBackend(SecretsBackend):
    """Fetch secrets from HashiCorp Vault KV v2."""

    def __init__(
        self,
        url: str,
        path: str,
        token: str | None = None,
        mount_point: str = "secret",
    ) -> None:
        _validate_config_param("PROXY_SECRETS_VAULT_URL", url)
        self._url = url
        self._path = _validate_config_param("PROXY_SECRETS_VAULT_PATH", path)
        self._token = token  # never exposed in repr/str/logs
        self._mount_point = _validate_config_param("PROXY_SECRETS_VAULT_MOUNT", mount_point)
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import hvac  # noqa: WPS433
            except ImportError:
                raise RuntimeError(
                    "hvac is required for Vault secrets provider. "
                    "Install with: pip install shieldai-proxy[vault]"
                )
            self._client = hvac.Client(url=self._url, token=self._token)
        return self._client

    def fetch_secrets(self) -> dict[str, str]:
        client = self._get_client()
        resp = client.secrets.kv.v2.read_secret_version(
            path=self._path, mount_point=self._mount_point
        )
        data = resp["data"]["data"]
        if not isinstance(data, dict):
            raise ValueError("Vault secret must be a dict, got " + type(data).__name__)
        result: dict[str, str] = {}
        for k, v in data.items():
            if v is None:
                continue
            if isinstance(v, (dict, list)):
                raise ValueError(
                    f"Vault secret key {k!r} has non-scalar value "
                    f"(type {type(v).__name__}); only strings, numbers, and booleans allowed"
                )
            result[k] = str(v)
        return result

    def name(self) -> str:
        return "vault"

    def __repr__(self) -> str:
        return (
            f"VaultSecretsBackend(url={self._url!r}, path={self._path!r}, "
            f"token=*****, mount_point={self._mount_point!r})"
        )


# ---------------------------------------------------------------------------
# SecretsProvider — orchestrates backend + cache
# ---------------------------------------------------------------------------

class SecretsProvider:
    """Wraps a backend with in-memory caching."""

    def __init__(self, backend: SecretsBackend, cache_ttl: int = 300) -> None:
        self.backend = backend
        self._cache = _SecretsCache(ttl=cache_ttl)

    def refresh(self) -> dict[str, str]:
        """Force-fetch from backend, update cache. Fail-open on error."""
        try:
            data = self.backend.fetch_secrets()
            self._cache.set_all(data)
            logger.info(
                "secrets_refreshed",
                provider=self.backend.name(),
                field_count=len(data),
            )
            return data
        except Exception as exc:
            # SECURITY: Do NOT use exc_info=True. Tracebacks from JSON
            # parse errors (json.JSONDecodeError.doc) or SDK exceptions
            # can contain raw secret values.
            logger.error(
                "secrets_refresh_failed",
                provider=self.backend.name(),
                error_type=type(exc).__name__,
                error_message=_sanitize_error(str(exc)),
            )
            return self._cache.get_all()

    def get_secret(self, key: str) -> str | None:
        """Get a single secret, refreshing cache if stale."""
        if self._cache.is_stale:
            self.refresh()
        return self._cache.get(key)

    def get_all(self) -> dict[str, str]:
        """Get all secrets, refreshing cache if stale."""
        if self._cache.is_stale:
            self.refresh()
        return self._cache.get_all()

    def __repr__(self) -> str:
        return f"SecretsProvider(backend={self.backend.name()}, cache={self._cache!r})"


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def _sanitize_error(msg: str) -> str:
    """Truncate error messages to prevent secret leakage in logs."""
    if len(msg) > 200:
        return msg[:200] + "...(truncated)"
    return msg


def _validate_provider_name(name: str) -> str:
    """Validate and normalize the provider name."""
    normalized = name.strip().lower()
    if normalized not in _VALID_PROVIDERS:
        raise ValueError(
            f"Unknown secrets provider: {normalized!r}. "
            f"Valid providers: {sorted(_VALID_PROVIDERS)}"
        )
    return normalized


def create_backend(provider_name: str) -> SecretsBackend:
    """Create a secrets backend from env-var configuration."""
    provider_name = _validate_provider_name(provider_name)

    if provider_name == "env":
        return EnvSecretsBackend()

    if provider_name == "aws":
        secret_id = os.environ.get("PROXY_SECRETS_AWS_SECRET_ID")
        if not secret_id:
            raise ValueError("PROXY_SECRETS_AWS_SECRET_ID is required for AWS provider")
        region = os.environ.get("PROXY_SECRETS_AWS_REGION")
        return AwsSecretsBackend(secret_id=secret_id, region=region)

    if provider_name == "gcp":
        project_id = os.environ.get("PROXY_SECRETS_GCP_PROJECT_ID")
        secret_id = os.environ.get("PROXY_SECRETS_GCP_SECRET_ID")
        if not project_id or not secret_id:
            raise ValueError(
                "PROXY_SECRETS_GCP_PROJECT_ID and PROXY_SECRETS_GCP_SECRET_ID "
                "are required for GCP provider"
            )
        version = os.environ.get("PROXY_SECRETS_GCP_VERSION", "latest")
        return GcpSecretsBackend(project_id=project_id, secret_id=secret_id, version=version)

    if provider_name == "vault":
        url = os.environ.get("PROXY_SECRETS_VAULT_URL")
        path = os.environ.get("PROXY_SECRETS_VAULT_PATH")
        if not url or not path:
            raise ValueError(
                "PROXY_SECRETS_VAULT_URL and PROXY_SECRETS_VAULT_PATH "
                "are required for Vault provider"
            )
        token = os.environ.get("PROXY_SECRETS_VAULT_TOKEN")
        mount = os.environ.get("PROXY_SECRETS_VAULT_MOUNT", "secret")
        return VaultSecretsBackend(url=url, path=path, token=token, mount_point=mount)

    # Unreachable due to _validate_provider_name, but defensive.
    raise ValueError(f"Unknown secrets provider: {provider_name!r}")


def create_provider(provider_name: str, cache_ttl: int = 300) -> SecretsProvider:
    """Create a SecretsProvider with the named backend."""
    backend = create_backend(provider_name)
    return SecretsProvider(backend=backend, cache_ttl=cache_ttl)


def resolve_settings(settings, provider: SecretsProvider) -> None:
    """Override ProxySettings fields from the secrets provider.

    Only fields listed in SETTINGS_FIELD_MAP are overridden.
    Empty/whitespace-only values from the provider are ignored.
    Secret VALUES are never logged — only field names.
    """
    secrets = provider.get_all()
    overridden: list[str] = []
    for secret_key, settings_field in SETTINGS_FIELD_MAP.items():
        value = secrets.get(secret_key)
        if value and value.strip():
            object.__setattr__(settings, settings_field, value)
            overridden.append(settings_field)
    if overridden:
        logger.info("secrets_applied", fields=overridden, count=len(overridden))


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_provider: SecretsProvider | None = None


def init_provider(provider_name: str = "env", cache_ttl: int = 300) -> SecretsProvider | None:
    """Initialize the module-level provider singleton.

    Returns None for "env" provider (no external secrets needed).
    """
    global _provider
    provider_name = _validate_provider_name(provider_name)
    if provider_name == "env":
        _provider = None
        return None
    _provider = create_provider(provider_name, cache_ttl)
    _provider.refresh()
    return _provider


def get_provider() -> SecretsProvider | None:
    """Return the current module-level provider (may be None)."""
    return _provider
