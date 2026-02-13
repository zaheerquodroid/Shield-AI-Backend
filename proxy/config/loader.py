"""YAML + env var config loading with pydantic-settings."""

from __future__ import annotations

import signal
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = structlog.get_logger()

_DEFAULTS_PATH = Path(__file__).parent / "defaults.yaml"


def _load_yaml_defaults(path: Path) -> dict[str, Any]:
    """Load YAML config file, returning empty dict on failure."""
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


class ProxySettings(BaseSettings):
    """Proxy configuration loaded from YAML defaults, overridden by env vars."""

    model_config = SettingsConfigDict(
        env_prefix="PROXY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    upstream_url: str = "http://localhost:3000"
    listen_port: int = 8080
    redis_url: str = "redis://localhost:6379"
    postgres_url: str = "postgresql://shieldai:shieldai@localhost:5432/shieldai"
    log_level: str = "info"
    log_json: bool = True
    config_file: str = str(_DEFAULTS_PATH)
    api_key: str = ""

    # Connection pool settings
    redis_pool_size: int = 10
    postgres_pool_min: int = 2
    postgres_pool_max: int = 10

    # Proxy settings
    proxy_timeout: float = 30.0
    shutdown_drain_seconds: int = 30

    # Customer config cache
    config_cache_ttl_seconds: int = 60

    # Rate limiting
    rate_limit_auth_max: int = 500
    rate_limit_global_max: int = 2000
    rate_limit_window_seconds: int = 300

    # Security headers
    header_preset: str = "balanced"

    # Request body limit (10MB default)
    max_body_bytes: int = 10 * 1024 * 1024

    # Response sanitizer: "sanitize" (default), "log_only", "passthrough"
    response_sanitizer_mode: str = "sanitize"

    # Session management
    session_idle_timeout: int = 1800  # 30 minutes
    session_absolute_timeout: int = 86400  # 24 hours
    session_cookie_name: str = "shield_session"
    session_binding_mode: str = "warn"  # "off", "warn", "strict"

    # HTTP client settings
    upstream_max_connections: int = 100
    upstream_max_keepalive: int = 20
    upstream_follow_redirects: bool = False

_settings: ProxySettings | None = None


def get_settings() -> ProxySettings:
    """Get or create the singleton settings instance."""
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def load_settings() -> ProxySettings:
    """Load settings from env vars (env vars override model defaults)."""
    global _settings
    _settings = ProxySettings()
    logger.info("config_loaded", upstream_url=_settings.upstream_url, port=_settings.listen_port)
    return _settings


def register_reload_handler() -> None:
    """Register SIGHUP handler for hot-reload of configuration."""
    import threading

    if threading.current_thread() is not threading.main_thread():
        logger.debug("skipping_sighup_handler", reason="not main thread")
        return

    def _reload(signum, frame):
        logger.info("config_reload_triggered")
        load_settings()

    try:
        signal.signal(signal.SIGHUP, _reload)
    except ValueError:
        logger.debug("skipping_sighup_handler", reason="signal not supported")
