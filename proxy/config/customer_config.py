"""Multi-tenant config service with caching."""

from __future__ import annotations

import asyncio
import copy
import json
import time
from typing import Any

import structlog

from proxy.store import postgres as pg_store

logger = structlog.get_logger()

_DEFAULT_CONFIG: dict[str, Any] = {
    "origin_url": "http://localhost:3000",
    "enabled_features": {
        "waf": True,
        "error_sanitization": True,
        "session_validation": True,
        "audit_logging": True,
        "rate_limiting": True,
        "security_headers": True,
        "bot_protection": False,
        "ssrf_validator": True,
    },
    "settings": {},
}


class CustomerConfigService:
    """Loads and caches per-domain app configuration from PostgreSQL."""

    def __init__(self, cache_ttl: int = 60) -> None:
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_time: float = 0.0
        self._cache_ttl = cache_ttl
        self._poll_task: asyncio.Task | None = None

    async def load_all(self) -> None:
        """Query all apps and build {domain: config} dict."""
        apps = await pg_store.get_all_apps()
        new_cache: dict[str, dict[str, Any]] = {}
        for app in apps:
            domain = app["domain"]
            features = app.get("enabled_features", {})
            if isinstance(features, str):
                features = json.loads(features)
            new_cache[domain] = {
                "app_id": str(app["id"]),
                "customer_id": str(app["customer_id"]),
                "origin_url": app["origin_url"],
                "enabled_features": features,
                "settings": app.get("settings", {}),
            }
        self._cache = new_cache
        self._cache_time = time.monotonic()
        logger.info("customer_config_loaded", domains=len(new_cache))

    def get_config(self, domain: str) -> dict[str, Any]:
        """Return config for a domain, or default config if not found."""
        config = self._cache.get(domain)
        if config is None:
            logger.debug("customer_config_miss", domain=domain)
            return copy.deepcopy(_DEFAULT_CONFIG)
        return config

    def is_stale(self) -> bool:
        """Check if cache is older than TTL."""
        return (time.monotonic() - self._cache_time) > self._cache_ttl

    async def start_polling(self) -> None:
        """Start background task to refresh config cache."""
        self._poll_task = asyncio.create_task(self._poll_loop())

    async def _poll_loop(self) -> None:
        """Periodically refresh the config cache."""
        while True:
            await asyncio.sleep(self._cache_ttl)
            try:
                await self.load_all()
            except Exception as exc:
                logger.error("customer_config_poll_error", error=str(exc))

    async def stop_polling(self) -> None:
        """Stop the background polling task."""
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass


# Module-level singleton
_service: CustomerConfigService | None = None


def get_config_service() -> CustomerConfigService:
    """Get or create the singleton config service."""
    global _service
    if _service is None:
        _service = CustomerConfigService()
    return _service
