"""Shared test fixtures."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _mock_settings(monkeypatch):
    """Provide default settings for all tests."""
    monkeypatch.setenv("PROXY_UPSTREAM_URL", "http://mock-upstream:3000")
    monkeypatch.setenv("PROXY_REDIS_URL", "redis://localhost:6379")
    monkeypatch.setenv("PROXY_POSTGRES_URL", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("PROXY_API_KEY", "test-api-key")
    monkeypatch.setenv("PROXY_LOG_JSON", "false")
    monkeypatch.setenv("PROXY_LOG_LEVEL", "debug")

    # Reset cached settings
    import proxy.config.loader as loader
    loader._settings = None
    yield
    loader._settings = None


@pytest.fixture
def mock_httpx_client():
    """Mock httpx.AsyncClient for proxy tests."""
    with patch("proxy.main._http_client") as mock_client:
        yield mock_client


@pytest.fixture
def mock_redis():
    """Mock Redis connection."""
    with patch("proxy.store.redis._pool") as mock_pool:
        mock_pool.ping = AsyncMock(return_value=True)
        yield mock_pool


@pytest.fixture
def client():
    """Create a FastAPI test client."""
    # Reset module state before creating client
    import proxy.main as main_module
    main_module._pipeline = None
    main_module._http_client = None

    from proxy.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def api_headers():
    """Headers with valid API key for config endpoints."""
    return {"Authorization": "Bearer test-api-key"}
