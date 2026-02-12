"""Health and readiness endpoint tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from proxy.main import app


@pytest.fixture
def health_client():
    """Test client for health endpoints."""
    import proxy.main as main_module
    main_module._pipeline = None
    main_module._http_client = None
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    main_module._http_client = None
    main_module._pipeline = None


def test_health_all_up(health_client):
    """Health returns healthy when all deps are up."""
    with (
        patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=True),
        patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
    ):
        resp = health_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["proxy"] == "up"
    assert data["redis"] == "up"
    assert data["upstream"] == "up"


def test_health_redis_down(health_client):
    """Health returns degraded when Redis is down."""
    with (
        patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=False),
        patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
    ):
        resp = health_client.get("/health")
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["redis"] == "down"


def test_health_upstream_down(health_client):
    """Health returns degraded when upstream is down."""
    with (
        patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=True),
        patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=False),
    ):
        resp = health_client.get("/health")
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["upstream"] == "down"


def test_ready_all_up(health_client):
    """Ready returns 200 when all deps are up."""
    with (
        patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=True),
        patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
    ):
        resp = health_client.get("/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


def test_ready_not_ready(health_client):
    """Ready returns 503 when deps are down."""
    with (
        patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=False),
        patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=False),
    ):
        resp = health_client.get("/ready")
    assert resp.status_code == 503
    assert resp.json()["status"] == "not_ready"


# --- Edge cases ---


def test_health_both_down(health_client):
    """Health returns degraded with both deps down."""
    with (
        patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=False),
        patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=False),
    ):
        resp = health_client.get("/health")
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["redis"] == "down"
    assert data["upstream"] == "down"
    assert data["proxy"] == "up"  # proxy itself is always up


def test_ready_redis_down_only(health_client):
    """Ready returns 503 when only Redis is down."""
    with (
        patch("proxy.health.redis_store.ping", new_callable=AsyncMock, return_value=False),
        patch("proxy.health._check_upstream", new_callable=AsyncMock, return_value=True),
    ):
        resp = health_client.get("/ready")
    assert resp.status_code == 503
    data = resp.json()
    assert data["redis"] == "down"
    assert data["upstream"] == "up"


@pytest.mark.asyncio
async def test_check_upstream_returns_true_for_4xx():
    """_check_upstream considers 4xx as 'up' (server is responding)."""
    import httpx
    from proxy.health import _check_upstream

    mock_response = httpx.Response(status_code=404)
    with patch("httpx.AsyncClient") as mock_class:
        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_class.return_value = mock_client
        result = await _check_upstream()
    assert result is True


@pytest.mark.asyncio
async def test_check_upstream_returns_false_for_5xx():
    """_check_upstream considers 5xx as 'down'."""
    import httpx
    from proxy.health import _check_upstream

    mock_response = httpx.Response(status_code=500)
    with patch("httpx.AsyncClient") as mock_class:
        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_class.return_value = mock_client
        result = await _check_upstream()
    assert result is False


@pytest.mark.asyncio
async def test_check_upstream_returns_false_on_exception():
    """_check_upstream returns False on connection error."""
    from proxy.health import _check_upstream

    with patch("httpx.AsyncClient") as mock_class:
        mock_client = AsyncMock()
        mock_client.head = AsyncMock(side_effect=Exception("connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_class.return_value = mock_client
        result = await _check_upstream()
    assert result is False
