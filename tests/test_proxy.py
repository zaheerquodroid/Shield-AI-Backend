"""Reverse proxy forwarding tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from proxy.main import app, _build_pipeline
from proxy.middleware.pipeline import RequestContext


@pytest.fixture
def proxy_client():
    """Test client with mocked HTTP client and pipeline."""
    import proxy.main as main_module

    mock_response = httpx.Response(
        status_code=200,
        headers={"content-type": "application/json", "x-custom": "value"},
        content=b'{"message": "upstream response"}',
    )

    mock_http = AsyncMock()
    mock_http.request = AsyncMock(return_value=mock_response)

    with TestClient(app, raise_server_exceptions=False) as c:
        # Set mocks AFTER lifespan runs so they don't get overwritten
        main_module._http_client = mock_http
        main_module._pipeline = _build_pipeline()
        yield c, mock_http

    main_module._http_client = None
    main_module._pipeline = None


def test_get_forwarding(proxy_client):
    """GET requests are forwarded to upstream."""
    client, mock_http = proxy_client
    resp = client.get("/api/users")
    assert resp.status_code == 200
    assert resp.json()["message"] == "upstream response"
    mock_http.request.assert_called_once()
    call_kwargs = mock_http.request.call_args
    assert call_kwargs.kwargs["method"] == "GET"
    assert "/api/users" in call_kwargs.kwargs["url"]


def test_post_forwarding(proxy_client):
    """POST requests forward body to upstream."""
    client, mock_http = proxy_client
    resp = client.post("/api/users", json={"name": "test"})
    assert resp.status_code == 200
    call_kwargs = mock_http.request.call_args
    assert call_kwargs.kwargs["method"] == "POST"


def test_put_forwarding(proxy_client):
    """PUT requests are forwarded."""
    client, mock_http = proxy_client
    resp = client.put("/api/users/1", json={"name": "updated"})
    assert resp.status_code == 200
    call_kwargs = mock_http.request.call_args
    assert call_kwargs.kwargs["method"] == "PUT"


def test_delete_forwarding(proxy_client):
    """DELETE requests are forwarded."""
    client, mock_http = proxy_client
    resp = client.delete("/api/users/1")
    assert resp.status_code == 200
    call_kwargs = mock_http.request.call_args
    assert call_kwargs.kwargs["method"] == "DELETE"


def test_header_preservation(proxy_client):
    """Custom headers are forwarded to upstream."""
    client, mock_http = proxy_client
    resp = client.get("/test", headers={"X-Custom-Header": "test-value"})
    assert resp.status_code == 200
    call_kwargs = mock_http.request.call_args
    forwarded_headers = call_kwargs.kwargs["headers"]
    assert forwarded_headers.get("x-custom-header") == "test-value"


def test_response_headers_preserved(proxy_client):
    """Upstream response headers are passed through."""
    client, _ = proxy_client
    resp = client.get("/test")
    assert resp.headers.get("x-custom") == "value"


def test_query_string_forwarding(proxy_client):
    """Query strings are forwarded to upstream."""
    client, mock_http = proxy_client
    resp = client.get("/search?q=test&page=1")
    assert resp.status_code == 200
    url = mock_http.request.call_args.kwargs["url"]
    assert "q=test" in url
    assert "page=1" in url


def test_request_id_in_response(proxy_client):
    """Response includes X-Request-ID header."""
    client, _ = proxy_client
    resp = client.get("/test")
    assert "x-request-id" in resp.headers


def test_hop_by_hop_headers_stripped(proxy_client):
    """Hop-by-hop headers are not forwarded."""
    client, mock_http = proxy_client
    resp = client.get("/test", headers={"Connection": "keep-alive"})
    call_kwargs = mock_http.request.call_args
    forwarded_headers = call_kwargs.kwargs["headers"]
    assert "connection" not in forwarded_headers


def test_upstream_timeout():
    """Upstream timeout returns 504."""
    import proxy.main as main_module

    mock_http = AsyncMock()
    mock_http.request = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

    with TestClient(app, raise_server_exceptions=False) as client:
        main_module._http_client = mock_http
        main_module._pipeline = _build_pipeline()
        resp = client.get("/test")
        assert resp.status_code == 504

    main_module._http_client = None
    main_module._pipeline = None


def test_upstream_unreachable():
    """Upstream connection error returns 502."""
    import proxy.main as main_module

    mock_http = AsyncMock()
    mock_http.request = AsyncMock(side_effect=httpx.ConnectError("refused"))

    with TestClient(app, raise_server_exceptions=False) as client:
        main_module._http_client = mock_http
        main_module._pipeline = _build_pipeline()
        resp = client.get("/test")
        assert resp.status_code == 502

    main_module._http_client = None
    main_module._pipeline = None


def test_proxy_not_initialized():
    """Returns 503 when proxy client is not initialized."""
    import proxy.main as main_module

    with TestClient(app, raise_server_exceptions=False) as client:
        main_module._http_client = None
        main_module._pipeline = None
        resp = client.get("/test")
        assert resp.status_code == 503


# --- Additional HTTP method tests ---


def test_patch_forwarding(proxy_client):
    """PATCH requests are forwarded."""
    client, mock_http = proxy_client
    resp = client.patch("/api/users/1", json={"name": "patched"})
    assert resp.status_code == 200
    call_kwargs = mock_http.request.call_args
    assert call_kwargs.kwargs["method"] == "PATCH"


def test_head_forwarding(proxy_client):
    """HEAD requests are forwarded."""
    client, mock_http = proxy_client
    resp = client.head("/api/users")
    assert resp.status_code == 200
    call_kwargs = mock_http.request.call_args
    assert call_kwargs.kwargs["method"] == "HEAD"


def test_options_forwarding(proxy_client):
    """OPTIONS requests are forwarded."""
    client, mock_http = proxy_client
    resp = client.options("/api/users")
    assert resp.status_code == 200
    call_kwargs = mock_http.request.call_args
    assert call_kwargs.kwargs["method"] == "OPTIONS"


# --- Generic httpx error handling ---


def test_upstream_read_error():
    """httpx.ReadError returns 502."""
    import proxy.main as main_module

    mock_http = AsyncMock()
    mock_http.request = AsyncMock(side_effect=httpx.ReadError("connection reset"))

    with TestClient(app, raise_server_exceptions=False) as client:
        main_module._http_client = mock_http
        main_module._pipeline = _build_pipeline()
        resp = client.get("/test")
        assert resp.status_code == 502

    main_module._http_client = None
    main_module._pipeline = None


def test_upstream_protocol_error():
    """httpx.ProtocolError returns 502."""
    import proxy.main as main_module

    mock_http = AsyncMock()
    mock_http.request = AsyncMock(side_effect=httpx.ProtocolError("bad response"))

    with TestClient(app, raise_server_exceptions=False) as client:
        main_module._http_client = mock_http
        main_module._pipeline = _build_pipeline()
        resp = client.get("/test")
        assert resp.status_code == 502

    main_module._http_client = None
    main_module._pipeline = None


# --- Edge cases ---


def test_empty_body_post(proxy_client):
    """POST with empty body is forwarded."""
    client, mock_http = proxy_client
    resp = client.post("/api/submit", content=b"")
    assert resp.status_code == 200
    call_kwargs = mock_http.request.call_args
    assert call_kwargs.kwargs["content"] == b""


def test_long_path(proxy_client):
    """Long URL path is forwarded correctly."""
    client, mock_http = proxy_client
    long_path = "/api/" + "a" * 500
    resp = client.get(long_path)
    assert resp.status_code == 200
    url = mock_http.request.call_args.kwargs["url"]
    assert "a" * 500 in url


def test_upstream_5xx_passthrough(proxy_client):
    """5xx from upstream is passed through as-is."""
    client, mock_http = proxy_client
    mock_http.request = AsyncMock(
        return_value=httpx.Response(status_code=500, content=b"Internal Server Error")
    )
    resp = client.get("/test")
    assert resp.status_code == 500


def test_upstream_redirect_not_followed(proxy_client):
    """Upstream 302 is passed through (follow_redirects=False)."""
    client, mock_http = proxy_client
    mock_resp = httpx.Response(
        status_code=302,
        headers={"location": "/other"},
        content=b"",
        request=httpx.Request("GET", "http://mock-upstream:3000/test"),
    )
    mock_http.request = AsyncMock(return_value=mock_resp)
    resp = client.get("/test", follow_redirects=False)
    assert resp.status_code == 302
