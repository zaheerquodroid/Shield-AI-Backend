"""Tests for session management: store, validator, and updater."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.pipeline import RequestContext
from proxy.middleware.session_validator import SessionValidator
from proxy.middleware.session_updater import SessionUpdater
from proxy.store.session import (
    _session_key,
    compute_fingerprint,
    create_session,
    delete_session,
    generate_token,
    is_valid_token,
    load_session,
    update_activity,
)

# Valid token for testing (64 hex chars)
_VALID_TOKEN = "a" * 64


# ── Helpers ────────────────────────────────────────────────────────────


def _make_request(
    path: str = "/",
    method: str = "GET",
    cookies: dict | None = None,
    headers: dict | None = None,
) -> Request:
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode(), v.encode()))
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        raw_headers.append((b"cookie", cookie_str.encode()))

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": raw_headers,
        "root_path": "",
        "server": ("localhost", 8080),
        "client": ("192.168.1.100", 12345),
    }
    return Request(scope)


def _make_context(
    session_validation: bool = True,
    session_cfg: dict | None = None,
    tenant_id: str = "tenant-1",
) -> RequestContext:
    ctx = RequestContext(tenant_id=tenant_id)
    settings: dict = {}
    if session_cfg:
        settings["session"] = session_cfg
    ctx.customer_config = {
        "enabled_features": {"session_validation": session_validation},
        "settings": settings,
    }
    return ctx


def _mock_redis():
    """Create a mock Redis instance with pipeline support."""
    from unittest.mock import MagicMock

    redis = AsyncMock()
    # Pipeline: redis.pipeline() is sync, pipe.hset/expire are sync (queue),
    # pipe.execute() is async.
    pipe = MagicMock()
    pipe.execute = AsyncMock(return_value=[True, True])
    redis.pipeline = MagicMock(return_value=pipe)
    return redis


def _make_session_data(
    tenant_id: str = "tenant-1",
    user_id: str = "user-1",
    ip: str = "192.168.1.100",
    user_agent: str = "TestAgent/1.0",
    created_at: int | None = None,
    last_activity: int | None = None,
) -> dict[str, str]:
    now = int(time.time())
    fp = compute_fingerprint(ip, user_agent)
    return {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "fingerprint": fp,
        "last_activity": str(last_activity or now),
        "created_at": str(created_at or now),
        "ip": ip,
        "user_agent": user_agent,
    }


# ══════════════════════════════════════════════════════════════════════
# Session Store Tests
# ══════════════════════════════════════════════════════════════════════


class TestGenerateToken:
    def test_token_length(self):
        token = generate_token()
        assert len(token) == 64  # 32 bytes = 64 hex chars

    def test_tokens_are_unique(self):
        tokens = {generate_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_token_is_hex(self):
        token = generate_token()
        int(token, 16)  # should not raise


class TestComputeFingerprint:
    def test_deterministic(self):
        fp1 = compute_fingerprint("1.2.3.4", "Mozilla/5.0")
        fp2 = compute_fingerprint("1.2.3.4", "Mozilla/5.0")
        assert fp1 == fp2

    def test_different_ip_different_fingerprint(self):
        fp1 = compute_fingerprint("1.2.3.4", "Mozilla/5.0")
        fp2 = compute_fingerprint("5.6.7.8", "Mozilla/5.0")
        assert fp1 != fp2

    def test_different_ua_different_fingerprint(self):
        fp1 = compute_fingerprint("1.2.3.4", "Mozilla/5.0")
        fp2 = compute_fingerprint("1.2.3.4", "Chrome/100")
        assert fp1 != fp2

    def test_fingerprint_length(self):
        fp = compute_fingerprint("1.2.3.4", "Agent")
        assert len(fp) == 16


class TestSessionKey:
    def test_key_format(self):
        assert _session_key(_VALID_TOKEN) == f"session:{_VALID_TOKEN}"


class TestCreateSession:
    @pytest.mark.asyncio
    async def test_creates_session_in_redis(self):
        redis = _mock_redis()
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await create_session(
                _VALID_TOKEN,
                tenant_id="t1",
                user_id="u1",
                ip="1.2.3.4",
                user_agent="Agent",
            )

        assert result is not None
        assert result["tenant_id"] == "t1"
        assert result["user_id"] == "u1"
        assert result["ip"] == "1.2.3.4"
        assert result["user_agent"] == "Agent"
        assert "fingerprint" in result
        assert "last_activity" in result
        assert "created_at" in result

        # Verify Redis calls
        pipe = redis.pipeline.return_value
        pipe.hset.assert_called_once()
        pipe.expire.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_none_when_no_redis(self):
        with patch("proxy.store.session.get_redis", return_value=None):
            result = await create_session(
                _VALID_TOKEN, tenant_id="t", user_id="u", ip="1.1.1.1", user_agent="A"
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_redis_error(self):
        redis = _mock_redis()
        redis.pipeline.return_value.execute = AsyncMock(side_effect=Exception("connection lost"))
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await create_session(
                _VALID_TOKEN, tenant_id="t", user_id="u", ip="1.1.1.1", user_agent="A"
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_ttl_set_to_absolute_timeout(self):
        redis = _mock_redis()
        with patch("proxy.store.session.get_redis", return_value=redis):
            await create_session(
                _VALID_TOKEN,
                tenant_id="t",
                user_id="u",
                ip="1.1.1.1",
                user_agent="A",
                absolute_timeout=7200,
            )
        pipe = redis.pipeline.return_value
        pipe.expire.assert_called_once_with(f"session:{_VALID_TOKEN}", 7200)


class TestLoadSession:
    @pytest.mark.asyncio
    async def test_loads_existing_session(self):
        redis = AsyncMock()
        session_data = {"tenant_id": "t1", "user_id": "u1"}
        redis.hgetall = AsyncMock(return_value=session_data)
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await load_session(_VALID_TOKEN)
        assert result == session_data
        redis.hgetall.assert_called_once_with(f"session:{_VALID_TOKEN}")

    @pytest.mark.asyncio
    async def test_returns_none_for_missing_session(self):
        redis = AsyncMock()
        redis.hgetall = AsyncMock(return_value={})
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await load_session("b" * 64)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_redis(self):
        with patch("proxy.store.session.get_redis", return_value=None):
            result = await load_session(_VALID_TOKEN)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_redis_error(self):
        redis = AsyncMock()
        redis.hgetall = AsyncMock(side_effect=Exception("timeout"))
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await load_session(_VALID_TOKEN)
        assert result is None


class TestUpdateActivity:
    @pytest.mark.asyncio
    async def test_updates_last_activity(self):
        redis = AsyncMock()
        redis.hset = AsyncMock(return_value=0)
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await update_activity(_VALID_TOKEN)
        assert result is True
        redis.hset.assert_called_once()
        args = redis.hset.call_args
        assert args[0][0] == f"session:{_VALID_TOKEN}"
        assert args[0][1] == "last_activity"

    @pytest.mark.asyncio
    async def test_returns_false_when_no_redis(self):
        with patch("proxy.store.session.get_redis", return_value=None):
            result = await update_activity(_VALID_TOKEN)
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_error(self):
        redis = AsyncMock()
        redis.hset = AsyncMock(side_effect=Exception("err"))
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await update_activity(_VALID_TOKEN)
        assert result is False


class TestDeleteSession:
    @pytest.mark.asyncio
    async def test_deletes_existing_session(self):
        redis = AsyncMock()
        redis.delete = AsyncMock(return_value=1)
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await delete_session(_VALID_TOKEN)
        assert result is True
        redis.delete.assert_called_once_with(f"session:{_VALID_TOKEN}")

    @pytest.mark.asyncio
    async def test_returns_false_for_missing_session(self):
        redis = AsyncMock()
        redis.delete = AsyncMock(return_value=0)
        with patch("proxy.store.session.get_redis", return_value=redis):
            result = await delete_session("b" * 64)
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_when_no_redis(self):
        with patch("proxy.store.session.get_redis", return_value=None):
            result = await delete_session(_VALID_TOKEN)
        assert result is False


# ══════════════════════════════════════════════════════════════════════
# SessionValidator Middleware Tests
# ══════════════════════════════════════════════════════════════════════


class TestSessionValidatorNoCookie:
    @pytest.mark.asyncio
    async def test_no_cookie_passes_through(self):
        """Requests without a session cookie should pass through."""
        mw = SessionValidator()
        ctx = _make_context()
        request = _make_request()

        result = await mw.process_request(request, ctx)

        assert result is None  # pass through

    @pytest.mark.asyncio
    async def test_no_cookie_does_not_set_user_id(self):
        """Without a session cookie, user_id should not be set on context."""
        mw = SessionValidator()
        ctx = _make_context()
        request = _make_request()

        await mw.process_request(request, ctx)

        assert ctx.user_id == ""


class TestSessionValidatorValidSession:
    @pytest.mark.asyncio
    async def test_valid_session_passes_through(self):
        """Valid, non-expired session should pass through."""
        mw = SessionValidator()
        ctx = _make_context()
        session = _make_session_data()
        request = _make_request(
            cookies={"shield_session": "valid-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                result = await mw.process_request(request, ctx)

        assert result is None
        assert ctx.user_id == "user-1"
        assert ctx.extra["session_token"] == "valid-token"

    @pytest.mark.asyncio
    async def test_valid_session_updates_activity(self):
        """Valid session should trigger an activity update."""
        mw = SessionValidator()
        ctx = _make_context()
        session = _make_session_data()
        request = _make_request(
            cookies={"shield_session": "valid-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True) as mock_update:
                await mw.process_request(request, ctx)

        mock_update.assert_called_once_with("valid-token")


class TestSessionValidatorIdleTimeout:
    @pytest.mark.asyncio
    async def test_idle_session_rejected(self):
        """Session exceeding idle timeout should return 401."""
        mw = SessionValidator()
        ctx = _make_context()
        # Session with last_activity 2 hours ago
        session = _make_session_data(last_activity=int(time.time()) - 7200)
        request = _make_request(
            cookies={"shield_session": "idle-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401
        body = result.body.decode()
        assert "inactivity" in body

    @pytest.mark.asyncio
    async def test_barely_active_session_passes(self):
        """Session just within idle timeout should pass."""
        mw = SessionValidator()
        ctx = _make_context()
        # Default idle timeout is 1800s (30 min)
        # Last activity 29 minutes ago
        session = _make_session_data(last_activity=int(time.time()) - 1740)
        request = _make_request(
            cookies={"shield_session": "active-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                result = await mw.process_request(request, ctx)

        assert result is None  # passes through

    @pytest.mark.asyncio
    async def test_custom_idle_timeout(self):
        """Customer-configured idle timeout should be respected."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"idle_timeout": 600})  # 10 min
        # Last activity 11 minutes ago — should fail with custom timeout
        session = _make_session_data(last_activity=int(time.time()) - 660)
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401


class TestSessionValidatorAbsoluteTimeout:
    @pytest.mark.asyncio
    async def test_absolute_timeout_exceeded(self):
        """Session exceeding absolute timeout should return 401 even if active."""
        mw = SessionValidator()
        ctx = _make_context()
        # Session created 25 hours ago, but recently active
        now = int(time.time())
        session = _make_session_data(
            created_at=now - 90000,  # 25 hours ago
            last_activity=now - 60,   # 1 minute ago (still "active")
        )
        request = _make_request(
            cookies={"shield_session": "old-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401
        body = result.body.decode()
        assert "expired" in body.lower()

    @pytest.mark.asyncio
    async def test_absolute_timeout_within_limit(self):
        """Session within absolute timeout should pass."""
        mw = SessionValidator()
        ctx = _make_context()
        now = int(time.time())
        session = _make_session_data(
            created_at=now - 3600,    # 1 hour ago
            last_activity=now - 60,
        )
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                result = await mw.process_request(request, ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_custom_absolute_timeout(self):
        """Customer-configured absolute timeout should be respected."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"absolute_timeout": 3600})  # 1 hour
        now = int(time.time())
        session = _make_session_data(
            created_at=now - 3700,  # 1h 1min ago
            last_activity=now - 30,
        )
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401


class TestSessionValidatorNotFound:
    @pytest.mark.asyncio
    async def test_missing_session_returns_401(self):
        """Session token that doesn't exist in Redis should return 401."""
        mw = SessionValidator()
        ctx = _make_context()
        request = _make_request(cookies={"shield_session": "nonexistent"})

        with patch("proxy.middleware.session_validator.load_session", return_value=None):
            result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401


# ── Session binding tests ─────────────────────────────────────────────


class TestSessionBindingWarnMode:
    @pytest.mark.asyncio
    async def test_matching_fingerprint_passes(self):
        """Same IP+UA should pass in warn mode."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "warn"})
        session = _make_session_data(ip="192.168.1.100", user_agent="TestAgent/1.0")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                result = await mw.process_request(request, ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_mismatched_ip_warns_but_passes(self):
        """Different IP should warn but still pass in warn mode."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "warn"})
        # Session created from different IP
        session = _make_session_data(ip="10.0.0.1", user_agent="TestAgent/1.0")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                with patch("proxy.middleware.session_validator.logger") as mock_logger:
                    result = await mw.process_request(request, ctx)

        assert result is None  # warn mode allows through
        mock_logger.warning.assert_called()
        # Verify the warning was about binding mismatch
        call_args = [c[0][0] for c in mock_logger.warning.call_args_list]
        assert "session_binding_mismatch" in call_args


class TestSessionBindingStrictMode:
    @pytest.mark.asyncio
    async def test_matching_fingerprint_passes(self):
        """Same fingerprint passes in strict mode."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "strict"})
        session = _make_session_data(ip="192.168.1.100", user_agent="TestAgent/1.0")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                result = await mw.process_request(request, ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_mismatched_ip_blocked(self):
        """Different IP should return 401 in strict mode."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "strict"})
        session = _make_session_data(ip="10.0.0.1", user_agent="TestAgent/1.0")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401
        body = result.body.decode()
        assert "security violation" in body.lower()

    @pytest.mark.asyncio
    async def test_mismatched_ua_blocked(self):
        """Different User-Agent should return 401 in strict mode."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "strict"})
        session = _make_session_data(ip="192.168.1.100", user_agent="OldBrowser/1.0")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "NewBrowser/2.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401


class TestSessionBindingOffMode:
    @pytest.mark.asyncio
    async def test_binding_off_ignores_mismatch(self):
        """With binding off, different IP/UA should pass without warnings."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "off"})
        session = _make_session_data(ip="10.0.0.1", user_agent="DifferentAgent")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                result = await mw.process_request(request, ctx)

        assert result is None


# ── Feature flag tests ────────────────────────────────────────────────


class TestSessionValidatorFeatureFlag:
    @pytest.mark.asyncio
    async def test_disabled_passes_through(self):
        """When session_validation is disabled, all requests pass through."""
        mw = SessionValidator()
        ctx = _make_context(session_validation=False)
        request = _make_request(cookies={"shield_session": "any-token"})

        result = await mw.process_request(request, ctx)

        assert result is None

    @pytest.mark.asyncio
    async def test_disabled_does_not_load_session(self):
        """When disabled, session should not be loaded from Redis."""
        mw = SessionValidator()
        ctx = _make_context(session_validation=False)
        request = _make_request(cookies={"shield_session": "any-token"})

        with patch("proxy.middleware.session_validator.load_session") as mock_load:
            await mw.process_request(request, ctx)

        mock_load.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_features_defaults_enabled(self):
        """Missing enabled_features defaults to session validation enabled."""
        mw = SessionValidator()
        ctx = RequestContext(tenant_id="t")
        ctx.customer_config = {"settings": {}}  # no enabled_features
        request = _make_request(cookies={"shield_session": "token"})

        with patch("proxy.middleware.session_validator.load_session", return_value=None):
            result = await mw.process_request(request, ctx)

        # Should reject because session not found (but validation IS running)
        assert result is not None
        assert result.status_code == 401


# ══════════════════════════════════════════════════════════════════════
# SessionUpdater Middleware Tests
# ══════════════════════════════════════════════════════════════════════


class TestSessionUpdaterLogin:
    @pytest.mark.asyncio
    async def test_login_creates_session(self):
        """POST to /login with 200 response should create a session."""
        mw = SessionUpdater()
        ctx = _make_context(tenant_id="tenant-1")
        request = _make_request(path="/login", method="POST")

        # First, process request to store path/method
        await mw.process_request(request, ctx)

        response = Response(content='{"token": "app-jwt"}', status_code=200)

        with patch("proxy.middleware.session_updater.create_session", return_value={"tenant_id": "tenant-1"}) as mock_create:
            with patch("proxy.middleware.session_updater.generate_token", return_value="new-session-token"):
                result = await mw.process_response(response, ctx)

        mock_create.assert_called_once()
        # Verify cookie was set
        set_cookie = result.headers.get("set-cookie", "")
        assert "shield_session=new-session-token" in set_cookie
        assert "httponly" in set_cookie.lower()
        assert "secure" in set_cookie.lower()

    @pytest.mark.asyncio
    async def test_login_with_auth_path(self):
        """POST to /auth/login should also create a session."""
        mw = SessionUpdater()
        ctx = _make_context()
        request = _make_request(path="/auth/login", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.create_session", return_value={"tenant_id": "t"}):
            with patch("proxy.middleware.session_updater.generate_token", return_value="tok"):
                result = await mw.process_response(response, ctx)

        assert "shield_session=tok" in result.headers.get("set-cookie", "")

    @pytest.mark.asyncio
    async def test_login_failure_no_session(self):
        """Failed login (401/403) should NOT create a session."""
        mw = SessionUpdater()
        ctx = _make_context()
        request = _make_request(path="/login", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="Unauthorized", status_code=401)

        with patch("proxy.middleware.session_updater.create_session") as mock_create:
            result = await mw.process_response(response, ctx)

        mock_create.assert_not_called()
        assert "shield_session" not in result.headers.get("set-cookie", "")

    @pytest.mark.asyncio
    async def test_get_login_no_session(self):
        """GET to /login should NOT create a session (only POST)."""
        mw = SessionUpdater()
        ctx = _make_context()
        request = _make_request(path="/login", method="GET")
        await mw.process_request(request, ctx)

        response = Response(content="login form", status_code=200)

        with patch("proxy.middleware.session_updater.create_session") as mock_create:
            await mw.process_response(response, ctx)

        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_login_path_no_session(self):
        """POST to /api/data should NOT create a session."""
        mw = SessionUpdater()
        ctx = _make_context()
        request = _make_request(path="/api/data", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.create_session") as mock_create:
            await mw.process_response(response, ctx)

        mock_create.assert_not_called()


class TestSessionUpdaterLogout:
    @pytest.mark.asyncio
    async def test_logout_deletes_session(self):
        """Request to /logout should delete the session and clear cookie."""
        mw = SessionUpdater()
        ctx = _make_context()
        ctx.extra["session_token"] = "existing-token"  # Set by SessionValidator
        request = _make_request(path="/logout", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.delete_session") as mock_delete:
            result = await mw.process_response(response, ctx)

        mock_delete.assert_called_once_with("existing-token")
        # Cookie should be cleared
        set_cookie = result.headers.get("set-cookie", "")
        assert "shield_session" in set_cookie

    @pytest.mark.asyncio
    async def test_logout_get_does_not_trigger(self):
        """GET to /logout should NOT trigger logout (CSRF protection)."""
        mw = SessionUpdater()
        ctx = _make_context()
        ctx.extra["session_token"] = "tok"
        request = _make_request(path="/logout", method="GET")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=302)

        with patch("proxy.middleware.session_updater.delete_session") as mock_delete:
            await mw.process_response(response, ctx)

        mock_delete.assert_not_called()  # GET should not trigger logout

    @pytest.mark.asyncio
    async def test_logout_without_session_token(self):
        """Logout without a session token should not crash."""
        mw = SessionUpdater()
        ctx = _make_context()
        # No session_token in context.extra
        request = _make_request(path="/logout", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.delete_session") as mock_delete:
            result = await mw.process_response(response, ctx)

        mock_delete.assert_not_called()  # No token to delete
        assert result.status_code == 200


class TestSessionUpdaterCustomPaths:
    @pytest.mark.asyncio
    async def test_custom_login_path(self):
        """Customer-configured login path should be used."""
        mw = SessionUpdater()
        ctx = _make_context(session_cfg={
            "login_paths": ["/api/v2/authenticate"],
        })
        request = _make_request(path="/api/v2/authenticate", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.create_session", return_value={"tenant_id": "t"}):
            with patch("proxy.middleware.session_updater.generate_token", return_value="tok"):
                result = await mw.process_response(response, ctx)

        assert "shield_session=tok" in result.headers.get("set-cookie", "")

    @pytest.mark.asyncio
    async def test_custom_logout_path(self):
        """Customer-configured logout path should be used."""
        mw = SessionUpdater()
        ctx = _make_context(session_cfg={
            "logout_paths": ["/api/v2/signout"],
        })
        ctx.extra["session_token"] = "tok"
        request = _make_request(path="/api/v2/signout", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.delete_session") as mock_delete:
            await mw.process_response(response, ctx)

        mock_delete.assert_called_once_with("tok")

    @pytest.mark.asyncio
    async def test_glob_pattern_matching(self):
        """Login paths should support glob patterns."""
        mw = SessionUpdater()
        ctx = _make_context(session_cfg={
            "login_paths": ["/api/*/login"],
        })
        request = _make_request(path="/api/v3/login", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.create_session", return_value={"tenant_id": "t"}):
            with patch("proxy.middleware.session_updater.generate_token", return_value="tok"):
                result = await mw.process_response(response, ctx)

        assert "shield_session=tok" in result.headers.get("set-cookie", "")


class TestSessionUpdaterFeatureFlag:
    @pytest.mark.asyncio
    async def test_disabled_no_session_creation(self):
        """When session_validation disabled, no sessions are created."""
        mw = SessionUpdater()
        ctx = _make_context(session_validation=False)
        request = _make_request(path="/login", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.create_session") as mock_create:
            result = await mw.process_response(response, ctx)

        mock_create.assert_not_called()
        assert "shield_session" not in result.headers.get("set-cookie", "")


class TestSessionUpdaterCookieAttributes:
    @pytest.mark.asyncio
    async def test_cookie_is_httponly(self):
        """Session cookie must be HttpOnly to prevent XSS theft."""
        mw = SessionUpdater()
        ctx = _make_context()
        request = _make_request(path="/login", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.create_session", return_value={"tenant_id": "t"}):
            with patch("proxy.middleware.session_updater.generate_token", return_value="tok"):
                result = await mw.process_response(response, ctx)

        set_cookie = result.headers.get("set-cookie", "").lower()
        assert "httponly" in set_cookie

    @pytest.mark.asyncio
    async def test_cookie_is_secure(self):
        """Session cookie must have Secure flag."""
        mw = SessionUpdater()
        ctx = _make_context()
        request = _make_request(path="/login", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.create_session", return_value={"tenant_id": "t"}):
            with patch("proxy.middleware.session_updater.generate_token", return_value="tok"):
                result = await mw.process_response(response, ctx)

        set_cookie = result.headers.get("set-cookie", "").lower()
        assert "secure" in set_cookie

    @pytest.mark.asyncio
    async def test_cookie_is_samesite_lax(self):
        """Session cookie must have SameSite=Lax."""
        mw = SessionUpdater()
        ctx = _make_context()
        request = _make_request(path="/login", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content="ok", status_code=200)

        with patch("proxy.middleware.session_updater.create_session", return_value={"tenant_id": "t"}):
            with patch("proxy.middleware.session_updater.generate_token", return_value="tok"):
                result = await mw.process_response(response, ctx)

        set_cookie = result.headers.get("set-cookie", "").lower()
        assert "samesite=lax" in set_cookie


class TestSessionUpdaterRedisFailure:
    @pytest.mark.asyncio
    async def test_create_failure_returns_original_response(self):
        """If session creation fails, original response is returned unchanged."""
        mw = SessionUpdater()
        ctx = _make_context()
        request = _make_request(path="/login", method="POST")
        await mw.process_request(request, ctx)

        response = Response(content='{"token": "jwt"}', status_code=200)

        with patch("proxy.middleware.session_updater.create_session", return_value=None):
            with patch("proxy.middleware.session_updater.generate_token", return_value="tok"):
                result = await mw.process_response(response, ctx)

        # No cookie set because session creation failed
        assert "shield_session" not in result.headers.get("set-cookie", "")
        # But original response body is preserved
        assert result.body.decode() == '{"token": "jwt"}'


# ══════════════════════════════════════════════════════════════════════
# Security guarantee tests
# ══════════════════════════════════════════════════════════════════════


class TestSessionSecurityGuarantees:
    def test_token_is_cryptographically_random(self):
        """Session tokens must use secrets module (CSPRNG)."""
        import secrets
        with patch("proxy.store.session.secrets.token_hex", wraps=secrets.token_hex) as mock_secrets:
            generate_token()
        mock_secrets.assert_called_once_with(32)

    @pytest.mark.asyncio
    async def test_expired_session_cannot_bypass_by_updating_activity(self):
        """An expired session should be rejected even if update_activity succeeds."""
        mw = SessionValidator()
        ctx = _make_context()
        # Session with idle timeout exceeded
        session = _make_session_data(last_activity=int(time.time()) - 7200)
        request = _make_request(
            cookies={"shield_session": "expired-token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity") as mock_update:
                result = await mw.process_request(request, ctx)

        # Must reject
        assert result is not None
        assert result.status_code == 401
        # Must NOT update activity for expired sessions
        mock_update.assert_not_called()

    @pytest.mark.asyncio
    async def test_absolute_timeout_checked_before_idle(self):
        """Absolute timeout should be checked first (can't be bypassed by activity)."""
        mw = SessionValidator()
        ctx = _make_context()
        now = int(time.time())
        # Created 25 hours ago but active just now
        session = _make_session_data(
            created_at=now - 90000,
            last_activity=now - 5,
        )
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity") as mock_update:
                result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401
        mock_update.assert_not_called()

    @pytest.mark.asyncio
    async def test_strict_binding_blocks_different_ip(self):
        """Strict binding must block even slightly different client fingerprints."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "strict"})
        # Session from 192.168.1.100 + TestAgent
        session = _make_session_data(ip="192.168.1.100", user_agent="TestAgent/1.0")
        # Request from 192.168.1.101 (IP changed slightly)
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )
        # Override the client IP in scope
        request.scope["client"] = ("192.168.1.101", 12345)

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            result = await mw.process_request(request, ctx)

        assert result is not None
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_binding_mode_falls_back_to_global(self):
        """Invalid binding mode in customer config should fall back to global."""
        mw = SessionValidator()
        ctx = _make_context(session_cfg={"binding_mode": "invalid_mode"})
        # Global default is "warn"
        session = _make_session_data(ip="10.0.0.1", user_agent="Diff")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                result = await mw.process_request(request, ctx)

        # warn mode: allows through with warning
        assert result is None

    @pytest.mark.asyncio
    async def test_redis_failure_on_load_does_not_crash(self):
        """Redis failure during session load should not crash the proxy."""
        mw = SessionValidator()
        ctx = _make_context()
        request = _make_request(cookies={"shield_session": "token"})

        with patch("proxy.middleware.session_validator.load_session", return_value=None):
            result = await mw.process_request(request, ctx)

        # Session not found = 401 (fail-closed, not fail-open)
        assert result is not None
        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_session_validator_populates_context(self):
        """Valid session should set user_id and session info on context."""
        mw = SessionValidator()
        ctx = _make_context()
        session = _make_session_data(user_id="admin-user")
        request = _make_request(
            cookies={"shield_session": "token"},
            headers={"user-agent": "TestAgent/1.0"},
        )

        with patch("proxy.middleware.session_validator.load_session", return_value=session):
            with patch("proxy.middleware.session_validator.update_activity", return_value=True):
                await mw.process_request(request, ctx)

        assert ctx.user_id == "admin-user"
        assert ctx.extra["session_token"] == "token"
        assert ctx.extra["session_tenant_id"] == "tenant-1"
