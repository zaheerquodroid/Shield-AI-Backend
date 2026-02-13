"""Unit tests for proxy.config.audit_actions.classify_action()."""

from __future__ import annotations

import pytest

from proxy.config.audit_actions import classify_action


class TestRateLimited:
    """429 status → rate_limited, blocked."""

    def test_429_get(self):
        action, blocked = classify_action("GET", "/api/data", 429, False)
        assert action == "rate_limited"
        assert blocked is True

    def test_429_post_auth(self):
        action, blocked = classify_action("POST", "/auth/login", 429, False)
        assert action == "rate_limited"
        assert blocked is True


class TestWafBlocked:
    """waf_blocked flag in context_extra → waf_blocked."""

    def test_waf_blocked(self):
        action, blocked = classify_action("GET", "/", 403, False, {"waf_blocked": True})
        assert action == "waf_blocked"
        assert blocked is True

    def test_waf_not_blocked(self):
        action, blocked = classify_action("GET", "/", 200, False, {"waf_blocked": False})
        assert action != "waf_blocked"


class TestSessionBlocked:
    """session_blocked flag in context_extra → session_blocked."""

    def test_session_blocked(self):
        action, blocked = classify_action("GET", "/", 401, False, {"session_blocked": True})
        assert action == "session_blocked"
        assert blocked is True


class TestLoginAttempt:
    """POST to auth endpoint → login_attempt."""

    @pytest.mark.parametrize("path", ["/auth/login", "/login", "/api/auth/token"])
    def test_post_auth(self, path):
        action, blocked = classify_action("POST", path, 200, False)
        assert action == "login_attempt"
        assert blocked is False


class TestAuthAccess:
    """GET to auth endpoint → auth_access."""

    def test_get_auth(self):
        action, blocked = classify_action("GET", "/auth/login", 200, False)
        assert action == "auth_access"
        assert blocked is False


class TestApiRead:
    """GET/HEAD/OPTIONS → api_read."""

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
    def test_read_methods(self, method):
        action, blocked = classify_action(method, "/api/data", 200, False)
        assert action == "api_read"
        assert blocked is False


class TestApiWrite:
    """POST/PUT/PATCH → api_write."""

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
    def test_write_methods(self, method):
        action, blocked = classify_action(method, "/api/data", 200, False)
        assert action == "api_write"
        assert blocked is False


class TestApiDelete:
    """DELETE → api_delete."""

    def test_delete(self):
        action, blocked = classify_action("DELETE", "/api/data/1", 200, False)
        assert action == "api_delete"
        assert blocked is False


class TestExplicitBlocked:
    """blocked=True with non-specific status → request, blocked."""

    def test_explicit_blocked(self):
        action, blocked = classify_action("GET", "/api/data", 200, True)
        assert action == "request"
        assert blocked is True


class TestPriorityOrder:
    """429 takes priority over waf_blocked and auth endpoints."""

    def test_429_over_waf(self):
        action, _ = classify_action("GET", "/", 429, False, {"waf_blocked": True})
        assert action == "rate_limited"

    def test_429_over_auth(self):
        action, _ = classify_action("POST", "/auth/login", 429, False)
        assert action == "rate_limited"

    def test_waf_over_session(self):
        action, _ = classify_action("GET", "/", 401, False, {"waf_blocked": True, "session_blocked": True})
        assert action == "waf_blocked"
