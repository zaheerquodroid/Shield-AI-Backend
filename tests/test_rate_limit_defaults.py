"""Tests for rate limit defaults and auth endpoint detection."""

from __future__ import annotations

import pytest

from proxy.config.rate_limit_defaults import (
    AUTH_PATH_PATTERNS,
    AUTH_RATE_LIMIT,
    GLOBAL_RATE_LIMIT,
    WINDOW_SECONDS,
    is_auth_endpoint,
)


class TestAuthEndpointPatterns:
    """All 8 AUTH_PATH_PATTERNS are correctly detected."""

    def test_auth_slash(self):
        assert is_auth_endpoint("/auth/login") is True

    def test_auth_callback(self):
        assert is_auth_endpoint("/auth/callback") is True

    def test_login(self):
        assert is_auth_endpoint("/login") is True

    def test_signup(self):
        assert is_auth_endpoint("/signup") is True

    def test_register(self):
        assert is_auth_endpoint("/register") is True

    def test_token(self):
        assert is_auth_endpoint("/token") is True

    def test_token_refresh(self):
        assert is_auth_endpoint("/token/refresh") is True

    def test_oauth_authorize(self):
        assert is_auth_endpoint("/oauth/authorize") is True

    def test_oauth_token(self):
        assert is_auth_endpoint("/oauth/token") is True

    def test_password(self):
        assert is_auth_endpoint("/password") is True

    def test_password_reset(self):
        assert is_auth_endpoint("/password/reset") is True

    def test_session(self):
        assert is_auth_endpoint("/session") is True

    def test_session_start(self):
        assert is_auth_endpoint("/session/start") is True


class TestAuthEndpointCaseInsensitive:
    """Patterns are case-insensitive."""

    def test_uppercase_login(self):
        assert is_auth_endpoint("/LOGIN") is True

    def test_mixed_case_auth(self):
        assert is_auth_endpoint("/Auth/Login") is True

    def test_uppercase_signup(self):
        assert is_auth_endpoint("/SIGNUP") is True

    def test_uppercase_token(self):
        assert is_auth_endpoint("/TOKEN") is True


class TestAuthEndpointNestedPaths:
    """Auth patterns in nested path segments."""

    def test_api_prefix_auth(self):
        assert is_auth_endpoint("/api/auth/login") is True

    def test_v1_prefix_login(self):
        assert is_auth_endpoint("/v1/login") is True

    def test_api_v2_signup(self):
        assert is_auth_endpoint("/api/v2/signup") is True

    def test_deep_nested_register(self):
        assert is_auth_endpoint("/app/api/v1/register") is True

    def test_api_oauth_flow(self):
        assert is_auth_endpoint("/api/oauth/callback") is True


class TestNonAuthEndpoints:
    """Non-auth endpoints should not match."""

    def test_root_path(self):
        assert is_auth_endpoint("/") is False

    def test_api_users(self):
        assert is_auth_endpoint("/api/users") is False

    def test_api_data(self):
        assert is_auth_endpoint("/api/data") is False

    def test_health(self):
        assert is_auth_endpoint("/health") is False

    def test_empty_path(self):
        assert is_auth_endpoint("") is False

    def test_static_assets(self):
        assert is_auth_endpoint("/static/app.js") is False

    def test_dashboard(self):
        assert is_auth_endpoint("/dashboard") is False

    def test_settings_page(self):
        assert is_auth_endpoint("/settings") is False


class TestDefaultThresholds:
    """Default threshold constants are reasonable."""

    def test_auth_rate_limit(self):
        assert AUTH_RATE_LIMIT == 500

    def test_global_rate_limit(self):
        assert GLOBAL_RATE_LIMIT == 2000

    def test_window_seconds(self):
        assert WINDOW_SECONDS == 300  # 5 minutes

    def test_auth_is_lower_than_global(self):
        assert AUTH_RATE_LIMIT < GLOBAL_RATE_LIMIT

    def test_all_patterns_compiled(self):
        """All patterns are pre-compiled re.Pattern objects."""
        import re

        assert len(AUTH_PATH_PATTERNS) == 8
        for pattern in AUTH_PATH_PATTERNS:
            assert isinstance(pattern, re.Pattern)
