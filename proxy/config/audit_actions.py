"""Audit action classification for request/response pairs."""

from __future__ import annotations

from typing import Any

from proxy.config.rate_limit_defaults import is_auth_endpoint


def classify_action(
    method: str,
    path: str,
    status_code: int,
    blocked: bool,
    context_extra: dict[str, Any] | None = None,
) -> tuple[str, bool]:
    """Classify a request into an action category.

    Returns (action_name, is_blocked).

    Priority order:
    1. Blocked statuses (rate_limited, waf_blocked, session_blocked)
    2. Auth endpoints (login_attempt, auth_access)
    3. API methods (api_read, api_write, api_delete)
    4. Fallback: request
    """
    extra = context_extra or {}

    # Check blocked statuses first
    if status_code == 429:
        return ("rate_limited", True)

    if extra.get("waf_blocked"):
        return ("waf_blocked", True)

    if extra.get("session_blocked"):
        return ("session_blocked", True)

    # If explicitly marked blocked by some other mechanism
    if blocked:
        return ("request", True)

    # Auth endpoints
    if is_auth_endpoint(path):
        if method.upper() == "POST":
            return ("login_attempt", False)
        return ("auth_access", False)

    # API methods
    upper = method.upper()
    if upper in ("GET", "HEAD", "OPTIONS"):
        return ("api_read", False)
    if upper in ("POST", "PUT", "PATCH"):
        return ("api_write", False)
    if upper == "DELETE":
        return ("api_delete", False)

    return ("request", False)
