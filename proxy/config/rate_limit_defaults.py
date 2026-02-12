"""Default rate-limit thresholds and auth-endpoint patterns."""

from __future__ import annotations

import re

# Regex patterns that identify authentication endpoints (case-insensitive)
AUTH_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"/auth/", re.IGNORECASE),
    re.compile(r"/login", re.IGNORECASE),
    re.compile(r"/signup", re.IGNORECASE),
    re.compile(r"/register", re.IGNORECASE),
    re.compile(r"/token", re.IGNORECASE),
    re.compile(r"/oauth/", re.IGNORECASE),
    re.compile(r"/password", re.IGNORECASE),
    re.compile(r"/session", re.IGNORECASE),
]

# Default thresholds
AUTH_RATE_LIMIT = 500  # requests per window for auth endpoints
GLOBAL_RATE_LIMIT = 2000  # requests per window for all endpoints
WINDOW_SECONDS = 300  # 5-minute sliding window


def is_auth_endpoint(path: str) -> bool:
    """Return True if the path matches an authentication endpoint pattern."""
    return any(pattern.search(path) for pattern in AUTH_PATH_PATTERNS)
