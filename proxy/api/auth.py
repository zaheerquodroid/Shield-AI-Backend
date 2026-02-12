"""API key authentication for config endpoints."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from proxy.config.loader import get_settings

_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


async def require_api_key(api_key: str | None = Security(_api_key_header)) -> str:
    """Validate the API key from the Authorization header.

    Expects format: 'Bearer <key>'
    """
    settings = get_settings()

    if not settings.api_key:
        raise HTTPException(status_code=500, detail="API key not configured on server")

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # Strip 'Bearer ' prefix if present
    token = api_key
    if token.lower().startswith("bearer "):
        token = token[7:]

    if not hmac.compare_digest(token, settings.api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")

    return token
