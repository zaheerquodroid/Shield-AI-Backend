"""Redis-backed session store for proxy-managed sessions."""

from __future__ import annotations

import hashlib
import re
import secrets
import time

import structlog

from proxy.store.redis import get_redis

logger = structlog.get_logger()

# Redis key prefix for sessions
_KEY_PREFIX = "session"

# Token length in bytes (32 bytes = 64 hex chars)
_TOKEN_BYTES = 32

# Valid token format: exactly 64 lowercase hex characters
_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def generate_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_hex(_TOKEN_BYTES)


def compute_fingerprint(ip: str, user_agent: str) -> str:
    """Compute a deterministic fingerprint from IP + User-Agent.

    Uses SHA-256 for collision resistance. The fingerprint is used
    for session binding (anti-hijacking).
    """
    raw = f"{ip}|{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _session_key(token: str) -> str:
    """Build the Redis key for a session."""
    return f"{_KEY_PREFIX}:{token}"


async def create_session(
    token: str,
    *,
    tenant_id: str,
    user_id: str,
    ip: str,
    user_agent: str,
    idle_timeout: int = 1800,
    absolute_timeout: int = 86400,
) -> dict[str, str] | None:
    """Create a new session in Redis.

    Args:
        token: Session token (from generate_token).
        tenant_id: Customer tenant identifier.
        user_id: Authenticated user identifier.
        ip: Client IP address.
        user_agent: Client User-Agent header.
        idle_timeout: Seconds of inactivity before expiry (default 30 min).
        absolute_timeout: Seconds from creation before forced expiry (default 24h).

    Returns:
        Session data dict on success, None on Redis failure.
    """
    redis = get_redis()
    if redis is None:
        logger.warning("session_create_no_redis")
        return None

    now = str(int(time.time()))
    fingerprint = compute_fingerprint(ip, user_agent)

    session_data = {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "fingerprint": fingerprint,
        "last_activity": now,
        "created_at": now,
        "ip": ip,
        "user_agent": user_agent,
    }

    key = _session_key(token)
    # TTL = absolute timeout (hard upper bound)
    ttl = absolute_timeout

    try:
        pipe = redis.pipeline()
        pipe.hset(key, mapping=session_data)
        pipe.expire(key, ttl)
        await pipe.execute()
        logger.info(
            "session_created",
            tenant_id=tenant_id,
            user_id=user_id,
            idle_timeout=idle_timeout,
            absolute_timeout=absolute_timeout,
        )
        return session_data
    except Exception as exc:
        logger.error("session_create_error", error=str(exc))
        return None


def is_valid_token(token: str) -> bool:
    """Check if a token matches the expected format (64 hex chars)."""
    return bool(_TOKEN_PATTERN.match(token))


async def load_session(token: str) -> dict[str, str] | None:
    """Load session data from Redis.

    Returns:
        Session data dict if found, None if not found, invalid token, or Redis unavailable.
    """
    # Validate token format before touching Redis — prevents oversized/malicious keys
    if not is_valid_token(token):
        logger.warning("session_invalid_token_format", token_length=len(token))
        return None

    redis = get_redis()
    if redis is None:
        return None

    try:
        data = await redis.hgetall(_session_key(token))
        return data if data else None
    except Exception as exc:
        logger.error("session_load_error", error=str(exc))
        return None


async def update_activity(token: str) -> bool:
    """Update the last_activity timestamp for a session.

    Returns:
        True on success, False on failure.
    """
    redis = get_redis()
    if redis is None:
        return False

    try:
        now = str(int(time.time()))
        result = await redis.hset(_session_key(token), "last_activity", now)
        return result is not None
    except Exception as exc:
        logger.error("session_update_error", error=str(exc))
        return False


async def delete_session(token: str) -> bool:
    """Delete a session from Redis.

    Returns:
        True if session was deleted, False if not found or error.
    """
    redis = get_redis()
    if redis is None:
        return False

    try:
        result = await redis.delete(_session_key(token))
        if result:
            logger.info("session_deleted", token_prefix=token[:8])
        return bool(result)
    except Exception as exc:
        logger.error("session_delete_error", error=str(exc))
        return False
