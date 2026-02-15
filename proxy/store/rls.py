"""PostgreSQL Row-Level Security (RLS) — tenant isolation at the database level.

Provides a ``tenant_transaction`` async context manager that acquires a
connection from the pool, starts a transaction, switches to the restricted
``shieldai_app`` role, and sets the GUC ``app.current_tenant_id`` so that RLS
policies filter rows automatically.

The pool connection uses the table-owner role (bypasses RLS).  For
tenant-scoped operations the context manager does:

    SET LOCAL ROLE shieldai_app
    SELECT set_config('app.current_tenant_id', $1, true)

Both are transaction-local and auto-revert when the transaction ends.

When ``rls_enabled`` is ``False`` in :class:`~proxy.config.loader.ProxySettings`,
``tenant_transaction`` still validates the tenant ID and acquires a
transactional connection, but skips the ``SET LOCAL ROLE`` / ``set_config``
commands.  This lets operators disable RLS without code changes.
"""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import structlog

from proxy.store.postgres import StoreUnavailable, get_pool

if TYPE_CHECKING:
    import asyncpg

logger = structlog.get_logger()

# The restricted NOLOGIN role subject to RLS policies.
RLS_APP_ROLE = "shieldai_app"

# Strict UUID-v4 pattern (lowercase hex, 8-4-4-4-12 with hyphens).
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

# Strict PostgreSQL identifier: 1-63 chars of [a-z0-9_], starting with letter or underscore.
_PG_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def validate_tenant_id(tenant_id: str) -> str:
    """Validate that *tenant_id* is a well-formed UUID string.

    Returns the normalised (lowercased) tenant ID or raises ``ValueError``.
    """
    if not isinstance(tenant_id, str):
        raise ValueError("tenant_id must be a string")
    normalised = tenant_id.strip().lower()
    if not normalised:
        raise ValueError("tenant_id must not be empty")
    if not _UUID_RE.match(normalised):
        safe_id = tenant_id[:50].encode("ascii", "replace").decode()
        raise ValueError(f"tenant_id is not a valid UUID: {safe_id!r}")
    return normalised


_rls_enabled_cache: bool | None = None


def _is_rls_enabled() -> bool:
    """Check the ``rls_enabled`` setting with caching to avoid per-call import overhead."""
    global _rls_enabled_cache
    if _rls_enabled_cache is not None:
        return _rls_enabled_cache
    from proxy.config.loader import get_settings  # noqa: PLC0415

    _rls_enabled_cache = get_settings().rls_enabled
    return _rls_enabled_cache


def invalidate_rls_cache() -> None:
    """Clear the cached ``rls_enabled`` value. Called on config reload."""
    global _rls_enabled_cache
    _rls_enabled_cache = None


def set_rls_cache(enabled: bool) -> None:
    """Atomically set the cached ``rls_enabled`` value.

    Preferred over :func:`invalidate_rls_cache` during SIGHUP reload to
    eliminate the race window between settings swap and cache invalidation.
    """
    global _rls_enabled_cache
    _rls_enabled_cache = enabled


@asynccontextmanager
async def tenant_transaction(tenant_id: str):
    """Acquire a connection with RLS tenant context.

    Usage::

        async with tenant_transaction(tenant_id) as conn:
            rows = await conn.fetch("SELECT * FROM audit_logs")
            # Only rows belonging to *tenant_id* are visible.

    The ``SET LOCAL ROLE`` and ``set_config`` are both transaction-scoped and
    revert automatically when the block exits.

    When ``rls_enabled`` is ``False``, the tenant ID is still validated but the
    ``SET LOCAL ROLE`` / ``set_config`` commands are skipped.
    """
    validated = validate_tenant_id(tenant_id)
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database pool not initialized")
    async with pool.acquire() as conn:
        async with conn.transaction():
            if _is_rls_enabled():
                await conn.execute(f"SET LOCAL ROLE {RLS_APP_ROLE}")
                await conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, true)",
                    validated,
                )
            else:
                logger.warning(
                    "rls_disabled",
                    tenant_id=validated,
                    msg="RLS is disabled — tenant isolation relies on application-level filters only",
                )
            yield conn


def _validate_pg_identifier(name: str) -> str:
    """Validate that *name* is a safe PostgreSQL identifier.

    DDL statements (``CREATE ROLE``, ``GRANT``) do not support ``$1``
    placeholders, so we must interpolate via f-string.  This guard ensures
    only well-formed identifiers pass through.
    """
    if not isinstance(name, str) or not _PG_IDENT_RE.match(name):
        raise ValueError(f"Invalid PostgreSQL identifier: {name!r}")
    return name


async def ensure_rls_setup(conn: asyncpg.Connection) -> None:
    """Verify that the RLS role and policies are in place (idempotent).

    Intended to be called during migration.  Creates the ``shieldai_app``
    role if it does not exist and grants it membership in ``CURRENT_USER``.
    """
    safe_role = _validate_pg_identifier(RLS_APP_ROLE)

    # Create restricted role if missing
    role_exists = await conn.fetchval(
        "SELECT 1 FROM pg_roles WHERE rolname = $1", safe_role
    )
    if not role_exists:
        await conn.execute(f"CREATE ROLE {safe_role} NOLOGIN")
        logger.info("rls_role_created", role=safe_role)

    # Grant membership so the owner can SET ROLE
    current_user = await conn.fetchval("SELECT current_user")
    safe_user = _validate_pg_identifier(current_user)
    await conn.execute(f"GRANT {safe_role} TO {safe_user}")
    logger.info("rls_setup_verified", app_role=safe_role, owner=safe_user)
