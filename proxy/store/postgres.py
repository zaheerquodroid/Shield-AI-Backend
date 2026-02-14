"""PostgreSQL async connection pool and CRUD helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog

logger = structlog.get_logger()

_pool = None

# Whitelisted column names for dynamic UPDATE statements
_CUSTOMER_COLUMNS = frozenset({"name", "plan", "settings"})
_APP_COLUMNS = frozenset({"name", "origin_url", "domain", "enabled_features", "settings"})

# PBKDF2 parameters for API key hashing
_PBKDF2_ITERATIONS = 260_000
_PBKDF2_HASH = "sha256"


class StoreUnavailable(Exception):
    """Raised when the database connection pool is not available."""
    pass

try:
    import asyncpg
except ImportError:
    asyncpg = None


async def init_postgres(url: str, min_size: int = 2, max_size: int = 10):
    """Initialize PostgreSQL connection pool."""
    global _pool
    if asyncpg is None:
        logger.warning("asyncpg_not_installed")
        return None
    try:
        _pool = await asyncpg.create_pool(url, min_size=min_size, max_size=max_size)
        logger.info("postgres_connected", min_size=min_size, max_size=max_size)
        return _pool
    except Exception as exc:
        logger.error("postgres_connect_failed", error=str(exc))
        _pool = None
        return None


def get_pool():
    """Return the current connection pool."""
    return _pool


async def run_migrations() -> None:
    """Execute schema.sql against the database."""
    if _pool is None:
        logger.warning("postgres_migrations_skipped", reason="no pool")
        return
    schema_path = Path(__file__).parent.parent / "models" / "schema.sql"
    sql = schema_path.read_text()
    async with _pool.acquire() as conn:
        await conn.execute(sql)
    logger.info("postgres_migrations_complete")


def hash_api_key(api_key: str) -> str:
    """Hash an API key with PBKDF2 and random salt for storage.

    Returns format: pbkdf2$<salt_hex>$<hash_hex>
    """
    salt = os.urandom(32)
    key_hash = hashlib.pbkdf2_hmac(_PBKDF2_HASH, api_key.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2${salt.hex()}${key_hash.hex()}"


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """Verify an API key against a stored hash (constant-time).

    Supports both PBKDF2 (new) and legacy unsalted SHA-256 hashes.
    """
    if stored_hash.startswith("pbkdf2$"):
        parts = stored_hash.split("$")
        if len(parts) != 3:
            return False
        try:
            salt = bytes.fromhex(parts[1])
            expected = bytes.fromhex(parts[2])
        except ValueError:
            return False
        actual = hashlib.pbkdf2_hmac(_PBKDF2_HASH, api_key.encode(), salt, _PBKDF2_ITERATIONS)
        return hmac.compare_digest(actual, expected)
    else:
        # Legacy SHA-256 (unsalted) — constant-time comparison
        actual = hashlib.sha256(api_key.encode()).hexdigest()
        return hmac.compare_digest(actual, stored_hash)


# --- Customer CRUD ---

async def create_customer(name: str, plan: str, api_key: str, settings: dict) -> dict[str, Any] | None:
    """Insert a new customer and return it."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    key_hash = hash_api_key(api_key)
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO customers (name, plan, api_key_hash, settings)
               VALUES ($1, $2, $3, $4::jsonb)
               RETURNING id, name, plan, settings, created_at, updated_at""",
            name, plan, key_hash, settings,
        )
        return dict(row) if row else None


async def get_customer(customer_id: UUID) -> dict[str, Any] | None:
    """Fetch a customer by ID."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, name, plan, settings, created_at, updated_at FROM customers WHERE id = $1",
            customer_id,
        )
        return dict(row) if row else None


async def update_customer(customer_id: UUID, **fields) -> dict[str, Any] | None:
    """Update a customer. Only non-None, whitelisted fields are updated."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    set_clauses = []
    values = []
    idx = 1
    for key, val in fields.items():
        if val is not None:
            if key not in _CUSTOMER_COLUMNS:
                raise ValueError(f"Invalid column name: {key}")
            set_clauses.append(f"{key} = ${idx}")
            values.append(val)
            idx += 1
    if not set_clauses:
        return await get_customer(customer_id)
    set_clauses.append("updated_at = now()")
    values.append(customer_id)
    sql = f"UPDATE customers SET {', '.join(set_clauses)} WHERE id = ${idx} RETURNING id, name, plan, settings, created_at, updated_at"
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(sql, *values)
        return dict(row) if row else None


async def delete_customer(customer_id: UUID) -> bool:
    """Delete a customer by ID."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with _pool.acquire() as conn:
        result = await conn.execute("DELETE FROM customers WHERE id = $1", customer_id)
        return result == "DELETE 1"


# --- App CRUD ---

async def create_app(customer_id: UUID, name: str, origin_url: str, domain: str,
                     enabled_features: dict, settings: dict) -> dict[str, Any] | None:
    """Insert a new app and return it."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO apps (customer_id, name, origin_url, domain, enabled_features, settings)
               VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)
               RETURNING id, customer_id, name, origin_url, domain, enabled_features, settings, created_at, updated_at""",
            customer_id, name, origin_url, domain, enabled_features, settings,
        )
        return dict(row) if row else None


async def get_app(app_id: UUID) -> dict[str, Any] | None:
    """Fetch an app by ID."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, customer_id, name, origin_url, domain, enabled_features, settings, created_at, updated_at FROM apps WHERE id = $1",
            app_id,
        )
        return dict(row) if row else None


async def get_all_apps() -> list[dict[str, Any]]:
    """Fetch all apps."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, customer_id, name, origin_url, domain, enabled_features, settings, created_at, updated_at FROM apps"
        )
        return [dict(row) for row in rows]


async def update_app(app_id: UUID, **fields) -> dict[str, Any] | None:
    """Update an app. Only non-None, whitelisted fields are updated."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    set_clauses = []
    values = []
    idx = 1
    for key, val in fields.items():
        if val is not None:
            if key not in _APP_COLUMNS:
                raise ValueError(f"Invalid column name: {key}")
            set_clauses.append(f"{key} = ${idx}")
            values.append(val)
            idx += 1
    if not set_clauses:
        return await get_app(app_id)
    set_clauses.append("updated_at = now()")
    values.append(app_id)
    sql = f"UPDATE apps SET {', '.join(set_clauses)} WHERE id = ${idx} RETURNING id, customer_id, name, origin_url, domain, enabled_features, settings, created_at, updated_at"
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(sql, *values)
        return dict(row) if row else None


async def delete_app(app_id: UUID) -> bool:
    """Delete an app by ID."""
    if _pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with _pool.acquire() as conn:
        result = await conn.execute("DELETE FROM apps WHERE id = $1", app_id)
        return result == "DELETE 1"


async def close_postgres() -> None:
    """Close the PostgreSQL connection pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("postgres_closed")


# Re-export RLS helpers for convenience
from proxy.store.rls import (  # noqa: E402, F401
    RLS_APP_ROLE,
    tenant_transaction,
    validate_tenant_id,
)
