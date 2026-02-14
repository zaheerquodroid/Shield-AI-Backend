"""Onboarding PostgreSQL storage — CRUD for customer domain onboarding records.

Tenant-scoped operations use ``tenant_transaction`` so that PostgreSQL
Row-Level Security (RLS) policies enforce tenant isolation at the database
level.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog

from proxy.store.postgres import get_pool, StoreUnavailable
from proxy.store.rls import tenant_transaction

logger = structlog.get_logger()

# Whitelisted columns for UPDATE
_ONBOARDING_COLUMNS = frozenset({
    "status", "acm_certificate_arn", "validation_cname_name",
    "validation_cname_value", "distribution_tenant_id", "cloudfront_cname",
    "error_message",
})

_SELECT_COLS = (
    "id, customer_id, customer_domain, origin_url, status, "
    "acm_certificate_arn, validation_cname_name, validation_cname_value, "
    "distribution_tenant_id, cloudfront_cname, error_message, "
    "created_at, updated_at"
)

# Maximum active onboardings per customer (prevent abuse)
MAX_ONBOARDINGS_PER_CUSTOMER = 10


class DuplicateDomain(Exception):
    """Raised when an onboarding insert violates the unique domain constraint."""


async def create_onboarding(
    customer_id: UUID,
    customer_domain: str,
    origin_url: str,
    *,
    acm_certificate_arn: str = "",
    validation_cname_name: str = "",
    validation_cname_value: str = "",
) -> dict[str, Any]:
    """Insert a new onboarding record and return it.

    Raises DuplicateDomain if the unique partial index on customer_domain
    is violated (TOCTOU-safe — the DB enforces uniqueness even under
    concurrent inserts).
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    try:
        async with tenant_transaction(str(customer_id)) as conn:
            row = await conn.fetchrow(
                f"""INSERT INTO onboardings
                    (customer_id, customer_domain, origin_url, status,
                     acm_certificate_arn, validation_cname_name, validation_cname_value)
                    VALUES ($1, $2, $3, 'certificate_pending', $4, $5, $6)
                    RETURNING {_SELECT_COLS}""",
                customer_id, customer_domain, origin_url,
                acm_certificate_arn, validation_cname_name, validation_cname_value,
            )
            return dict(row) if row else {}
    except Exception as exc:
        # asyncpg raises UniqueViolationError (subclass of Exception) when
        # the partial unique index on customer_domain is violated.
        exc_name = type(exc).__name__
        if exc_name == "UniqueViolationError" or "unique" in str(exc).lower():
            raise DuplicateDomain(
                f"Domain {customer_domain} already has an active onboarding"
            ) from exc
        raise


async def get_onboarding(
    onboarding_id: UUID, *, customer_id: UUID | None = None
) -> dict[str, Any] | None:
    """Fetch an onboarding record by ID.

    When customer_id is provided, enforces ownership via RLS — returns None if
    the record belongs to a different customer (prevents IDOR).
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    if customer_id is not None:
        async with tenant_transaction(str(customer_id)) as conn:
            row = await conn.fetchrow(
                f"SELECT {_SELECT_COLS} FROM onboardings WHERE id = $1 AND customer_id = $2",
                onboarding_id, customer_id,
            )
    else:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT {_SELECT_COLS} FROM onboardings WHERE id = $1",
                onboarding_id,
            )
    return dict(row) if row else None


async def list_onboardings(customer_id: UUID) -> list[dict[str, Any]]:
    """List all onboarding records for a customer."""
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with tenant_transaction(str(customer_id)) as conn:
        rows = await conn.fetch(
            f"SELECT {_SELECT_COLS} FROM onboardings WHERE customer_id = $1 ORDER BY created_at DESC",
            customer_id,
        )
        return [dict(r) for r in rows]


async def list_pending_onboardings() -> list[dict[str, Any]]:
    """List all onboardings in certificate_pending status (admin — bypasses RLS).

    Used by the certificate poller background job.
    """
    pool = get_pool()
    if pool is None:
        logger.warning("onboarding_store_no_pool", operation="list_pending")
        return []
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT {_SELECT_COLS} FROM onboardings WHERE status = 'certificate_pending' ORDER BY created_at ASC",
        )
        return [dict(r) for r in rows]


async def list_validated_onboardings() -> list[dict[str, Any]]:
    """List all onboardings in certificate_validated status (admin — bypasses RLS).

    Used by the tenant creator background job.
    """
    pool = get_pool()
    if pool is None:
        logger.warning("onboarding_store_no_pool", operation="list_validated")
        return []
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT {_SELECT_COLS} FROM onboardings WHERE status = 'certificate_validated' ORDER BY created_at ASC",
        )
        return [dict(r) for r in rows]


async def claim_and_update(
    onboarding_id: UUID,
    *,
    expected_status: str,
    new_status: str,
    **fields: Any,
) -> dict[str, Any] | None:
    """Atomically update an onboarding record only if it's in the expected status.

    Returns the updated record, or None if the row was already claimed by
    another poller instance (prevents concurrent duplicate processing).

    This is the ONLY safe way for background jobs to transition status —
    it uses ``WHERE status = $expected`` as an optimistic lock.
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")

    set_clauses = ["status = $1", "updated_at = now()"]
    values: list[Any] = [new_status]
    idx = 2

    for key, val in fields.items():
        if val is not None:
            if key not in _ONBOARDING_COLUMNS:
                raise ValueError(f"Invalid column name: {key}")
            set_clauses.append(f"{key} = ${idx}")
            values.append(val)
            idx += 1

    values.append(onboarding_id)
    values.append(expected_status)
    where = f"WHERE id = ${idx} AND status = ${idx + 1}"

    sql = f"UPDATE onboardings SET {', '.join(set_clauses)} {where} RETURNING {_SELECT_COLS}"

    async with pool.acquire() as conn:
        row = await conn.fetchrow(sql, *values)
    return dict(row) if row else None


async def update_onboarding(
    onboarding_id: UUID, *, customer_id: UUID | None = None, **fields
) -> dict[str, Any] | None:
    """Update an onboarding record. Only non-None, whitelisted fields are updated.

    When customer_id is provided, enforces ownership via RLS.
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    set_clauses = []
    values: list[Any] = []
    idx = 1
    for key, val in fields.items():
        if val is not None:
            if key not in _ONBOARDING_COLUMNS:
                raise ValueError(f"Invalid column name: {key}")
            set_clauses.append(f"{key} = ${idx}")
            values.append(val)
            idx += 1
    if not set_clauses:
        return await get_onboarding(onboarding_id, customer_id=customer_id)
    set_clauses.append("updated_at = now()")
    values.append(onboarding_id)

    if customer_id is not None:
        values.append(customer_id)
        where = f"WHERE id = ${idx} AND customer_id = ${idx + 1}"
    else:
        where = f"WHERE id = ${idx}"

    sql = f"UPDATE onboardings SET {', '.join(set_clauses)} {where} RETURNING {_SELECT_COLS}"

    if customer_id is not None:
        async with tenant_transaction(str(customer_id)) as conn:
            row = await conn.fetchrow(sql, *values)
    else:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(sql, *values)
    return dict(row) if row else None


async def delete_onboarding(
    onboarding_id: UUID, *, customer_id: UUID | None = None
) -> bool:
    """Delete an onboarding record by ID.

    When customer_id is provided, enforces ownership via RLS.
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    if customer_id is not None:
        async with tenant_transaction(str(customer_id)) as conn:
            result = await conn.execute(
                "DELETE FROM onboardings WHERE id = $1 AND customer_id = $2",
                onboarding_id, customer_id,
            )
    else:
        async with pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM onboardings WHERE id = $1",
                onboarding_id,
            )
    return result == "DELETE 1"


async def count_active_onboardings(customer_id: UUID) -> int:
    """Count active (non-offboarded, non-failed) onboardings for a customer."""
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with tenant_transaction(str(customer_id)) as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM onboardings WHERE customer_id = $1 AND status NOT IN ('offboarded', 'failed')",
            customer_id,
        )
        return count or 0


async def get_onboarding_by_domain(customer_domain: str) -> dict[str, Any] | None:
    """Fetch active onboarding by domain (admin — bypasses RLS).

    Used to check for duplicate domain onboardings.
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT {_SELECT_COLS} FROM onboardings WHERE customer_domain = $1 AND status NOT IN ('offboarded', 'failed')",
            customer_domain,
        )
        return dict(row) if row else None
