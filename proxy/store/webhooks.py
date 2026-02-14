"""Webhook PostgreSQL storage — CRUD for webhook configurations.

Tenant-scoped operations use ``tenant_transaction`` so that PostgreSQL
Row-Level Security (RLS) policies enforce tenant isolation at the database
level.  When ``customer_id`` is ``None`` (admin access), the pool is used
directly — the owner role bypasses RLS.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog

from proxy.store.postgres import get_pool, StoreUnavailable
from proxy.store.rls import tenant_transaction

logger = structlog.get_logger()

# Whitelisted columns for UPDATE
_WEBHOOK_COLUMNS = frozenset({"name", "url", "provider", "events", "secret", "enabled"})


async def create_webhook(
    customer_id: UUID,
    name: str,
    url: str,
    provider: str = "custom",
    events: list[str] | None = None,
    secret: str = "",
    enabled: bool = True,
) -> dict[str, Any]:
    """Insert a new webhook and return it (without secret)."""
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with tenant_transaction(str(customer_id)) as conn:
        row = await conn.fetchrow(
            """INSERT INTO webhooks (customer_id, name, url, provider, events, secret, enabled)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, customer_id, name, url, provider, events, enabled, created_at, updated_at""",
            customer_id, name, url, provider, events or [], secret, enabled,
        )
        return dict(row) if row else {}


async def get_webhook(webhook_id: UUID, *, customer_id: UUID | None = None) -> dict[str, Any] | None:
    """Fetch a webhook by ID (without secret).

    When customer_id is provided, enforces ownership via RLS — returns None if
    the webhook belongs to a different customer (prevents IDOR).
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    if customer_id is not None:
        async with tenant_transaction(str(customer_id)) as conn:
            row = await conn.fetchrow(
                "SELECT id, customer_id, name, url, provider, events, enabled, created_at, updated_at FROM webhooks WHERE id = $1 AND customer_id = $2",
                webhook_id, customer_id,
            )
    else:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, customer_id, name, url, provider, events, enabled, created_at, updated_at FROM webhooks WHERE id = $1",
                webhook_id,
            )
    return dict(row) if row else None


async def list_webhooks(customer_id: UUID) -> list[dict[str, Any]]:
    """List all webhooks for a customer (without secrets)."""
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with tenant_transaction(str(customer_id)) as conn:
        rows = await conn.fetch(
            "SELECT id, customer_id, name, url, provider, events, enabled, created_at, updated_at FROM webhooks WHERE customer_id = $1 ORDER BY created_at",
            customer_id,
        )
        return [dict(r) for r in rows]


async def update_webhook(webhook_id: UUID, *, customer_id: UUID | None = None, **fields) -> dict[str, Any] | None:
    """Update a webhook. Only non-None, whitelisted fields are updated.

    When customer_id is provided, enforces ownership via RLS — returns None if
    the webhook belongs to a different customer (prevents IDOR).
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    set_clauses = []
    values = []
    idx = 1
    for key, val in fields.items():
        if val is not None:
            if key not in _WEBHOOK_COLUMNS:
                raise ValueError(f"Invalid column name: {key}")
            set_clauses.append(f"{key} = ${idx}")
            values.append(val)
            idx += 1
    if not set_clauses:
        return await get_webhook(webhook_id, customer_id=customer_id)
    set_clauses.append("updated_at = now()")
    values.append(webhook_id)

    if customer_id is not None:
        values.append(customer_id)
        where = f"WHERE id = ${idx} AND customer_id = ${idx + 1}"
    else:
        where = f"WHERE id = ${idx}"

    sql = f"UPDATE webhooks SET {', '.join(set_clauses)} {where} RETURNING id, customer_id, name, url, provider, events, enabled, created_at, updated_at"

    if customer_id is not None:
        async with tenant_transaction(str(customer_id)) as conn:
            row = await conn.fetchrow(sql, *values)
    else:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(sql, *values)
    return dict(row) if row else None


async def delete_webhook(webhook_id: UUID, *, customer_id: UUID | None = None) -> bool:
    """Delete a webhook by ID.

    When customer_id is provided, enforces ownership via RLS — returns False if
    the webhook belongs to a different customer (prevents IDOR).
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    if customer_id is not None:
        async with tenant_transaction(str(customer_id)) as conn:
            result = await conn.execute(
                "DELETE FROM webhooks WHERE id = $1 AND customer_id = $2",
                webhook_id, customer_id,
            )
    else:
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM webhooks WHERE id = $1", webhook_id)
    return result == "DELETE 1"


async def get_enabled_webhooks_for_event(
    customer_id: str, event_type: str
) -> list[dict[str, Any]]:
    """Fetch enabled webhooks that subscribe to a given event type.

    Matches webhooks where events array contains the exact event_type,
    the 'security' meta-event (for security event types), or 'all'.
    """
    pool = get_pool()
    if pool is None:
        return []
    try:
        cid = UUID(customer_id)
    except (ValueError, AttributeError):
        logger.warning("webhook_invalid_customer_id", customer_id=customer_id)
        return []
    async with tenant_transaction(str(cid)) as conn:
        rows = await conn.fetch(
            """SELECT id, url, provider, secret, events
               FROM webhooks
               WHERE customer_id = $1
                 AND enabled = TRUE
                 AND ($2 = ANY(events)
                      OR 'all' = ANY(events)
                      OR 'security' = ANY(events))""",
            cid, event_type,
        )
        return [dict(r) for r in rows]
