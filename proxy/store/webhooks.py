"""Webhook PostgreSQL storage — CRUD for webhook configurations."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog

from proxy.store.postgres import get_pool, StoreUnavailable

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
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO webhooks (customer_id, name, url, provider, events, secret, enabled)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, customer_id, name, url, provider, events, enabled, created_at, updated_at""",
            customer_id, name, url, provider, events or [], secret, enabled,
        )
        return dict(row) if row else {}


async def get_webhook(webhook_id: UUID, *, customer_id: UUID | None = None) -> dict[str, Any] | None:
    """Fetch a webhook by ID (without secret).

    When customer_id is provided, enforces ownership — returns None if the
    webhook belongs to a different customer (prevents IDOR).
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with pool.acquire() as conn:
        if customer_id is not None:
            row = await conn.fetchrow(
                "SELECT id, customer_id, name, url, provider, events, enabled, created_at, updated_at FROM webhooks WHERE id = $1 AND customer_id = $2",
                webhook_id, customer_id,
            )
        else:
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
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, customer_id, name, url, provider, events, enabled, created_at, updated_at FROM webhooks WHERE customer_id = $1 ORDER BY created_at",
            customer_id,
        )
        return [dict(r) for r in rows]


async def update_webhook(webhook_id: UUID, *, customer_id: UUID | None = None, **fields) -> dict[str, Any] | None:
    """Update a webhook. Only non-None, whitelisted fields are updated.

    When customer_id is provided, enforces ownership — returns None if the
    webhook belongs to a different customer (prevents IDOR).
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
    async with pool.acquire() as conn:
        row = await conn.fetchrow(sql, *values)
        return dict(row) if row else None


async def delete_webhook(webhook_id: UUID, *, customer_id: UUID | None = None) -> bool:
    """Delete a webhook by ID.

    When customer_id is provided, enforces ownership — returns False if the
    webhook belongs to a different customer (prevents IDOR).
    """
    pool = get_pool()
    if pool is None:
        raise StoreUnavailable("Database connection pool not initialized")
    async with pool.acquire() as conn:
        if customer_id is not None:
            result = await conn.execute(
                "DELETE FROM webhooks WHERE id = $1 AND customer_id = $2",
                webhook_id, customer_id,
            )
        else:
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
        return []
    async with pool.acquire() as conn:
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
