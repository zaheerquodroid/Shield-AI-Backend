"""Audit log PostgreSQL storage — fire-and-forget insert, parameterized queries."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from proxy.store.postgres import get_pool

logger = structlog.get_logger()

# Allowed filter columns for query_audit_logs (whitelist for SQL safety)
_FILTER_COLUMNS = frozenset({
    "tenant_id", "app_id", "method", "path", "status_code",
    "action", "blocked", "user_id",
})

_MAX_QUERY_LIMIT = 1000


async def insert_audit_log(
    *,
    tenant_id: str,
    app_id: str,
    request_id: str,
    timestamp: datetime,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    client_ip: str,
    user_agent: str,
    country: str,
    user_id: str,
    action: str,
    blocked: bool,
) -> None:
    """Insert an audit log row. Fire-and-forget: catches all exceptions."""
    pool = get_pool()
    if pool is None:
        logger.warning("audit_insert_skipped", reason="no db pool", tenant_id=tenant_id)
        return
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO audit_logs
                   (tenant_id, app_id, request_id, timestamp, method, path,
                    status_code, duration_ms, client_ip, user_agent, country,
                    user_id, action, blocked)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)""",
                tenant_id, app_id, request_id, timestamp, method, path,
                status_code, duration_ms, client_ip, user_agent, country,
                user_id, action, blocked,
            )
    except Exception:
        logger.exception("audit_insert_failed", tenant_id=tenant_id, request_id=request_id)


async def query_audit_logs(
    *,
    tenant_id: str,
    app_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
    action: str | None = None,
    blocked: bool | None = None,
    user_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Query audit logs with filters. Returns (rows, total_count).

    All filters use parameterized SQL. Limit is clamped to 1000.
    """
    pool = get_pool()
    if pool is None:
        return ([], 0)

    limit = max(1, min(limit, _MAX_QUERY_LIMIT))
    offset = max(0, offset)

    conditions = ["tenant_id = $1"]
    values: list[Any] = [tenant_id]
    idx = 2

    if app_id is not None:
        conditions.append(f"app_id = ${idx}")
        values.append(app_id)
        idx += 1

    if start_time is not None:
        conditions.append(f"timestamp >= ${idx}")
        values.append(start_time)
        idx += 1

    if end_time is not None:
        conditions.append(f"timestamp <= ${idx}")
        values.append(end_time)
        idx += 1

    if method is not None:
        conditions.append(f"method = ${idx}")
        values.append(method.upper())
        idx += 1

    if path is not None:
        conditions.append(f"path LIKE ${idx}")
        # Escape LIKE wildcards so user-supplied % and _ are literal
        escaped = path.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        values.append(f"%{escaped}%")
        idx += 1

    if status_code is not None:
        conditions.append(f"status_code = ${idx}")
        values.append(status_code)
        idx += 1

    if action is not None:
        conditions.append(f"action = ${idx}")
        values.append(action)
        idx += 1

    if blocked is not None:
        conditions.append(f"blocked = ${idx}")
        values.append(blocked)
        idx += 1

    if user_id is not None:
        conditions.append(f"user_id = ${idx}")
        values.append(user_id)
        idx += 1

    where = " AND ".join(conditions)

    async with pool.acquire() as conn:
        count_row = await conn.fetchrow(
            f"SELECT COUNT(*) AS total FROM audit_logs WHERE {where}",
            *values,
        )
        total = count_row["total"] if count_row else 0

        rows = await conn.fetch(
            f"SELECT * FROM audit_logs WHERE {where} ORDER BY timestamp DESC LIMIT ${idx} OFFSET ${idx + 1}",
            *values, limit, offset,
        )

    return ([dict(r) for r in rows], total)


async def delete_old_audit_logs(tenant_id: str, retention_days: int) -> int:
    """Delete audit logs older than retention_days for a tenant. Returns count deleted.

    Uses make_interval() with an integer parameter to prevent SQL injection
    via string-concatenated intervals. Validates retention_days > 0 to prevent
    accidental deletion of all logs (negative values would match future timestamps).
    """
    if retention_days < 1:
        logger.error("audit_retention_invalid_days", tenant_id=tenant_id, days=retention_days)
        return 0
    pool = get_pool()
    if pool is None:
        return 0
    try:
        async with pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM audit_logs WHERE tenant_id = $1 AND timestamp < now() - make_interval(days => $2)",
                tenant_id, retention_days,
            )
            # result is like "DELETE 42"
            parts = result.split()
            return int(parts[1]) if len(parts) == 2 else 0
    except Exception:
        logger.exception("audit_retention_delete_failed", tenant_id=tenant_id)
        return 0
