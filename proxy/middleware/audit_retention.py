"""Background task for audit log retention cleanup."""

from __future__ import annotations

import asyncio

import structlog

from proxy.store.audit import delete_old_audit_logs
from proxy.store.postgres import get_pool

logger = structlog.get_logger()

# Retention days by customer plan
PLAN_RETENTION_DAYS: dict[str, int] = {
    "starter": 7,
    "pro": 30,
    "business": 90,
    "enterprise": 365,
}

DEFAULT_RETENTION_DAYS = 30


async def run_retention_cleanup(interval_seconds: int) -> None:
    """Periodically delete expired audit logs for all customers.

    Runs forever until cancelled. Errors are logged but never crash the loop.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            pool = get_pool()
            if pool is None:
                logger.debug("audit_retention_skip", reason="no db pool")
                continue

            async with pool.acquire() as conn:
                rows = await conn.fetch("SELECT id, plan FROM customers")

            total_deleted = 0
            for row in rows:
                tenant_id = str(row["id"])
                plan = row.get("plan", "starter") or "starter"
                days = PLAN_RETENTION_DAYS.get(plan, DEFAULT_RETENTION_DAYS)
                deleted = await delete_old_audit_logs(tenant_id, days)
                total_deleted += deleted

            if total_deleted:
                logger.info("audit_retention_complete", deleted=total_deleted, customers=len(rows))

        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("audit_retention_error")
