"""Audit log query and export API."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from proxy.api.auth import require_api_key
from proxy.store.audit import query_audit_logs

logger = structlog.get_logger()

router = APIRouter(
    prefix="/api/config/audit-logs",
    tags=["audit"],
    dependencies=[Depends(require_api_key)],
)

_CSV_COLUMNS = [
    "id", "tenant_id", "app_id", "request_id", "timestamp", "method",
    "path", "status_code", "duration_ms", "client_ip", "user_agent",
    "country", "user_id", "action", "blocked",
]


def _strip_control_chars(s: str) -> str:
    """Strip control characters from a string to prevent ANSI/log injection."""
    import re
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s)


def _parse_datetime(value: str | None, field_name: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        # Truncate and sanitize reflected input to prevent ANSI/log injection
        safe_preview = _strip_control_chars(value[:40]) + ("..." if len(value) > 40 else "")
        raise HTTPException(
            status_code=422,
            detail=f"Invalid ISO datetime for {field_name}: {safe_preview!r}",
        )


# Characters that trigger formula execution in spreadsheets (CSV injection).
# Covers: standard formula prefixes (=, +, -, @), whitespace that hides
# formulas (\t, \r), pipe (LibreOffice macro trigger), semicolon
# (European locale separator used to hide formulas in adjacent cells).
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "|", ";")


def _csv_safe(value: Any) -> str:
    """Sanitize a cell value to prevent CSV formula injection.

    Prefixes dangerous values with a single-quote so spreadsheets
    treat them as text instead of formulas/macros. Strips leading
    whitespace before checking to prevent bypass via "   =CMD()".
    """
    s = str(value) if value is not None else ""
    stripped = s.lstrip()
    if stripped and stripped[0] in _CSV_FORMULA_PREFIXES:
        return f"'{s}"
    return s


def _rows_to_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)
    for row in rows:
        writer.writerow([_csv_safe(row.get(k, "")) for k in _CSV_COLUMNS])
    return buf.getvalue()


@router.get("/")
async def get_audit_logs(
    tenant_id: str = Query(..., description="Tenant ID (required)"),
    app_id: str | None = Query(None),
    start_time: str | None = Query(None, description="ISO datetime"),
    end_time: str | None = Query(None, description="ISO datetime"),
    method: str | None = Query(None),
    path: str | None = Query(None),
    status: int | None = Query(None),
    action: str | None = Query(None),
    blocked: bool | None = Query(None),
    user_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    format: str = Query("json", pattern="^(json|csv)$"),
):
    """Query audit logs with filters. Supports JSON and CSV export."""
    try:
        rows, has_more = await query_audit_logs(
            tenant_id=tenant_id,
            app_id=app_id,
            start_time=_parse_datetime(start_time, "start_time"),
            end_time=_parse_datetime(end_time, "end_time"),
            method=method,
            path=path,
            status_code=status,
            action=action,
            blocked=blocked,
            user_id=user_id,
            limit=limit,
            offset=offset,
        )
    except Exception:
        logger.exception("audit_query_failed", tenant_id=tenant_id)
        raise HTTPException(status_code=503, detail="Audit log query failed")

    if format == "csv":
        csv_content = _rows_to_csv(rows)
        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
        )

    # Serialize datetime and UUID fields for JSON
    serialized = []
    for row in rows:
        out = {}
        for k, v in row.items():
            if isinstance(v, datetime):
                out[k] = v.isoformat()
            else:
                out[k] = v
            # Convert UUID-like objects to strings
            if hasattr(out[k], "hex") and not isinstance(out[k], (str, bytes, float, int, bool)):
                out[k] = str(out[k])
        serialized.append(out)

    return {"data": serialized, "has_more": has_more, "limit": limit, "offset": offset}
