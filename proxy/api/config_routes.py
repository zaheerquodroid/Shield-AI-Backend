"""CRUD endpoints for customer and app configuration."""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException

from proxy.api.auth import require_api_key
from pydantic import BaseModel, Field

from proxy.models.customer import (
    AppCreate,
    AppUpdate,
    CustomerCreate,
    CustomerUpdate,
)
from proxy.store import postgres as pg_store

logger = structlog.get_logger()

router = APIRouter(prefix="/api/config", tags=["config"], dependencies=[Depends(require_api_key)])


# --- Customer endpoints ---

@router.post("/customers/", status_code=201)
async def create_customer(body: CustomerCreate):
    """Create a new customer."""
    result = await pg_store.create_customer(
        name=body.name, plan=body.plan, api_key=body.api_key, settings=body.settings
    )
    if result is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return result


@router.get("/customers/{customer_id}")
async def get_customer(customer_id: UUID):
    """Get a customer by ID."""
    result = await pg_store.get_customer(customer_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return result


@router.put("/customers/{customer_id}")
async def update_customer(customer_id: UUID, body: CustomerUpdate):
    """Update a customer."""
    fields = body.model_dump(exclude_none=True)
    result = await pg_store.update_customer(customer_id, **fields)
    if result is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return result


@router.delete("/customers/{customer_id}", status_code=204)
async def delete_customer(customer_id: UUID):
    """Delete a customer."""
    deleted = await pg_store.delete_customer(customer_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Customer not found")


# --- App endpoints ---

@router.post("/customers/{customer_id}/apps/", status_code=201)
async def create_app(customer_id: UUID, body: AppCreate):
    """Create a new app for a customer."""
    customer = await pg_store.get_customer(customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    result = await pg_store.create_app(
        customer_id=customer_id,
        name=body.name,
        origin_url=body.origin_url,
        domain=body.domain,
        enabled_features=body.enabled_features.model_dump(),
        settings=body.settings,
    )
    if result is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return result


@router.get("/apps/{app_id}")
async def get_app(app_id: UUID):
    """Get an app by ID."""
    result = await pg_store.get_app(app_id)
    if result is None:
        raise HTTPException(status_code=404, detail="App not found")
    return result


@router.put("/apps/{app_id}")
async def update_app(app_id: UUID, body: AppUpdate):
    """Update an app."""
    fields = {}
    if body.name is not None:
        fields["name"] = body.name
    if body.origin_url is not None:
        fields["origin_url"] = body.origin_url
    if body.domain is not None:
        fields["domain"] = body.domain
    if body.enabled_features is not None:
        fields["enabled_features"] = body.enabled_features.model_dump()
    if body.settings is not None:
        fields["settings"] = body.settings
    result = await pg_store.update_app(app_id, **fields)
    if result is None:
        raise HTTPException(status_code=404, detail="App not found")
    return result


@router.delete("/apps/{app_id}", status_code=204)
async def delete_app(app_id: UUID):
    """Delete an app."""
    deleted = await pg_store.delete_app(app_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="App not found")


# --- Convenience endpoints for Sprint 2 features ---


class RateLimitUpdate(BaseModel):
    """Request body for updating rate limit settings."""

    auth_max: int | None = Field(None, gt=0)
    global_max: int | None = Field(None, gt=0)
    window_seconds: int | None = Field(None, gt=0)


class HeaderSettingsUpdate(BaseModel):
    """Request body for updating header settings."""

    header_preset: str | None = Field(None, pattern=r"^(strict|balanced|permissive)$")
    csp_override: str | None = None


@router.put("/apps/{app_id}/rate-limits")
async def update_rate_limits(app_id: UUID, body: RateLimitUpdate):
    """Update per-app rate limit settings."""
    app = await pg_store.get_app(app_id)
    if app is None:
        raise HTTPException(status_code=404, detail="App not found")

    settings = dict(app.get("settings", {}))
    rate_limits = dict(settings.get("rate_limits", {}))
    updates = body.model_dump(exclude_none=True)
    rate_limits.update(updates)
    settings["rate_limits"] = rate_limits

    result = await pg_store.update_app(app_id, settings=settings)
    if result is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return result


@router.put("/apps/{app_id}/headers")
async def update_header_settings(app_id: UUID, body: HeaderSettingsUpdate):
    """Update per-app security header settings."""
    app = await pg_store.get_app(app_id)
    if app is None:
        raise HTTPException(status_code=404, detail="App not found")

    settings = dict(app.get("settings", {}))
    updates = body.model_dump(exclude_none=True)
    settings.update(updates)

    result = await pg_store.update_app(app_id, settings=settings)
    if result is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return result
