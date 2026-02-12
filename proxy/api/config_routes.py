"""CRUD endpoints for customer and app configuration."""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException

from proxy.api.auth import require_api_key
from pydantic import BaseModel, Field

from proxy.middleware.url_validator import validate_origin_url
from proxy.models.customer import (
    AppCreate,
    AppUpdate,
    CustomerCreate,
    CustomerUpdate,
)
from proxy.store import postgres as pg_store
from proxy.store.postgres import StoreUnavailable

logger = structlog.get_logger()

router = APIRouter(prefix="/api/config", tags=["config"], dependencies=[Depends(require_api_key)])


# --- Customer endpoints ---

@router.post("/customers/", status_code=201)
async def create_customer(body: CustomerCreate):
    """Create a new customer."""
    try:
        result = await pg_store.create_customer(
            name=body.name, plan=body.plan, api_key=body.api_key, settings=body.settings
        )
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if result is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return result


@router.get("/customers/{customer_id}")
async def get_customer(customer_id: UUID):
    """Get a customer by ID."""
    try:
        result = await pg_store.get_customer(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if result is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return result


@router.put("/customers/{customer_id}")
async def update_customer(customer_id: UUID, body: CustomerUpdate):
    """Update a customer."""
    fields = body.model_dump(exclude_none=True)
    try:
        result = await pg_store.update_customer(customer_id, **fields)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return result


@router.delete("/customers/{customer_id}", status_code=204)
async def delete_customer(customer_id: UUID):
    """Delete a customer."""
    try:
        deleted = await pg_store.delete_customer(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if not deleted:
        raise HTTPException(status_code=404, detail="Customer not found")


# --- App endpoints ---

@router.post("/customers/{customer_id}/apps/", status_code=201)
async def create_app(customer_id: UUID, body: AppCreate):
    """Create a new app for a customer."""
    # Validate origin_url against SSRF
    ssrf_error = validate_origin_url(body.origin_url)
    if ssrf_error:
        raise HTTPException(status_code=422, detail=f"Invalid origin_url: {ssrf_error}")
    try:
        customer = await pg_store.get_customer(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    try:
        result = await pg_store.create_app(
            customer_id=customer_id,
            name=body.name,
            origin_url=body.origin_url,
            domain=body.domain,
            enabled_features=body.enabled_features.model_dump(),
            settings=body.settings,
        )
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if result is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return result


@router.get("/apps/{app_id}")
async def get_app(app_id: UUID):
    """Get an app by ID."""
    try:
        result = await pg_store.get_app(app_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if result is None:
        raise HTTPException(status_code=404, detail="App not found")
    return result


@router.put("/apps/{app_id}")
async def update_app(app_id: UUID, body: AppUpdate):
    """Update an app."""
    # Validate origin_url against SSRF if provided
    if body.origin_url is not None:
        ssrf_error = validate_origin_url(body.origin_url)
        if ssrf_error:
            raise HTTPException(status_code=422, detail=f"Invalid origin_url: {ssrf_error}")
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
    try:
        result = await pg_store.update_app(app_id, **fields)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail="App not found")
    return result


@router.delete("/apps/{app_id}", status_code=204)
async def delete_app(app_id: UUID):
    """Delete an app."""
    try:
        deleted = await pg_store.delete_app(app_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
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
    try:
        app_data = await pg_store.get_app(app_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if app_data is None:
        raise HTTPException(status_code=404, detail="App not found")

    settings = dict(app_data.get("settings", {}))
    rate_limits = dict(settings.get("rate_limits", {}))
    updates = body.model_dump(exclude_none=True)
    rate_limits.update(updates)
    settings["rate_limits"] = rate_limits

    try:
        result = await pg_store.update_app(app_id, settings=settings)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if result is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return result


@router.put("/apps/{app_id}/headers")
async def update_header_settings(app_id: UUID, body: HeaderSettingsUpdate):
    """Update per-app security header settings."""
    try:
        app_data = await pg_store.get_app(app_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if app_data is None:
        raise HTTPException(status_code=404, detail="App not found")

    settings = dict(app_data.get("settings", {}))
    updates = body.model_dump(exclude_none=True)
    settings.update(updates)

    try:
        result = await pg_store.update_app(app_id, settings=settings)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if result is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return result
