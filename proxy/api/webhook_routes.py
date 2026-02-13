"""Webhook CRUD API endpoints."""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException

from proxy.api.auth import require_api_key
from proxy.middleware.url_validator import validate_origin_url
from proxy.models.webhook import VALID_EVENTS, WebhookCreate, WebhookUpdate
from proxy.store import postgres as pg_store
from proxy.store.postgres import StoreUnavailable
from proxy.store import webhooks as webhook_store

logger = structlog.get_logger()

# Maximum number of webhooks per customer
_MAX_WEBHOOKS_PER_CUSTOMER = 25
# Maximum number of event subscriptions per webhook
_MAX_EVENTS_PER_WEBHOOK = 10

router = APIRouter(
    prefix="/api/config/webhooks",
    tags=["webhooks"],
    dependencies=[Depends(require_api_key)],
)


def _validate_events(events: list[str]) -> None:
    """Validate event types. Raises HTTPException on invalid events."""
    if len(events) > _MAX_EVENTS_PER_WEBHOOK:
        raise HTTPException(
            status_code=422,
            detail=f"Too many event subscriptions (max {_MAX_EVENTS_PER_WEBHOOK})",
        )
    invalid = [e for e in events if e not in VALID_EVENTS]
    if invalid:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid event types: {invalid}. Valid: {sorted(VALID_EVENTS)}",
        )


def _validate_webhook_url(url: str) -> None:
    """Validate webhook URL against SSRF. Raises HTTPException on failure."""
    ssrf_error = validate_origin_url(url)
    if ssrf_error:
        # Log detailed error server-side, return generic message to client
        logger.warning("webhook_url_ssrf_blocked", url=url, reason=ssrf_error)
        raise HTTPException(status_code=422, detail="Webhook URL validation failed")


@router.post("/customers/{customer_id}/", status_code=201)
async def create_webhook(customer_id: UUID, body: WebhookCreate):
    """Create a webhook for a customer."""
    # Validate customer exists
    try:
        customer = await pg_store.get_customer(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")

    # Validate webhook URL against SSRF
    _validate_webhook_url(body.url)

    # Validate event types
    _validate_events(body.events)

    # Check per-customer webhook limit
    try:
        existing = await webhook_store.list_webhooks(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if len(existing) >= _MAX_WEBHOOKS_PER_CUSTOMER:
        raise HTTPException(
            status_code=422,
            detail=f"Maximum webhooks per customer ({_MAX_WEBHOOKS_PER_CUSTOMER}) reached",
        )

    try:
        result = await webhook_store.create_webhook(
            customer_id=customer_id,
            name=body.name,
            url=body.url,
            provider=body.provider,
            events=body.events,
            secret=body.secret,
            enabled=body.enabled,
        )
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")

    return result


@router.get("/customers/{customer_id}/")
async def list_webhooks(customer_id: UUID):
    """List all webhooks for a customer."""
    try:
        webhooks = await webhook_store.list_webhooks(customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"data": webhooks, "total": len(webhooks)}


@router.get("/customers/{customer_id}/{webhook_id}")
async def get_webhook(customer_id: UUID, webhook_id: UUID):
    """Get a webhook by ID, scoped to customer (prevents IDOR)."""
    try:
        result = await webhook_store.get_webhook(webhook_id, customer_id=customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if result is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return result


@router.put("/customers/{customer_id}/{webhook_id}")
async def update_webhook(customer_id: UUID, webhook_id: UUID, body: WebhookUpdate):
    """Update a webhook, scoped to customer (prevents IDOR)."""
    # Validate URL if provided
    if body.url is not None:
        _validate_webhook_url(body.url)

    # Validate events if provided
    if body.events is not None:
        _validate_events(body.events)

    fields = body.model_dump(exclude_none=True)
    try:
        result = await webhook_store.update_webhook(
            webhook_id, customer_id=customer_id, **fields,
        )
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return result


@router.delete("/customers/{customer_id}/{webhook_id}", status_code=204)
async def delete_webhook(customer_id: UUID, webhook_id: UUID):
    """Delete a webhook, scoped to customer (prevents IDOR)."""
    try:
        deleted = await webhook_store.delete_webhook(webhook_id, customer_id=customer_id)
    except StoreUnavailable:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
