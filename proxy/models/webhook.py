"""Pydantic models for webhook configuration."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

VALID_PROVIDERS = frozenset({"custom", "slack", "pagerduty"})
VALID_EVENTS = frozenset({
    "security",       # all security events
    "waf_blocked",
    "rate_limited",
    "session_blocked",
    "login_attempt",
    "all",            # everything
})


_MAX_EVENT_STRING_LENGTH = 64


class WebhookCreate(BaseModel):
    """Request body for creating a webhook."""

    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1, max_length=2048)
    provider: str = Field("custom", pattern=r"^(custom|slack|pagerduty)$")
    events: list[str] = Field(default_factory=lambda: ["security"], max_length=10)
    secret: str = Field("", max_length=255)
    enabled: bool = True

    @field_validator("events")
    @classmethod
    def validate_event_string_lengths(cls, v: list[str]) -> list[str]:
        for item in v:
            if len(item) > _MAX_EVENT_STRING_LENGTH:
                raise ValueError(
                    f"Event string too long ({len(item)} chars, max {_MAX_EVENT_STRING_LENGTH})"
                )
        return v


class WebhookUpdate(BaseModel):
    """Request body for updating a webhook."""

    name: str | None = Field(None, min_length=1, max_length=255)
    url: str | None = Field(None, min_length=1, max_length=2048)
    provider: str | None = Field(None, pattern=r"^(custom|slack|pagerduty)$")
    events: list[str] | None = Field(None, max_length=10)

    @field_validator("events")
    @classmethod
    def validate_event_string_lengths(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            for item in v:
                if len(item) > _MAX_EVENT_STRING_LENGTH:
                    raise ValueError(
                        f"Event string too long ({len(item)} chars, max {_MAX_EVENT_STRING_LENGTH})"
                    )
        return v
    secret: str | None = Field(None, max_length=255)
    enabled: bool | None = None


class WebhookResponse(BaseModel):
    """Response body for a webhook (secret never exposed)."""

    id: UUID
    customer_id: UUID
    name: str
    url: str
    provider: str
    events: list[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime
