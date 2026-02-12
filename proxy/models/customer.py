"""Pydantic models for customer and app configuration."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class EnabledFeatures(BaseModel):
    """Feature flags for an app."""

    waf: bool = True
    error_sanitization: bool = True
    session_validation: bool = True
    audit_logging: bool = True
    rate_limiting: bool = True
    security_headers: bool = True
    bot_protection: bool = False


class AppCreate(BaseModel):
    """Request body for creating an app."""

    name: str
    origin_url: str
    domain: str
    enabled_features: EnabledFeatures = Field(default_factory=EnabledFeatures)
    settings: dict = Field(default_factory=dict)


class AppUpdate(BaseModel):
    """Request body for updating an app."""

    name: str | None = None
    origin_url: str | None = None
    domain: str | None = None
    enabled_features: EnabledFeatures | None = None
    settings: dict | None = None


class AppResponse(BaseModel):
    """Response body for an app."""

    id: UUID
    customer_id: UUID
    name: str
    origin_url: str
    domain: str
    enabled_features: EnabledFeatures
    settings: dict
    created_at: datetime
    updated_at: datetime


class CustomerCreate(BaseModel):
    """Request body for creating a customer."""

    name: str
    plan: str = "starter"
    api_key: str
    settings: dict = Field(default_factory=dict)


class CustomerUpdate(BaseModel):
    """Request body for updating a customer."""

    name: str | None = None
    plan: str | None = None
    settings: dict | None = None


class CustomerResponse(BaseModel):
    """Response body for a customer."""

    id: UUID
    name: str
    plan: str
    settings: dict
    created_at: datetime
    updated_at: datetime
