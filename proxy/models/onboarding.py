"""Pydantic models for customer domain onboarding."""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


# Onboarding lifecycle states
class OnboardingStatus(str, Enum):
    """Status flow: certificate_pending → certificate_validated → tenant_created → active / failed."""

    CERTIFICATE_PENDING = "certificate_pending"
    CERTIFICATE_VALIDATED = "certificate_validated"
    TENANT_CREATED = "tenant_created"
    ACTIVE = "active"
    FAILED = "failed"
    OFFBOARDED = "offboarded"


# Valid state transitions — prevents skipping states or illegal rollbacks
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    OnboardingStatus.CERTIFICATE_PENDING: frozenset({
        OnboardingStatus.CERTIFICATE_VALIDATED,
        OnboardingStatus.FAILED,
        OnboardingStatus.OFFBOARDED,
    }),
    OnboardingStatus.CERTIFICATE_VALIDATED: frozenset({
        OnboardingStatus.TENANT_CREATED,
        OnboardingStatus.FAILED,
        OnboardingStatus.OFFBOARDED,
    }),
    OnboardingStatus.TENANT_CREATED: frozenset({
        OnboardingStatus.ACTIVE,
        OnboardingStatus.FAILED,
        OnboardingStatus.OFFBOARDED,
    }),
    OnboardingStatus.ACTIVE: frozenset({
        OnboardingStatus.OFFBOARDED,
    }),
    OnboardingStatus.FAILED: frozenset({
        OnboardingStatus.OFFBOARDED,
    }),
    OnboardingStatus.OFFBOARDED: frozenset(),  # terminal
}


# Valid domain regex: each label starts with alnum, optionally contains hyphens,
# ends with alnum. TLD must be alphabetic >= 2 chars.
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"\.[A-Za-z]{2,}$"
)

# Blocked infrastructure domain suffixes — prevent onboarding internal/cloud domains
_BLOCKED_DOMAIN_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".corp",
    ".lan",
    ".home",
    ".localdomain",
    ".example",
    ".invalid",
    ".test",
    # Cloud metadata / service discovery
    ".amazonaws.com",
    ".google.internal",
    ".metadata.google.internal",
    ".azure-devices.net",
    ".cloudapp.azure.com",
    # DNS rebinding services
    ".nip.io",
    ".sslip.io",
    ".xip.io",
    ".traefik.me",
)

# Blocked exact domains
_BLOCKED_DOMAINS = frozenset({
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "169.254.169.254",
})

# Maximum lengths
_MAX_DOMAIN_LEN = 253
_MAX_ORIGIN_URL_LEN = 2048
_MAX_ERROR_MSG_LEN = 1024


class OnboardingCreate(BaseModel):
    """Request body for initiating customer domain onboarding."""

    customer_domain: str = Field(..., min_length=1, max_length=_MAX_DOMAIN_LEN)
    origin_url: str = Field(..., min_length=1, max_length=_MAX_ORIGIN_URL_LEN)

    @field_validator("customer_domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("customer_domain must not be empty")
        if len(v) > _MAX_DOMAIN_LEN:
            raise ValueError(f"Domain too long (max {_MAX_DOMAIN_LEN} chars)")
        # Reject null bytes and control characters
        if any(ord(c) < 0x20 or c == "\x7f" for c in v):
            raise ValueError("Domain contains invalid characters")
        if not _DOMAIN_RE.match(v):
            raise ValueError(
                "Invalid domain format. "
                "Must be a valid FQDN (e.g. app.example.com)"
            )
        # Reject IP addresses as domains
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
            raise ValueError("IP addresses are not allowed as customer domains")
        # Reject exact blocked domains
        if v in _BLOCKED_DOMAINS:
            raise ValueError("This domain is not allowed")
        # Reject blocked suffixes (infrastructure/internal domains)
        for suffix in _BLOCKED_DOMAIN_SUFFIXES:
            if v.endswith(suffix) or v == suffix.lstrip("."):
                raise ValueError("Infrastructure and internal domains are not allowed")
        return v

    @field_validator("origin_url")
    @classmethod
    def validate_origin(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("origin_url must not be empty")
        if not v.startswith(("http://", "https://")):
            raise ValueError("origin_url must start with http:// or https://")
        return v


class OnboardingResponse(BaseModel):
    """Safe response body — excludes AWS-internal fields (ACM ARN, tenant ID)."""

    id: UUID
    customer_id: UUID
    customer_domain: str
    origin_url: str
    status: OnboardingStatus
    validation_cname_name: str = ""
    validation_cname_value: str = ""
    cloudfront_cname: str = ""
    error_message: str = ""
    created_at: datetime
    updated_at: datetime


class OnboardingStatusResponse(BaseModel):
    """Lightweight status response with required actions and next steps."""

    id: UUID
    customer_domain: str
    status: OnboardingStatus
    required_actions: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    cloudfront_cname: str = ""
    error_message: str = ""
