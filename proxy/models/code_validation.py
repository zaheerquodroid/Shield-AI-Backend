"""Pydantic request/response models for code validation API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CodeValidationConfig(BaseModel):
    """Optional per-request validation config overrides.

    Note: allowed_builtins is NOT exposed in the API to prevent callers
    from disabling security checks. It is only available in middleware config.
    """

    allowed_imports: list[str] = Field(default_factory=list, max_length=50)
    blocked_imports: list[str] = Field(default_factory=list, max_length=50)
    mode: str = Field(default="block", pattern=r"^(block|detect_only)$")


class CodeValidationRequest(BaseModel):
    """Request body for POST /api/v1/validate."""

    code: str = Field(..., min_length=1, max_length=100_000)
    language: str = Field(..., pattern=r"^(python|javascript)$")
    config: CodeValidationConfig | None = None


class FindingResponse(BaseModel):
    """Single finding in the validation response."""

    rule_id: str
    category: str
    severity: str
    message: str
    line: int
    col: int
    snippet: str


class CodeValidationResponse(BaseModel):
    """Response body for POST /api/v1/validate."""

    valid: bool
    language: str
    findings: list[FindingResponse]
    summary: dict[str, int]
    truncated: bool
    finding_count: int
