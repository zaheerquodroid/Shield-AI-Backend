"""Code validation API endpoint."""

from __future__ import annotations

from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException

from proxy.api.auth import require_api_key
from proxy.models.code_validation import (
    CodeValidationRequest,
    CodeValidationResponse,
    FindingResponse,
)
from proxy.validation.code_validator import CodeValidator

logger = structlog.get_logger()

# Module-level default validator (stateless, thread-safe)
_default_validator = CodeValidator()

# Severity ranking for max_severity log (lexicographic would be wrong)
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

router = APIRouter(
    prefix="/api/v1",
    tags=["code_validation"],
    dependencies=[Depends(require_api_key)],
)


@router.post("/validate", response_model=CodeValidationResponse)
async def validate_code(body: CodeValidationRequest):
    """Validate AI-generated code for dangerous patterns."""
    try:
        # Build per-request validator if config overrides provided
        # Note: allowed_builtins is NOT exposed in the API — only in middleware config
        if body.config and (
            body.config.allowed_imports
            or body.config.blocked_imports
        ):
            validator = CodeValidator(
                allowed_imports=set(body.config.allowed_imports) if body.config.allowed_imports else None,
                blocked_imports=set(body.config.blocked_imports) if body.config.blocked_imports else None,
            )
        else:
            validator = _default_validator

        result = validator.validate(body.code, body.language)

        # Compute max_severity correctly (not lexicographic)
        max_sev = "none"
        if result.summary:
            max_sev = max(result.summary.keys(), key=lambda s: _SEVERITY_RANK.get(s, 0))

        logger.info(
            "code_validation_complete",
            language=result.language,
            valid=result.valid,
            finding_count=len(result.findings),
            max_severity=max_sev,
        )

        return CodeValidationResponse(
            valid=result.valid,
            language=result.language,
            findings=[
                FindingResponse(
                    rule_id=f.rule_id,
                    category=f.category,
                    severity=f.severity,
                    message=f.message,
                    line=f.line,
                    col=f.col,
                    snippet=f.snippet,
                )
                for f in result.findings
            ],
            summary=result.summary,
            truncated=result.truncated,
            finding_count=len(result.findings),
        )

    except Exception:
        error_id = uuid4().hex[:8]
        # Use logger.error instead of logger.exception to avoid leaking
        # code content via traceback (JSONDecodeError.doc, etc.)
        logger.error("code_validation_error", error_id=error_id)
        raise HTTPException(
            status_code=500,
            detail={"error": True, "message": "Internal validation error", "error_id": error_id},
        )
