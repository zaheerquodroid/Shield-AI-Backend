"""Code validator middleware — validates AI-generated code in request bodies.

Follows the CallbackVerifier/SSRFValidator pattern:
- Feature flag: code_validator (default False, opt-in)
- Per-customer config in settings.code_validator
- Only scans POST/PUT/PATCH on matched endpoints
- Fail-closed: non-JSON body on protected endpoint → block in block mode
"""

from __future__ import annotations

import fnmatch
import json
from uuid import uuid4

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxy.middleware.pipeline import Middleware, RequestContext
from proxy.validation.code_validator import CodeValidator

logger = structlog.get_logger()

# Default code fields to scan in JSON body
_DEFAULT_CODE_FIELDS = ["code", "script", "source"]
_DEFAULT_LANGUAGE_FIELD = "language"
_DEFAULT_LANGUAGE = "python"

# Performance guards
_MAX_BODY_SIZE = 1_048_576  # 1 MB — prevent memory exhaustion from huge payloads
_MAX_CODE_ENTRIES = 10  # Max code fields to validate per request


class CodeValidatorMiddleware(Middleware):
    """Validate AI-generated code in request bodies before forwarding.

    Customers configure which endpoints are protected and what code
    fields to scan. Fail-closed: parse errors → reject in block mode.
    """

    def __init__(self) -> None:
        self._default_validator = CodeValidator()

    async def process_request(
        self, request: Request, context: RequestContext
    ) -> Request | Response | None:
        # Check feature flag (default False — opt-in)
        features = context.customer_config.get("enabled_features", {})
        if not features.get("code_validator", False):
            return None

        # Load code_validator settings
        customer_settings = context.customer_config.get("settings", {})
        cv_cfg = customer_settings.get("code_validator", {})

        # Protected endpoints — empty list means disabled
        protected_endpoints: list[str] = cv_cfg.get("protected_endpoints", [])
        if not protected_endpoints:
            return None

        # Only scan POST/PUT/PATCH
        if request.method.upper() not in ("POST", "PUT", "PATCH"):
            return None

        # Check if request path matches any protected endpoint pattern
        path = request.url.path
        if not any(fnmatch.fnmatch(path, p) for p in protected_endpoints):
            return None

        mode = cv_cfg.get("mode", "block")

        # Parse JSON body
        body = await request.body()
        if not body:
            return self._reject(
                "code_validator_empty_body",
                "Empty body on protected code endpoint",
                mode,
                context,
                path=path,
            )

        # Body size limit — prevent memory exhaustion from oversized payloads
        if len(body) > _MAX_BODY_SIZE:
            return self._reject(
                "code_validator_body_too_large",
                f"Request body exceeds {_MAX_BODY_SIZE} bytes",
                mode,
                context,
                path=path,
                body_size=len(body),
            )

        # Duplicate JSON key detection (prevents parser differential smuggling)
        has_dupes = False

        def _pairs_hook(pairs: list[tuple[str, object]]) -> dict:
            nonlocal has_dupes
            keys = [k for k, _ in pairs]
            if len(keys) != len(set(keys)):
                has_dupes = True
            return dict(pairs)

        try:
            data = json.loads(body, object_pairs_hook=_pairs_hook)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            return self._reject(
                "code_validator_invalid_json",
                "Non-JSON body on protected code endpoint",
                mode,
                context,
                path=path,
            )

        if not isinstance(data, dict):
            return self._reject(
                "code_validator_invalid_body",
                "Expected JSON object body",
                mode,
                context,
                path=path,
            )

        # Reject duplicate JSON keys (parser differential smuggling)
        if has_dupes:
            error_id = uuid4().hex[:8]
            logger.warning(
                "code_validator_duplicate_json_keys",
                error_id=error_id,
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                path=path,
            )
            if mode != "detect_only":
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": True,
                        "message": "Request contains duplicate JSON keys.",
                        "error_id": error_id,
                    },
                )

        # Extract code from configured fields — scan ALL matching fields
        code_fields: list[str] = cv_cfg.get("code_fields", _DEFAULT_CODE_FIELDS)
        language_field: str = cv_cfg.get("language_field", _DEFAULT_LANGUAGE_FIELD)
        default_language: str = cv_cfg.get("default_language", _DEFAULT_LANGUAGE)

        # Reject null bytes in JSON keys — prevents field name smuggling
        # ("co\u0000de" would not match "code" in code_fields)
        if any("\x00" in k for k in data):
            return self._reject(
                "code_validator_null_byte_key",
                "JSON key contains null byte",
                mode,
                context,
                path=path,
            )

        # Collect code from all matching fields (not just first)
        code_entries: list[tuple[str, str]] = []  # (field_name, code)
        for field_name in code_fields:
            val = data.get(field_name)
            if isinstance(val, str) and val:
                code_entries.append((field_name, val))

        # Also scan nested fields (one level deep) for code smuggling
        for key, val in data.items():
            if isinstance(val, dict):
                for field_name in code_fields:
                    nested_val = val.get(field_name)
                    if isinstance(nested_val, str) and nested_val:
                        code_entries.append((f"{key}.{field_name}", nested_val))
            # Scan arrays of dicts (e.g. {"items": [{"code": "..."}]})
            elif isinstance(val, list):
                for idx, item in enumerate(val):
                    if isinstance(item, dict):
                        for field_name in code_fields:
                            nested_val = item.get(field_name)
                            if isinstance(nested_val, str) and nested_val:
                                code_entries.append((f"{key}[{idx}].{field_name}", nested_val))

        # Cap code entries to prevent amplification attacks
        if len(code_entries) > _MAX_CODE_ENTRIES:
            return self._reject(
                "code_validator_too_many_entries",
                f"Too many code fields ({len(code_entries)} > {_MAX_CODE_ENTRIES})",
                mode,
                context,
                path=path,
                entry_count=len(code_entries),
            )

        if not code_entries:
            return None

        # Determine language
        language = data.get(language_field, default_language)
        if not isinstance(language, str):
            language = default_language

        # Build validator with customer allowlist
        allowed_imports = cv_cfg.get("allowed_imports", [])
        if allowed_imports:
            validator = CodeValidator(allowed_imports=set(allowed_imports))
        else:
            validator = self._default_validator

        # Validate code entries — block if ANY fails
        # In block mode, early-terminate after first invalid entry (no point
        # continuing validation if we're going to reject anyway).
        all_findings = []
        any_invalid = False
        for field_name, code in code_entries:
            result = validator.validate(code, language)
            if not result.valid:
                any_invalid = True
                all_findings.extend(result.findings)
                if mode != "detect_only":
                    break  # Early termination in block mode

        if not any_invalid:
            logger.info(
                "code_validator_passed",
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                path=path,
                language=language,
                fields_scanned=len(code_entries),
            )
            return None

        # Code is invalid
        error_id = uuid4().hex[:8]
        logger.warning(
            "code_validator_blocked",
            error_id=error_id,
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            path=path,
            language=language,
            finding_count=len(all_findings),
            mode=mode,
        )

        if mode == "detect_only":
            return None

        return JSONResponse(
            status_code=400,
            content={
                "error": True,
                "message": "Code validation failed: dangerous patterns detected.",
                "error_id": error_id,
            },
        )

    @staticmethod
    def _reject(
        event: str,
        message: str,
        mode: str,
        context: RequestContext,
        **log_extra,
    ) -> Response | None:
        """Log rejection and return 400 (block) or None (detect_only)."""
        error_id = uuid4().hex[:8]
        logger.warning(
            event,
            error_id=error_id,
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            mode=mode,
            **log_extra,
        )
        if mode == "detect_only":
            return None
        return JSONResponse(
            status_code=400,
            content={
                "error": True,
                "message": "Code validation failed.",
                "error_id": error_id,
            },
        )
