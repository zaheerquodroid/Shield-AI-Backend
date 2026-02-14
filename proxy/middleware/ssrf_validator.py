"""SSRF validator middleware — blocks server-side request forgery in URL-valued fields."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import re
from uuid import uuid4

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxy.middleware.llm_sanitizer import extract_string_fields
from proxy.middleware.pipeline import Middleware, RequestContext
from proxy.middleware.url_validator import validate_origin_url

logger = structlog.get_logger()

_DEFAULT_URL_FIELD_PATTERNS: list[str] = [
    "*url*",
    "*callback*",
    "*endpoint*",
    "*webhook*",
    "*redirect*",
    "*return*",
    "*target*",
    "*dest*",
    "*link*",
    "*href*",
]

# Matches http(s) URLs + dangerous non-http schemes (ftp, file, gopher, dict,
# tftp, ldap, ssh, telnet) + protocol-relative URLs (//host/...).
# This ensures we don't silently ignore SSRF payloads using alternate schemes.
_URL_RE = re.compile(
    r"(?:https?|ftp|file|gopher|dict|tftp|ldap|ssh|telnet)://[^\s<>\"']+"
    r"|//[^\s<>\"']+",
)


def _check_duplicate_keys(raw_body: bytes) -> bool:
    """Detect duplicate JSON keys using object_pairs_hook.

    Returns True if duplicates found.
    """
    try:
        has_dupes = False

        def _pairs_hook(pairs: list[tuple[str, object]]) -> dict:
            nonlocal has_dupes
            keys = [k for k, _ in pairs]
            if len(keys) != len(set(keys)):
                has_dupes = True
            return dict(pairs)

        json.loads(raw_body, object_pairs_hook=_pairs_hook)
        return has_dupes
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


class SSRFValidator(Middleware):
    """Validate URL-valued fields in request bodies to prevent SSRF attacks.

    Intercepts requests to customer-configured endpoints, extracts URL-valued
    fields from JSON bodies, and validates each URL against private/reserved
    IP ranges using the existing ``validate_origin_url()`` infrastructure.
    """

    async def process_request(
        self, request: Request, context: RequestContext
    ) -> Request | Response | None:
        # Check feature flag
        features = context.customer_config.get("enabled_features", {})
        if not features.get("ssrf_validator", True):
            return None

        # Get SSRF config from customer settings
        customer_settings = context.customer_config.get("settings", {})
        ssrf_cfg = customer_settings.get("ssrf", {})

        # Protected endpoints — empty list means disabled (safe default)
        protected_endpoints: list[str] = ssrf_cfg.get("protected_endpoints", [])
        if not protected_endpoints:
            return None

        # Check if request path matches any protected endpoint pattern
        path = request.url.path
        if not any(fnmatch.fnmatch(path, p) for p in protected_endpoints):
            return None

        # Only scan POST/PUT/PATCH (requests with bodies)
        if request.method.upper() not in ("POST", "PUT", "PATCH"):
            return None

        # Parse JSON body with duplicate key detection in a single pass
        body = await request.body()
        if not body:
            return None

        has_dupes = False

        def _pairs_hook(pairs: list[tuple[str, object]]) -> dict:
            nonlocal has_dupes
            keys = [k for k, _ in pairs]
            if len(keys) != len(set(keys)):
                has_dupes = True
            return dict(pairs)

        try:
            data = json.loads(body, object_pairs_hook=_pairs_hook)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Non-JSON body on a protected endpoint — log for visibility.
            # Attackers can bypass JSON-only scanning by switching Content-Type.
            logger.warning(
                "ssrf_non_json_body_on_protected_endpoint",
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                path=path,
                content_type=request.headers.get("content-type", ""),
                body_size=len(body),
            )
            return None

        if not isinstance(data, (dict, list)):
            return None

        # Reject duplicate JSON keys — prevents smuggling where Python
        # (last-wins) sees a safe value but upstream (first-wins) sees malicious.
        if isinstance(data, dict) and has_dupes:
            error_id = uuid4().hex[:8]
            logger.warning(
                "ssrf_duplicate_json_keys",
                error_id=error_id,
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                path=path,
            )
            mode = ssrf_cfg.get("mode", "block")
            if mode == "block":
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": True,
                        "message": "Request contains duplicate JSON keys.",
                        "error_id": error_id,
                    },
                )
            # detect_only: logged above, continue processing

        # Extract all string fields (cache for reuse by LLM sanitizer)
        _cache_key = "_extracted_string_fields"
        if _cache_key in context.extra:
            string_fields = context.extra[_cache_key]
        else:
            string_fields = extract_string_fields(data)
            context.extra[_cache_key] = string_fields
        if not string_fields:
            return None

        # Filter fields by name pattern (or scan all if configured)
        scan_all = ssrf_cfg.get("scan_all_fields", False)
        field_patterns: list[str] = ssrf_cfg.get(
            "url_field_patterns", _DEFAULT_URL_FIELD_PATTERNS
        )

        if not scan_all:
            string_fields = [
                (fp, val)
                for fp, val in string_fields
                if self._matches_field_pattern(fp, field_patterns)
            ]

        if not string_fields:
            return None

        # Extract URLs from field values
        allowlist: list[str] = ssrf_cfg.get("allowlist", [])
        urls_to_check: list[tuple[str, str]] = []  # (field_path, url)

        for field_path, field_value in string_fields:
            for match in _URL_RE.finditer(field_value):
                url = match.group(0)

                # Normalize protocol-relative URLs → http:// for validation
                if url.startswith("//"):
                    url = "http:" + url

                # Skip allowlisted URLs
                if any(fnmatch.fnmatch(url, pat) for pat in allowlist):
                    continue
                urls_to_check.append((field_path, url))

        if not urls_to_check:
            return None

        # Validate each URL — fail-closed: exceptions count as violations
        violations: list[dict[str, str]] = []
        for field_path, url in urls_to_check:
            try:
                error = await asyncio.to_thread(
                    validate_origin_url, url, strict_dns=True
                )
            except Exception as exc:
                # Fail-closed: treat unexpected errors as violations
                error = f"Validation error: {type(exc).__name__}"
                logger.error(
                    "ssrf_validation_error",
                    url_length=len(url),
                    field=field_path,
                    error=str(exc),
                    request_id=context.request_id,
                )
            if error:
                violations.append({"field": field_path, "reason": error})

        if not violations:
            return None

        # Determine mode
        mode = ssrf_cfg.get("mode", "block")
        error_id = uuid4().hex[:8]

        logger.warning(
            "ssrf_attempt_detected",
            error_id=error_id,
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            path=path,
            mode=mode,
            violation_count=len(violations),
            violations=violations,
        )

        if mode == "block":
            return JSONResponse(
                status_code=400,
                content={
                    "error": True,
                    "message": "Request contains URLs that failed security validation.",
                    "error_id": error_id,
                },
            )

        # detect_only — log but allow through
        return None

    @staticmethod
    def _matches_field_pattern(field_path: str, patterns: list[str]) -> bool:
        """Check if the leaf field name matches any of the URL field patterns."""
        # Extract leaf name from dotted path (e.g. "config.callback_url" -> "callback_url")
        leaf = field_path.rsplit(".", 1)[-1]
        # Strip array indices (e.g. "urls[0]" -> "urls")
        bracket = leaf.find("[")
        if bracket != -1:
            leaf = leaf[:bracket]
        return any(fnmatch.fnmatch(leaf.lower(), pat.lower()) for pat in patterns)
