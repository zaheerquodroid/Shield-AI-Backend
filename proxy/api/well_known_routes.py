"""RFC 9116 security.txt well-known endpoint."""

from __future__ import annotations

import re
from pathlib import Path

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, Response

from proxy.config.customer_config import get_config_service

logger = structlog.get_logger()

router = APIRouter(tags=["well-known"])

_TEMPLATE_PATH = Path(__file__).resolve().parent.parent.parent / "templates" / "security.txt"

# Maximum length for a single field value after sanitization.
_MAX_FIELD_LENGTH = 500

# Maximum number of config keys to process — prevents DoS via huge config.
_MAX_CONFIG_KEYS = 50

# Cached template content — read once from disk, not on every request.
_template_cache: str | None = None

# Regex matching {{PLACEHOLDER}} tokens in the template.
_PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")

# Security headers applied directly — this route bypasses the middleware
# pipeline so it must set its own security headers.
_SECURITY_HEADERS = {
    "Cache-Control": "max-age=86400",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Vary": "Host",
}


def _load_template() -> str | None:
    """Load and cache the security.txt template from disk.

    Returns None if the file cannot be read. Caches the result so
    subsequent requests do not hit disk.
    """
    global _template_cache
    if _template_cache is not None:
        return _template_cache
    try:
        _template_cache = _TEMPLATE_PATH.read_text(encoding="utf-8")
        return _template_cache
    except (OSError, UnicodeDecodeError) as exc:
        logger.error("security_txt_template_read_failed", error=str(exc))
        return None


def invalidate_template_cache() -> None:
    """Clear the cached template (for SIGHUP reload or tests)."""
    global _template_cache
    _template_cache = None


def _sanitize_field(value: str) -> str:
    """Sanitize a security.txt field value.

    Strips newlines, carriage returns, and null bytes to prevent
    header injection and field smuggling. Caps length to prevent abuse.
    Also strips ``{{`` and ``}}`` sequences to prevent template
    re-injection (a value containing ``{{OTHER_KEY}}`` must not be
    re-expanded on a subsequent replacement pass).
    """
    if not isinstance(value, str):
        return ""
    cleaned = value.replace("\n", "").replace("\r", "").replace("\x00", "")
    # Strip placeholder delimiters to prevent re-injection
    cleaned = cleaned.replace("{{", "").replace("}}", "")
    return cleaned[:_MAX_FIELD_LENGTH]


def _render_template(template: str, values: dict) -> str:
    """Replace {{PLACEHOLDER}} variables in template with sanitized values.

    Uses a single-pass regex substitution to avoid sequential replacement
    bugs where an injected value could contain another placeholder that
    gets expanded on a later iteration.

    Caps the number of keys processed to prevent DoS via huge config dicts.
    """
    # Cap keys to prevent excessive dict creation from huge configs
    items = list(values.items())[:_MAX_CONFIG_KEYS]
    lookup = {str(k).upper(): _sanitize_field(str(v)) for k, v in items}

    def _replacer(match: re.Match) -> str:
        key = match.group(1)
        if key in lookup:
            return lookup[key]
        # Unknown placeholder — leave as-is (serves as documentation)
        return match.group(0)

    return _PLACEHOLDER_RE.sub(_replacer, template)


def _extract_domain(request: Request) -> str:
    """Extract the tenant domain from the request Host header.

    Ignores X-Forwarded-Host and other override headers to prevent
    tenant-spoofing attacks. Only the Host header is trusted for
    tenant identification. The port component is stripped.
    """
    host = request.headers.get("host", "")
    # Strip port from Host header
    domain = host.split(":")[0] if host else ""
    return domain


@router.get("/.well-known/security.txt")
async def security_txt(request: Request) -> Response:
    """Serve RFC 9116 security.txt for the requesting domain.

    Looks up customer config by Host header, renders the security.txt
    template with per-tenant values. Returns 404 if the feature is
    disabled or if the template is not available.
    """
    domain = _extract_domain(request)

    config_service = get_config_service()
    config = config_service.get_config(domain)

    enabled_features = config.get("enabled_features", {})
    if not isinstance(enabled_features, dict):
        return Response(status_code=404)
    if not enabled_features.get("security_txt", False):
        return Response(status_code=404)

    # Load template from cache (reads disk once)
    template_content = _load_template()
    if template_content is None:
        return Response(status_code=404)

    # Get per-tenant security.txt settings
    settings = config.get("settings", {})
    security_txt_values = settings.get("security_txt", {}) if isinstance(settings, dict) else {}
    if not isinstance(security_txt_values, dict):
        security_txt_values = {}

    rendered = _render_template(template_content, security_txt_values)

    return PlainTextResponse(
        content=rendered,
        media_type="text/plain",
        headers=_SECURITY_HEADERS,
    )
