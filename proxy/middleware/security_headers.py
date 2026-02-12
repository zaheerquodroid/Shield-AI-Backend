"""Security headers injection middleware."""

from __future__ import annotations

from pathlib import Path

import structlog
import yaml
from starlette.requests import Request
from starlette.responses import Response

from proxy.config.loader import get_settings
from proxy.middleware.csp_builder import build_csp, merge_csp, parse_csp
from proxy.middleware.pipeline import Middleware, RequestContext

logger = structlog.get_logger()

_PRESETS_PATH = Path(__file__).parent.parent / "config" / "header_presets.yaml"

# Headers that should be stripped from upstream responses
_STRIP_HEADERS = frozenset({
    "server",
    "x-powered-by",
})

# Cache loaded presets
_presets: dict | None = None


def _load_presets() -> dict:
    """Load header presets from YAML, caching after first load."""
    global _presets
    if _presets is not None:
        return _presets
    if not _PRESETS_PATH.exists():
        logger.error("header_presets_not_found", path=str(_PRESETS_PATH))
        _presets = {}
        return _presets
    with open(_PRESETS_PATH) as f:
        _presets = yaml.safe_load(f) or {}
    return _presets


def reset_presets_cache() -> None:
    """Reset the presets cache (for testing)."""
    global _presets
    _presets = None


class SecurityHeaders(Middleware):
    """Inject security headers into every response.

    - Uses preset profiles (strict/balanced/permissive) from header_presets.yaml
    - Supports per-customer CSP overrides via settings JSONB
    - Strips Server and X-Powered-By headers from upstream responses
    """

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        return None

    async def process_response(self, response: Response, context: RequestContext) -> Response:
        # Check feature flag
        features = context.customer_config.get("enabled_features", {})
        if not features.get("security_headers", True):
            return response

        try:
            return self._apply_headers(response, context)
        except Exception as exc:
            logger.error("security_headers_error", error=str(exc))
            return response

    def _apply_headers(self, response: Response, context: RequestContext) -> Response:
        """Apply security headers to the response."""
        # Determine preset
        customer_settings = context.customer_config.get("settings", {})
        preset_name = customer_settings.get("header_preset", get_settings().header_preset)
        presets = _load_presets()
        preset = presets.get(preset_name, presets.get("balanced", {}))

        # Strip unwanted upstream headers
        for header in _STRIP_HEADERS:
            if header in response.headers:
                del response.headers[header]

        # Apply preset headers
        for header_name, header_value in preset.items():
            # Handle CSP specially — merge with customer overrides
            if header_name == "content-security-policy":
                csp_override = customer_settings.get("csp_override", "")
                if csp_override:
                    base = parse_csp(header_value)
                    override = parse_csp(csp_override)
                    merged = merge_csp(base, override)
                    header_value = build_csp(merged)
            response.headers[header_name] = header_value

        return response
