"""LLM sanitizer middleware — detects and neutralizes prompt injection attacks."""

from __future__ import annotations

import fnmatch
import json
import re
import unicodedata
from uuid import uuid4

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxy.config.loader import get_settings
from proxy.middleware.pipeline import Middleware, RequestContext

logger = structlog.get_logger()

# Unicode characters to strip before pattern matching
# Includes zero-width chars, BOM, soft hyphens, direction overrides, tag chars
_INVISIBLE_CHARS = re.compile(
    "["
    "\u200b"          # Zero-width space
    "\u200c"          # Zero-width non-joiner
    "\u200d"          # Zero-width joiner
    "\u200e\u200f"    # LTR/RTL marks
    "\u2060"          # Word joiner
    "\u2061-\u2064"   # Invisible math operators
    "\ufeff"          # BOM / zero-width no-break space
    "\u00ad"          # Soft hyphen
    "\u034f"          # Combining grapheme joiner
    "\u061c"          # Arabic letter mark
    "\u115f\u1160"    # Hangul fillers
    "\u17b4\u17b5"    # Khmer vowel inherent
    "\u180e"          # Mongolian vowel separator
    "\u2028\u2029"    # Line/paragraph separator
    "\u202a-\u202e"   # Bidi embedding/override
    "\u2066-\u2069"   # Bidi isolate
    "\U000e0001"      # Language tag begin
    "\U000e0020-\U000e007f"  # Tag characters (ASCII smuggling)
    "]+"
)

# ── Prompt injection patterns ─────────────────────────────────────────
# Each tuple: (compiled regex, pattern name for logging)

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Direct instruction override
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "ignore_previous"),
    (re.compile(r"disregard\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "disregard_previous"),
    (re.compile(r"forget\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "forget_previous"),
    (re.compile(r"override\s+(all\s+)?(previous\s+)?instructions", re.IGNORECASE), "override_instructions"),

    # Role/persona manipulation
    (re.compile(r"you\s+are\s+now\b", re.IGNORECASE), "role_override"),
    (re.compile(r"act\s+as\s+(if\s+you\s+are\s+|a\s+)", re.IGNORECASE), "act_as"),
    (re.compile(r"pretend\s+(you\s+are|to\s+be)\b", re.IGNORECASE), "pretend_to_be"),
    (re.compile(r"you\s+must\s+now\s+behave\b", re.IGNORECASE), "must_behave"),
    (re.compile(r"switch\s+to\s+.*?\bmode\b", re.IGNORECASE), "switch_mode"),

    # System prompt extraction
    (re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE), "reveal_prompt"),
    (re.compile(r"show\s+(me\s+)?(your\s+)?(system\s+)?prompt", re.IGNORECASE), "show_prompt"),
    (re.compile(r"what\s+(is|are)\s+your\s+(system\s+)?instructions", re.IGNORECASE), "extract_instructions"),
    (re.compile(r"print\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE), "print_prompt"),
    (re.compile(r"output\s+(your\s+)?initial\s+instructions", re.IGNORECASE), "output_initial"),
    (re.compile(r"repeat\s+(the\s+)?(text|words)\s+above", re.IGNORECASE), "repeat_above"),
    (re.compile(r"display\s+your\s+(hidden|secret|internal)", re.IGNORECASE), "display_hidden"),

    # Jailbreak / DAN patterns
    (re.compile(r"\bDAN\b.*\bmode\b", re.IGNORECASE), "dan_mode"),
    (re.compile(r"do\s+anything\s+now", re.IGNORECASE), "do_anything_now"),
    (re.compile(r"jailbreak", re.IGNORECASE), "jailbreak"),
    (re.compile(r"bypass\s+(your\s+)?(safety|content)\s+(filters?|restrictions?)", re.IGNORECASE), "bypass_safety"),

    # Template injection (Jinja2, Handlebars, etc.)
    (re.compile(r"\{\{.*?\}\}"), "template_double_brace"),
    (re.compile(r"\{%.*?%\}"), "template_block_tag"),
    (re.compile(r"\$\{.*?\}"), "template_dollar_brace"),

    # Delimiter/fence manipulation
    (re.compile(r"<\|?system\|?>", re.IGNORECASE), "system_tag"),
    (re.compile(r"<\|?assistant\|?>", re.IGNORECASE), "assistant_tag"),
    (re.compile(r"<\|?user\|?>", re.IGNORECASE), "user_tag"),
    (re.compile(r"<\|?im_start\|?>", re.IGNORECASE), "im_start_tag"),
    (re.compile(r"<\|?im_end\|?>", re.IGNORECASE), "im_end_tag"),
    (re.compile(r"\[INST\]", re.IGNORECASE), "inst_tag"),
    (re.compile(r"<<SYS>>", re.IGNORECASE), "sys_tag"),

    # Data exfiltration
    (re.compile(r"send\s+(the\s+)?(data|information|results?)\s+to\b", re.IGNORECASE), "data_exfil"),
    (re.compile(r"(http|https|ftp)://\S+", re.IGNORECASE), "url_in_prompt"),
]

# Default max length for user input fields (chars)
_DEFAULT_MAX_LENGTH = 10_000

# Default LLM endpoint patterns
_DEFAULT_LLM_PATHS: list[str] = []


def normalize_text(text: str) -> str:
    """Normalize text to defeat Unicode bypass attacks.

    1. NFKC normalization — converts fullwidth, compatibility chars to ASCII equivalents
    2. Strip invisible characters — zero-width joiners, BOM, soft hyphens, tag chars
    """
    # NFKC: fullwidth 'ｉｇｎｏｒｅ' → 'ignore', compatibility forms → canonical
    text = unicodedata.normalize("NFKC", text)
    # Strip invisible characters that can break up keywords
    text = _INVISIBLE_CHARS.sub("", text)
    return text


def detect_injection(text: str) -> list[str]:
    """Scan text for prompt injection patterns. Returns list of matched pattern names.

    Applies Unicode normalization before matching to prevent bypass via
    fullwidth characters, Cyrillic homoglyphs, zero-width joiners, etc.
    """
    normalized = normalize_text(text)
    matches = []
    for pattern, name in _INJECTION_PATTERNS:
        if pattern.search(normalized):
            matches.append(name)
    return matches


def sanitize_text(text: str, max_length: int = _DEFAULT_MAX_LENGTH) -> str:
    """Sanitize user input text for safe LLM interpolation.

    1. Strip invisible/zero-width characters
    2. Truncate to max_length
    3. Escape XML-like tags that could break delimiters
    4. Wrap in <user_data>...</user_data> delimiters
    """
    # Strip invisible characters that could smuggle instructions
    text = _INVISIBLE_CHARS.sub("", text)

    # Truncate
    if len(text) > max_length:
        text = text[:max_length]

    # Escape angle brackets in user content to prevent delimiter breaking
    text = text.replace("<", "&lt;").replace(">", "&gt;")

    # Wrap in delimiters
    return f"<user_data>{text}</user_data>"


_MAX_EXTRACT_DEPTH = 64


def _extract_string_fields(obj, path: str = "", *, _depth: int = 0) -> list[tuple[str, str]]:
    """Recursively extract all string fields from a JSON-like object.

    Returns list of (dotted_path, value) tuples.
    Enforces a maximum recursion depth to prevent stack overflow from
    deeply nested JSON payloads (depth bomb DoS).
    """
    if _depth > _MAX_EXTRACT_DEPTH:
        return []
    fields = []
    if isinstance(obj, str):
        fields.append((path, obj))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}" if path else key
            fields.extend(_extract_string_fields(value, child_path, _depth=_depth + 1))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            child_path = f"{path}[{i}]"
            fields.extend(_extract_string_fields(item, child_path, _depth=_depth + 1))
    return fields


# Public alias for reuse by other middleware (e.g. SSRFValidator)
extract_string_fields = _extract_string_fields


def _set_nested_value(obj, path: str, value: str) -> None:
    """Set a value in a nested dict/list structure using a dotted path."""
    parts = []
    # Parse path like "messages[0].content" into parts
    for part in path.split("."):
        bracket = part.find("[")
        if bracket != -1:
            parts.append(part[:bracket])
            idx_str = part[bracket + 1 : part.index("]")]
            parts.append(int(idx_str))
        else:
            parts.append(part)

    current = obj
    for part in parts[:-1]:
        if isinstance(part, int):
            current = current[part]
        else:
            current = current[part]

    last = parts[-1]
    if isinstance(last, int):
        current[last] = value
    else:
        current[last] = value


class LLMSanitizer(Middleware):
    """Sanitize user input on LLM-facing endpoints to prevent prompt injection.

    Modes (configurable per customer):
      - detect_only: scan and log injection attempts, but don't modify the request
      - sanitize: wrap user input in <user_data> delimiters, escape tags, truncate (default)
      - block: reject requests containing injection patterns with 400

    Only applies to endpoints matching configured LLM path patterns.
    """

    async def process_request(self, request: Request, context: RequestContext) -> Request | Response | None:
        # Skip WebSocket upgrade requests (frame-level sanitization handled separately)
        if context.extra.get("is_websocket"):
            return None

        # Check feature flag
        features = context.customer_config.get("enabled_features", {})
        if not features.get("llm_sanitizer", True):
            return None

        # Get LLM endpoint patterns
        customer_settings = context.customer_config.get("settings", {})
        llm_cfg = customer_settings.get("llm", {})
        llm_paths = llm_cfg.get("paths", _DEFAULT_LLM_PATHS)

        # No configured LLM paths = nothing to do
        if not llm_paths:
            return None

        # Check if this request matches an LLM endpoint
        path = request.url.path
        if not self._matches_patterns(path, llm_paths):
            return None

        # Only process POST/PUT/PATCH requests (those with bodies)
        if request.method.upper() not in ("POST", "PUT", "PATCH"):
            return None

        # Read and parse request body
        body = await request.body()
        if not body:
            return None

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Non-JSON body — can't process, pass through
            return None

        if not isinstance(data, dict):
            return None

        # Extract all string fields (reuse cached result from SSRF validator if available)
        _cache_key = "_extracted_string_fields"
        if _cache_key in context.extra:
            string_fields = context.extra[_cache_key]
        else:
            string_fields = _extract_string_fields(data)
            context.extra[_cache_key] = string_fields
        if not string_fields:
            return None

        # Scan for injection patterns
        mode = self._get_mode(context)
        max_length = int(llm_cfg.get("max_input_length", _DEFAULT_MAX_LENGTH))
        all_detections: list[dict] = []

        for field_path, field_value in string_fields:
            detections = detect_injection(field_value)
            if detections:
                all_detections.append({
                    "field": field_path,
                    "patterns": detections,
                })

        # Log detections if any
        if all_detections:
            error_id = uuid4().hex[:8]
            logger.warning(
                "llm_injection_detected",
                error_id=error_id,
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                path=path,
                mode=mode,
                detections=all_detections,
            )

            if mode == "block":
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": True,
                        "message": "Request contains potentially unsafe content for AI processing.",
                        "error_id": error_id,
                    },
                )

        if mode == "detect_only":
            return None

        # mode == "sanitize": wrap all string fields in delimiters
        modified = False
        for field_path, field_value in string_fields:
            sanitized = sanitize_text(field_value, max_length)
            if sanitized != field_value:
                _set_nested_value(data, field_path, sanitized)
                modified = True

        if not modified:
            return None

        # Build a new request scope with the modified body
        new_body = json.dumps(data).encode("utf-8")
        context.extra["llm_sanitized"] = True
        context.extra["llm_original_body_size"] = len(body)
        context.extra["llm_sanitized_body_size"] = len(new_body)

        # Store modified body for the proxy handler to use
        context.extra["modified_body"] = new_body

        return None

    def _get_mode(self, context: RequestContext) -> str:
        """Get LLM sanitizer mode from customer config or global default."""
        customer_settings = context.customer_config.get("settings", {})
        llm_cfg = customer_settings.get("llm", {})
        mode = llm_cfg.get("mode")
        if mode in ("detect_only", "sanitize", "block"):
            return mode
        return "sanitize"

    def _matches_patterns(self, path: str, patterns: list[str]) -> bool:
        """Check if path matches any of the configured patterns."""
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
