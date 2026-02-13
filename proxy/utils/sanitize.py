"""Shared sanitization utilities used across middleware."""

from __future__ import annotations

import re

# Comprehensive control character pattern covering:
# C0 controls (\x00-\x1f), DEL (\x7f), C1 controls (\x80-\x9f),
# Unicode line/paragraph separators (\u2028-\u2029),
# bidi overrides (\u200b-\u200f, \u202a-\u202e, \u2066-\u2069),
# zero-width no-break space / BOM (\ufeff).
CONTROL_CHARS_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)


def strip_control_chars(value: str) -> str:
    """Strip all control characters from a string."""
    return CONTROL_CHARS_RE.sub("", value)
