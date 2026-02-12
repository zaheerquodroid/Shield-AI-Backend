"""Pure-function CSP (Content-Security-Policy) utilities."""

from __future__ import annotations


def parse_csp(csp_string: str) -> dict[str, list[str]]:
    """Parse a CSP string into {directive: [values]} dict.

    Example:
        >>> parse_csp("default-src 'self'; script-src 'self' https:")
        {"default-src": ["'self'"], "script-src": ["'self'", "https:"]}
    """
    result: dict[str, list[str]] = {}
    if not csp_string or not csp_string.strip():
        return result
    for part in csp_string.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        values = tokens[1:]
        result[directive] = values
    return result


def merge_csp(base: dict[str, list[str]], override: dict[str, list[str]]) -> dict[str, list[str]]:
    """Merge override CSP directives into base, deduplicating values.

    Override values are appended to base values for each directive.
    New directives from override are added.
    """
    merged: dict[str, list[str]] = {}
    for directive, values in base.items():
        merged[directive] = list(values)
    for directive, values in override.items():
        if directive in merged:
            existing = set(merged[directive])
            for v in values:
                if v not in existing:
                    merged[directive].append(v)
                    existing.add(v)
        else:
            merged[directive] = list(values)
    return merged


def build_csp(directives: dict[str, list[str]]) -> str:
    """Build a CSP string from {directive: [values]} dict.

    Example:
        >>> build_csp({"default-src": ["'self'"], "script-src": ["'self'", "https:"]})
        "default-src 'self'; script-src 'self' https:"
    """
    parts = []
    for directive, values in directives.items():
        if values:
            parts.append(f"{directive} {' '.join(values)}")
        else:
            parts.append(directive)
    return "; ".join(parts)
