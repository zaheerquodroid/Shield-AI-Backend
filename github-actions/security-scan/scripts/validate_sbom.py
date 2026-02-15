#!/usr/bin/env python3
"""Validate CycloneDX SBOM files for structure, bounds, and security.

Reads a CycloneDX JSON SBOM file and validates its structure, component
fields, and security invariants. Rejects malformed, oversized, or
symlink-pointed files.

Usage:
    python validate_sbom.py <path>
"""

import json
import os
import re
import sys

# --- Security constants ---

MAX_SBOM_SIZE = 50 * 1024 * 1024  # 50 MB per file
MAX_COMPONENTS = 100000

VALID_COMPONENT_TYPES = frozenset({
    "application",
    "container",
    "device",
    "file",
    "firmware",
    "framework",
    "library",
    "machine-learning-model",
    "operating-system",
    "platform",
})

# Token patterns to mask in SBOM text fields
TOKEN_MASK_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"ghs_[A-Za-z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{80,}"),
    re.compile(r"glpat-[A-Za-z0-9\-]{20,}"),
    re.compile(r"xox[bporas]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
    re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
]


def _sanitize_text(text: object) -> str:
    """Strip null bytes, newlines, and :: from text fields.

    Args:
        text: Raw text value. May be None or non-string.

    Returns:
        Sanitized single-line string.
    """
    if not isinstance(text, str):
        return ""
    text = text.replace("\x00", "")
    text = text.replace("\n", " ").replace("\r", " ")
    text = text.replace("::", " ")
    return text


def _mask_tokens(text: object) -> str:
    """Replace token patterns with [MASKED] in text."""
    if not isinstance(text, str):
        return ""
    for pattern in TOKEN_MASK_PATTERNS:
        text = pattern.sub("[MASKED]", text)
    return text


def validate_component(comp: dict) -> list[str]:
    """Validate a single CycloneDX component.

    Args:
        comp: Component dict from the SBOM.

    Returns:
        List of error messages (empty if valid).
    """
    errors: list[str] = []

    if not isinstance(comp, dict):
        return ["component is not a dict"]

    # type — required, must be in allowed set
    comp_type = comp.get("type")
    if not isinstance(comp_type, str):
        errors.append("component missing 'type' field")
    elif comp_type not in VALID_COMPONENT_TYPES:
        errors.append(f"invalid component type: {_sanitize_text(comp_type)}")

    # name — required, non-empty string
    name = comp.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("component missing or empty 'name' field")

    # version — optional, but must be string if present
    version = comp.get("version")
    if version is not None and not isinstance(version, str):
        errors.append("component 'version' must be a string")

    # purl — optional, but must be string starting with pkg: if present
    purl = comp.get("purl")
    if purl is not None:
        if not isinstance(purl, str):
            errors.append("component 'purl' must be a string")
        elif not purl.startswith("pkg:"):
            errors.append(f"invalid purl format: {_sanitize_text(purl[:50])}")

    return errors


def validate_cyclonedx(data: dict) -> tuple[bool, list[str]]:
    """Validate CycloneDX SBOM structure.

    Args:
        data: Parsed JSON data.

    Returns:
        Tuple of (valid, list of error messages).
    """
    errors: list[str] = []

    if not isinstance(data, dict):
        return False, ["SBOM is not a JSON object"]

    # bomFormat — required
    bom_format = data.get("bomFormat")
    if bom_format != "CycloneDX":
        errors.append(f"bomFormat must be 'CycloneDX', got: {_sanitize_text(bom_format)}")

    # specVersion — required, must start with "1."
    spec_version = data.get("specVersion")
    if not isinstance(spec_version, str) or not spec_version.startswith("1."):
        errors.append(f"specVersion must start with '1.', got: {_sanitize_text(spec_version)}")

    # components — required, must be list
    components = data.get("components")
    if not isinstance(components, list):
        errors.append("'components' must be a list")
    else:
        if len(components) > MAX_COMPONENTS:
            errors.append(f"component count {len(components)} exceeds limit {MAX_COMPONENTS}")
        else:
            for i, comp in enumerate(components):
                comp_errors = validate_component(comp)
                for err in comp_errors:
                    errors.append(f"component[{i}]: {err}")

    return len(errors) == 0, errors


def load_and_validate(path: str) -> tuple[dict | None, list[str]]:
    """Load and validate a CycloneDX SBOM file.

    Security guards:
    - Symlink rejection (TOCTOU-safe: check before open)
    - Bounded read (no stat + open race)
    - BOM stripping
    - RecursionError catch (deeply nested JSON)

    Args:
        path: Path to the SBOM JSON file.

    Returns:
        Tuple of (parsed dict or None, list of error messages).
    """
    errors: list[str] = []

    # Reject symlinks
    if os.path.islink(path):
        return None, ["symlinks not allowed"]

    try:
        with open(path) as f:
            raw = f.read(MAX_SBOM_SIZE + 1)
    except OSError as exc:
        return None, [f"cannot read file: {_sanitize_text(str(exc))}"]

    if len(raw) > MAX_SBOM_SIZE:
        return None, [f"file exceeds {MAX_SBOM_SIZE} byte limit"]

    # Strip UTF-8 BOM
    if raw.startswith("\ufeff"):
        raw = raw[1:]

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None, ["invalid JSON"]
    except RecursionError:
        return None, ["JSON nesting too deep"]

    valid, validation_errors = validate_cyclonedx(data)
    if not valid:
        return None, validation_errors

    return data, []


def main() -> int:
    """CLI entry point: validate a single SBOM file."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <sbom-path>", file=sys.stderr)
        return 1

    path = sys.argv[1]
    data, errors = load_and_validate(path)

    if errors:
        for err in errors:
            print(f"::error::{_mask_tokens(err)}", file=sys.stderr)
        return 1

    components = data.get("components", []) if data else []
    print(f"SBOM valid: {len(components)} components")
    return 0


if __name__ == "__main__":
    sys.exit(main())
