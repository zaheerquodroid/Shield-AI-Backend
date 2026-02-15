#!/usr/bin/env python3
"""Merge multiple CycloneDX SBOM files into a single deduplicated SBOM.

Loads all *.cdx.json files from a directory, validates each, merges
components with deduplication by purl or (type, name, version), and
writes the merged result.

Usage:
    python merge_sboms.py \
        --sbom-dir /path/to/sboms \
        --output /path/to/merged.cdx.json \
        --github-output /path/to/GITHUB_OUTPUT
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from validate_sbom import (
    MAX_SBOM_SIZE,
    TOKEN_MASK_PATTERNS,
    _sanitize_text,
    validate_cyclonedx,
)

# --- Security constants ---

MAX_SBOM_FILES = 20
MAX_COMPONENTS = 100000


def _mask_tokens(text: object) -> str:
    """Replace token patterns with [MASKED] in text."""
    if not isinstance(text, str):
        return ""
    for pattern in TOKEN_MASK_PATTERNS:
        text = pattern.sub("[MASKED]", text)
    return text


def load_sbom_files(sbom_dir: str) -> list[dict]:
    """Load and validate all *.cdx.json SBOM files from a directory.

    Security guards:
    - Symlink rejection per file
    - Bounded reads (no TOCTOU)
    - BOM stripping
    - File count cap
    - RecursionError catch

    Args:
        sbom_dir: Path to directory containing SBOM files.

    Returns:
        List of validated SBOM dicts.
    """
    sboms: list[dict] = []
    dir_path = Path(sbom_dir)

    if not dir_path.is_dir():
        return sboms

    cdx_files = sorted(dir_path.glob("*.cdx.json"))

    for idx, cdx_file in enumerate(cdx_files):
        if idx >= MAX_SBOM_FILES:
            print(
                f"::warning::SBOM file limit reached ({MAX_SBOM_FILES}), skipping remaining",
                file=sys.stderr,
            )
            break

        # Reject symlinks
        if cdx_file.is_symlink():
            print(
                f"::warning::Skipping {cdx_file.name}: symlinks not allowed",
                file=sys.stderr,
            )
            continue

        try:
            with open(cdx_file) as f:
                raw = f.read(MAX_SBOM_SIZE + 1)
        except OSError:
            print(
                f"::warning::Skipping {cdx_file.name}: cannot read file",
                file=sys.stderr,
            )
            continue

        if len(raw) > MAX_SBOM_SIZE:
            print(
                f"::warning::Skipping {cdx_file.name}: exceeds size limit",
                file=sys.stderr,
            )
            continue

        # Strip UTF-8 BOM
        if raw.startswith("\ufeff"):
            raw = raw[1:]

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, RecursionError):
            print(
                f"::warning::Skipping {cdx_file.name}: invalid JSON",
                file=sys.stderr,
            )
            continue

        valid, errors = validate_cyclonedx(data)
        if not valid:
            print(
                f"::warning::Skipping {cdx_file.name}: validation failed",
                file=sys.stderr,
            )
            continue

        sboms.append(data)

    return sboms


def _deduplicate_components(components: list[dict]) -> list[dict]:
    """Deduplicate components by purl (primary) or (type, name, version) fallback.

    Args:
        components: List of component dicts.

    Returns:
        Deduplicated list of components.
    """
    seen: set[str] = set()
    unique: list[dict] = []

    for comp in components:
        if not isinstance(comp, dict):
            continue

        # Primary key: purl
        purl = comp.get("purl")
        if isinstance(purl, str) and purl:
            if purl in seen:
                continue
            seen.add(purl)
            unique.append(comp)
            continue

        # Fallback key: (type, name, version)
        comp_type = comp.get("type", "")
        name = comp.get("name", "")
        version = comp.get("version", "")
        key = f"{comp_type}:{name}:{version}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(comp)

    return unique


def _merge_metadata(sboms: list[dict]) -> dict:
    """Merge metadata from multiple SBOMs.

    Combines tool lists and uses the latest timestamp.

    Args:
        sboms: List of validated SBOM dicts.

    Returns:
        Merged metadata dict.
    """
    tools: list[dict] = []
    latest_timestamp = ""

    for sbom in sboms:
        metadata = sbom.get("metadata")
        if not isinstance(metadata, dict):
            continue

        # Collect tools
        sbom_tools = metadata.get("tools")
        if isinstance(sbom_tools, list):
            for tool in sbom_tools:
                if isinstance(tool, dict):
                    tools.append(tool)

        # Track latest timestamp
        ts = metadata.get("timestamp")
        if isinstance(ts, str) and ts > latest_timestamp:
            latest_timestamp = ts

    if not latest_timestamp:
        latest_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    result: dict = {
        "timestamp": latest_timestamp,
        "tools": [{"vendor": "ShieldAI", "name": "sbom-merge", "version": "1.0.0"}],
    }

    if tools:
        result["tools"].extend(tools)

    return result


def merge_sboms(sboms: list[dict]) -> dict:
    """Merge multiple CycloneDX SBOMs into a single document.

    Args:
        sboms: List of validated SBOM dicts.

    Returns:
        Merged CycloneDX SBOM dict.
    """
    if not sboms:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": [{"vendor": "ShieldAI", "name": "sbom-merge", "version": "1.0.0"}],
            },
            "components": [],
        }

    # Collect all components
    all_components: list[dict] = []
    for sbom in sboms:
        components = sbom.get("components")
        if isinstance(components, list):
            all_components.extend(components)

    # Deduplicate
    unique = _deduplicate_components(all_components)

    # Cap components
    if len(unique) > MAX_COMPONENTS:
        print(
            f"::warning::Component count {len(unique)} exceeds limit {MAX_COMPONENTS}, truncating",
            file=sys.stderr,
        )
        unique = unique[:MAX_COMPONENTS]

    # Mask tokens in component fields
    for comp in unique:
        for field in ("name", "version", "description", "purl"):
            val = comp.get(field)
            if isinstance(val, str):
                comp[field] = _mask_tokens(val)

    # Build merged SBOM
    metadata = _merge_metadata(sboms)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": unique,
    }


def _sanitize_output_value(value: str) -> str:
    """Strip newlines from GITHUB_OUTPUT values."""
    return str(value).replace("\n", "").replace("\r", "")


def write_outputs(
    component_count: int,
    sbom_path: str,
    valid: bool,
    github_output: str,
) -> None:
    """Write step outputs to GITHUB_OUTPUT file.

    Args:
        component_count: Number of deduplicated components.
        sbom_path: Path to the merged SBOM file.
        valid: Whether the merged SBOM is valid.
        github_output: Path to GITHUB_OUTPUT file.
    """
    lines = [
        f"sbom-file={_sanitize_output_value(sbom_path)}",
        f"component-count={component_count}",
        f"sbom-valid={str(valid).lower()}",
    ]
    with open(github_output, "a") as f:
        for line in lines:
            f.write(line + "\n")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Merge CycloneDX SBOM files")
    parser.add_argument("--sbom-dir", required=True, help="Directory with *.cdx.json files")
    parser.add_argument("--output", required=True, help="Output merged SBOM path")
    parser.add_argument("--github-output", required=True, help="GITHUB_OUTPUT file path")
    args = parser.parse_args()

    # Validate sbom-dir
    if not args.sbom_dir or not os.path.isdir(args.sbom_dir):
        print(
            f"::error::sbom-dir must be a valid directory, got '{_sanitize_text(args.sbom_dir)}'",
            file=sys.stderr,
        )
        return 1

    # Load and validate all SBOMs
    sboms = load_sbom_files(args.sbom_dir)

    if not sboms:
        print("::warning::No valid SBOM files found", file=sys.stderr)

    # Merge
    merged = merge_sboms(sboms)

    # Write merged SBOM
    with open(args.output, "w") as f:
        json.dump(merged, f, indent=2)

    # Validate merged result
    valid, errors = validate_cyclonedx(merged)
    component_count = len(merged.get("components", []))

    # Write outputs
    write_outputs(component_count, args.output, valid, args.github_output)

    print(f"Merged SBOM: {component_count} components, valid={valid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
