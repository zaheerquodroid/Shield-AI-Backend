#!/usr/bin/env python3
"""Aggregate SARIF files, normalize severity, emit PR annotations, and apply threshold.

Reads all .sarif files from a results directory, merges them into a single
SARIF 2.1.0 document, emits GitHub Actions workflow commands for PR annotations,
and applies a configurable severity threshold to determine pass/fail.

Usage:
    python aggregate_sarif.py \
        --results-dir /path/to/sarif-files \
        --threshold high \
        --output-sarif /path/to/merged.sarif \
        --github-output /path/to/GITHUB_OUTPUT \
        --fail-on-findings true
"""

import argparse
import json
import math
import os
import re
import sys
from pathlib import Path

# --- Security constants ---

MAX_SARIF_SIZE = 10 * 1024 * 1024  # 10 MB per file
MAX_FINDINGS = 5000
MAX_ANNOTATIONS = 50
MAX_SARIF_FILES = 50

# Token patterns to mask in annotations
TOKEN_MASK_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),       # GitHub PAT
    re.compile(r"ghs_[A-Za-z0-9]{36,}"),       # GitHub App token
    re.compile(r"github_pat_[A-Za-z0-9_]{80,}"),  # GitHub fine-grained PAT
    re.compile(r"glpat-[A-Za-z0-9\-]{20,}"),   # GitLab PAT
    re.compile(r"xox[bporas]-[A-Za-z0-9\-]{10,}"),  # Slack token
    re.compile(r"AKIA[0-9A-Z]{16}"),            # AWS access key
    re.compile(r"sk-[A-Za-z0-9]{32,}"),         # OpenAI/Stripe key
    re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),  # Private key
]

# Severity levels in order of severity
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
VALID_THRESHOLDS = {"critical", "high", "medium", "low", "any"}

# SARIF level to severity mapping
SARIF_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}


def sanitize_uri(uri: str) -> str:
    """Strip path traversal and dangerous patterns from artifact URIs.

    Uses iterative replacement to prevent nested bypass (e.g. '....//').

    Args:
        uri: Raw URI from SARIF result.

    Returns:
        Sanitized URI safe for annotation output.
    """
    if not isinstance(uri, str):
        return ""
    # Reject null bytes
    if "\x00" in uri:
        return ""
    # Strip file:/// prefix
    uri = re.sub(r"^file:///", "", uri)
    # Remove backslashes (normalize before traversal check)
    uri = uri.replace("\\", "/")
    # URL-decode common traversal encodings (case-insensitive)
    uri = re.sub(r"%2e", ".", uri, flags=re.IGNORECASE)
    uri = re.sub(r"%2f", "/", uri, flags=re.IGNORECASE)
    # Iterative removal of path traversal — handles nested ....// → ../
    prev = None
    while prev != uri:
        prev = uri
        uri = uri.replace("../", "")
    # Reject any remaining .. components (e.g. trailing '..' without slash)
    if ".." in uri:
        return ""
    # Strip characters that could poison annotation format (::error file=X,line=Y::)
    uri = uri.replace("\n", "").replace("\r", "")
    uri = re.sub(r"[,;:]{2,}", "", uri)  # strip :: and similar delimiters
    return uri


def _sanitize_annotation_text(text: str) -> str:
    """Remove characters that could inject workflow commands.

    Strips newlines, carriage returns, and :: sequences that could
    produce rogue workflow commands in annotation output.

    Args:
        text: Raw text from SARIF message/ruleId.

    Returns:
        Sanitized single-line text.
    """
    # Strip newlines and carriage returns to prevent command injection
    text = text.replace("\n", " ").replace("\r", " ")
    # Truncate to prevent excessive annotation length
    if len(text) > 500:
        text = text[:497] + "..."
    return text


def validate_sarif(data: object) -> bool:
    """Validate basic SARIF structure.

    Args:
        data: Parsed JSON data.

    Returns:
        True if the data has valid SARIF structure.
    """
    if not isinstance(data, dict):
        return False
    if data.get("version") != "2.1.0":
        return False
    if not isinstance(data.get("$schema"), str) and "version" in data:
        pass  # schema is optional
    runs = data.get("runs")
    if not isinstance(runs, list):
        return False
    return True


def normalize_severity(result: dict, rules: dict) -> str:
    """Map a SARIF result to a normalized severity level.

    Uses security-severity score from rule properties if available,
    otherwise falls back to SARIF level mapping.

    Args:
        result: A SARIF result dict.
        rules: Dict of {rule_id: rule_dict} for looking up properties.

    Returns:
        Normalized severity: critical, high, medium, or low.
    """
    rule_id = result.get("ruleId", "")
    rule = rules.get(rule_id, {})

    # Check for security-severity in rule properties
    props = rule.get("properties", {})
    score_str = props.get("security-severity", "")
    if score_str:
        try:
            score = float(score_str)
            # Reject NaN/Inf — fall through to SARIF level mapping
            if not math.isfinite(score):
                pass
            elif score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            else:
                return "low"
        except (ValueError, TypeError):
            pass

    # Fall back to SARIF level
    level = result.get("level", "warning")
    return SARIF_LEVEL_MAP.get(level, "medium")


def _mask_tokens(text: str) -> str:
    """Replace token patterns with [MASKED] in text."""
    for pattern in TOKEN_MASK_PATTERNS:
        text = pattern.sub("[MASKED]", text)
    return text


def load_sarif_files(results_dir: str) -> list[dict]:
    """Load all .sarif files from the results directory.

    Args:
        results_dir: Path to directory containing .sarif files.

    Returns:
        List of parsed SARIF run dicts.
    """
    runs = []
    results_path = Path(results_dir)

    if not results_path.is_dir():
        return runs

    sarif_files = sorted(results_path.glob("*.sarif"))

    for idx, sarif_file in enumerate(sarif_files):
        if idx >= MAX_SARIF_FILES:
            print(
                f"::warning::SARIF file limit reached ({MAX_SARIF_FILES}), skipping remaining files",
                file=sys.stderr,
            )
            break

        # Size check
        if sarif_file.stat().st_size > MAX_SARIF_SIZE:
            print(
                f"::warning::Skipping {sarif_file.name}: exceeds {MAX_SARIF_SIZE} byte limit",
                file=sys.stderr,
            )
            continue

        try:
            with open(sarif_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            print(
                f"::warning::Skipping {sarif_file.name}: invalid JSON",
                file=sys.stderr,
            )
            continue

        if not validate_sarif(data):
            print(
                f"::warning::Skipping {sarif_file.name}: invalid SARIF structure",
                file=sys.stderr,
            )
            continue

        for run in data.get("runs", []):
            if isinstance(run, dict):
                runs.append(run)

    return runs


def emit_annotations(results: list[dict], rules: dict) -> None:
    """Emit GitHub Actions workflow commands for PR annotations.

    Args:
        results: List of SARIF result dicts with normalized severity.
        rules: Rule lookup dict for severity normalization.
    """
    count = 0
    for result in results:
        if count >= MAX_ANNOTATIONS:
            print(
                f"::warning::Annotation limit reached ({MAX_ANNOTATIONS}), "
                "remaining findings not annotated",
                file=sys.stderr,
            )
            break

        severity = normalize_severity(result, rules)
        raw_message = result.get("message", {}).get("text", "Finding")
        message = _sanitize_annotation_text(_mask_tokens(raw_message))
        rule_id = _sanitize_annotation_text(result.get("ruleId", "unknown"))

        # Extract location
        locations = result.get("locations", [])
        file_path = ""
        line = 1
        if locations and isinstance(locations[0], dict):
            phys = locations[0].get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            file_path = sanitize_uri(artifact.get("uri", ""))
            # Strip commas — they separate annotation parameters (file=X,line=Y)
            # and could inject extra parameters like title= or col=
            file_path = file_path.replace(",", "")
            region = phys.get("region", {})
            line = region.get("startLine", 1)
            if not isinstance(line, int) or line < 1:
                line = 1

        # Map severity to annotation level
        if severity in ("critical", "high"):
            level = "error"
        elif severity == "medium":
            level = "warning"
        else:
            level = "notice"

        annotation = f"::{level} file={file_path},line={line}::[{severity.upper()}] {rule_id}: {message}"
        print(annotation)
        count += 1


def merge_sarif(runs: list[dict]) -> dict:
    """Produce a single merged SARIF 2.1.0 document from multiple runs.

    Args:
        runs: List of SARIF run dicts.

    Returns:
        Merged SARIF document dict.
    """
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs if runs else [{"tool": {"driver": {"name": "shieldai-security-scan", "rules": []}}, "results": []}],
    }


def apply_threshold(counts: dict[str, int], threshold: str) -> bool:
    """Determine if findings exceed the severity threshold.

    Args:
        counts: Dict of {severity: count}.
        threshold: Minimum severity to trigger failure.

    Returns:
        True if findings exceed threshold (should fail).
    """
    if threshold == "any":
        return sum(counts.values()) > 0

    if threshold not in SEVERITY_ORDER:
        print(
            f"::warning::Invalid threshold '{threshold}', defaulting to 'high'",
            file=sys.stderr,
        )
        threshold = "high"

    threshold_idx = SEVERITY_ORDER.index(threshold)
    for i in range(threshold_idx + 1):
        if counts.get(SEVERITY_ORDER[i], 0) > 0:
            return True
    return False


def _sanitize_output_value(value: str) -> str:
    """Strip newlines and carriage returns from GITHUB_OUTPUT values.

    Prevents CVE-2022-35954-style injection where a crafted value
    containing newlines could inject additional key=value pairs into
    GITHUB_OUTPUT, potentially overriding scan-result.

    Args:
        value: Raw value to write.

    Returns:
        Single-line sanitized value.
    """
    return str(value).replace("\n", "").replace("\r", "")


def write_outputs(
    counts: dict[str, int],
    result: str,
    sarif_path: str,
    github_output: str,
) -> None:
    """Write step outputs to GITHUB_OUTPUT file.

    Args:
        counts: Dict of {severity: count}.
        result: "pass" or "fail".
        sarif_path: Path to the merged SARIF file.
        github_output: Path to GITHUB_OUTPUT file.
    """
    total = sum(counts.values())
    lines = [
        f"scan-result={_sanitize_output_value(result)}",
        f"findings-count={total}",
        f"critical-count={counts.get('critical', 0)}",
        f"high-count={counts.get('high', 0)}",
        f"medium-count={counts.get('medium', 0)}",
        f"low-count={counts.get('low', 0)}",
        f"sarif-file={_sanitize_output_value(sarif_path)}",
    ]
    with open(github_output, "a") as f:
        for line in lines:
            f.write(line + "\n")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Aggregate SARIF scan results")
    parser.add_argument("--results-dir", required=True, help="Directory with .sarif files")
    parser.add_argument("--threshold", default="high", help="Severity threshold")
    parser.add_argument("--output-sarif", required=True, help="Output merged SARIF path")
    parser.add_argument("--github-output", required=True, help="GITHUB_OUTPUT file path")
    parser.add_argument("--fail-on-findings", default="true", help="Fail on findings")
    args = parser.parse_args()

    # Validate threshold early
    if args.threshold not in VALID_THRESHOLDS:
        print(
            f"::warning::Invalid threshold '{args.threshold}', defaulting to 'high'",
            file=sys.stderr,
        )
        args.threshold = "high"

    # Load all SARIF files
    runs = load_sarif_files(args.results_dir)

    # Build rules lookup and collect results
    all_rules: dict[str, dict] = {}
    all_results: list[dict] = []

    for run in runs:
        # Build rules index
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        for rule in driver.get("rules", []):
            rule_id = rule.get("id", "")
            if rule_id:
                all_rules[rule_id] = rule

        # Collect results (cap at MAX_FINDINGS)
        for result in run.get("results", []):
            if len(all_results) >= MAX_FINDINGS:
                break
            if isinstance(result, dict):
                all_results.append(result)

    # Count by severity
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for result in all_results:
        severity = normalize_severity(result, all_rules)
        counts[severity] = counts.get(severity, 0) + 1

    # Emit annotations
    emit_annotations(all_results, all_rules)

    # Merge and write SARIF
    merged = merge_sarif(runs)
    with open(args.output_sarif, "w") as f:
        json.dump(merged, f, indent=2)

    # Determine result
    fail_on_findings = args.fail_on_findings.lower() == "true"
    exceeds = apply_threshold(counts, args.threshold)
    scan_result = "fail" if (exceeds and fail_on_findings) else "pass"

    # Write outputs
    write_outputs(counts, scan_result, args.output_sarif, args.github_output)

    # Exit code
    if scan_result == "fail":
        total = sum(counts.values())
        print(f"::error::Security scan failed: {total} finding(s) at or above '{args.threshold}' threshold")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
