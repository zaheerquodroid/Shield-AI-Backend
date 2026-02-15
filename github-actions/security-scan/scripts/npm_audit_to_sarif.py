#!/usr/bin/env python3
"""Convert npm audit JSON output to SARIF 2.1.0 format.

Handles both npm 6 (advisories object) and npm 7+ (vulnerabilities object) formats.

Usage:
    python npm_audit_to_sarif.py <input.json> <output.sarif>
"""

import json
import sys

MAX_INPUT_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_RESULTS = 10000

# npm severity to SARIF security-severity score
SEVERITY_SCORES = {
    "critical": "9.5",
    "high": "7.5",
    "moderate": "5.0",
    "low": "2.5",
    "info": "1.0",
}

SEVERITY_LEVELS = {
    "critical": "error",
    "high": "error",
    "moderate": "warning",
    "low": "note",
    "info": "note",
}


def convert(input_path: str, output_path: str) -> None:
    """Read npm audit JSON and write SARIF 2.1.0.

    Args:
        input_path: Path to npm audit JSON output.
        output_path: Path to write SARIF file.
    """
    try:
        # Size-limited read to prevent TOCTOU race (stat then open)
        with open(input_path) as f:
            raw = f.read(MAX_INPUT_SIZE + 1)
        if len(raw) > MAX_INPUT_SIZE:
            print(f"::warning::npm audit input exceeds {MAX_INPUT_SIZE} bytes, skipping", file=sys.stderr)
            data = {}
        else:
            data = json.loads(raw)
    except (json.JSONDecodeError, OSError, FileNotFoundError):
        data = {}

    if not isinstance(data, dict):
        data = {}

    results = []
    rules = []
    rule_ids = set()

    # npm 6 format: { "advisories": { "1234": {...}, ... } }
    advisories = data.get("advisories", {})
    if isinstance(advisories, dict):
        for adv_id, advisory in advisories.items():
            if len(results) >= MAX_RESULTS:
                break
            if not isinstance(advisory, dict):
                continue
            _process_advisory(advisory, str(adv_id), results, rules, rule_ids)

    # npm 7+ format: { "vulnerabilities": { "package-name": {...}, ... } }
    vulnerabilities = data.get("vulnerabilities", {})
    if isinstance(vulnerabilities, dict):
        for pkg_name, vuln in vulnerabilities.items():
            if len(results) >= MAX_RESULTS:
                break
            if not isinstance(vuln, dict):
                continue
            via = vuln.get("via", [])
            if isinstance(via, list):
                for entry in via:
                    if len(results) >= MAX_RESULTS:
                        break
                    if isinstance(entry, dict):
                        _process_npm7_vuln(entry, pkg_name, results, rules, rule_ids)
                    elif isinstance(entry, str):
                        # Transitive dependency reference — skip
                        pass

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "npm-audit",
                        "informationUri": "https://docs.npmjs.com/cli/audit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)


def _process_advisory(
    advisory: dict,
    adv_id: str,
    results: list,
    rules: list,
    rule_ids: set,
) -> None:
    """Process an npm 6 advisory into SARIF results and rules."""
    severity = advisory.get("severity") or "moderate"
    title = advisory.get("title") or f"Advisory {adv_id}"
    module_name = advisory.get("module_name") or "unknown"
    rule_id = f"npm-advisory-{adv_id}"

    if rule_id not in rule_ids:
        rule_ids.add(rule_id)
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": title},
            "properties": {
                "security-severity": SEVERITY_SCORES.get(severity, "5.0"),
            },
        })

    results.append({
        "ruleId": rule_id,
        "level": SEVERITY_LEVELS.get(severity, "warning"),
        "message": {"text": f"{title} in {module_name}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "package-lock.json"},
                    "region": {"startLine": 1},
                }
            }
        ],
    })


def _process_npm7_vuln(
    entry: dict,
    pkg_name: str,
    results: list,
    rules: list,
    rule_ids: set,
) -> None:
    """Process an npm 7+ vulnerability via entry into SARIF results and rules."""
    severity = entry.get("severity") or "moderate"
    title = entry.get("title") or entry.get("name") or f"Vulnerability in {pkg_name}"
    source_id = str(entry.get("source") or entry.get("url") or pkg_name)
    rule_id = f"npm-vuln-{source_id}"

    if rule_id not in rule_ids:
        rule_ids.add(rule_id)
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": title},
            "properties": {
                "security-severity": SEVERITY_SCORES.get(severity, "5.0"),
            },
        })

    results.append({
        "ruleId": rule_id,
        "level": SEVERITY_LEVELS.get(severity, "warning"),
        "message": {"text": f"{title} in {pkg_name}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "package-lock.json"},
                    "region": {"startLine": 1},
                }
            }
        ],
    })


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.sarif>", file=sys.stderr)
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
