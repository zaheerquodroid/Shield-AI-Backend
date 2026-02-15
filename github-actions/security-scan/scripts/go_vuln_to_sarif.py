#!/usr/bin/env python3
"""Convert govulncheck JSON output to SARIF 2.1.0 format.

Parses newline-delimited JSON from govulncheck -json and maps
vulnerability.osv entries to SARIF results.

Usage:
    python go_vuln_to_sarif.py <input.json> <output.sarif>
"""

import json
import sys

MAX_INPUT_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_RESULTS = 10000


def convert(input_path: str, output_path: str) -> None:
    """Read govulncheck JSON and write SARIF 2.1.0.

    Args:
        input_path: Path to govulncheck JSON output.
        output_path: Path to write SARIF file.
    """
    results = []
    rules = []
    rule_ids = set()

    try:
        # Size-limited read to prevent TOCTOU race and 2x memory from read+split
        with open(input_path) as f:
            content = f.read(MAX_INPUT_SIZE + 1)
        if len(content) > MAX_INPUT_SIZE:
            print(f"::warning::govulncheck input exceeds {MAX_INPUT_SIZE} bytes, skipping", file=sys.stderr)
            content = ""
    except (OSError, FileNotFoundError):
        content = ""

    # govulncheck outputs newline-delimited JSON objects
    for line in content.split("\n"):
        if len(results) >= MAX_RESULTS:
            break
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(entry, dict):
            continue

        # Look for vulnerability entries
        vuln = entry.get("vulnerability")
        if not isinstance(vuln, dict):
            # Also handle the finding structure
            finding = entry.get("finding")
            if isinstance(finding, dict):
                _process_finding(finding, results, rules, rule_ids)
            continue

        osv = vuln.get("osv", {})
        if not isinstance(osv, dict):
            continue

        vuln_id = osv.get("id", "")
        if not vuln_id:
            continue

        summary = osv.get("summary") or f"Vulnerability {vuln_id}"
        affected = osv.get("affected", [])
        module_path = ""
        if isinstance(affected, list) and affected:
            pkg = affected[0] if isinstance(affected[0], dict) else {}
            # Guard against null values: pkg.get("package", {}) returns None
            # when "package" key exists with null value
            pkg_info = pkg.get("package")
            if isinstance(pkg_info, dict):
                module_path = pkg_info.get("name") or ""
            if not module_path:
                mod_info = pkg.get("module")
                if isinstance(mod_info, dict):
                    module_path = mod_info.get("path") or ""

        if vuln_id not in rule_ids:
            rule_ids.add(vuln_id)
            rules.append({
                "id": vuln_id,
                "shortDescription": {"text": summary},
                "helpUri": f"https://pkg.go.dev/vuln/{vuln_id}",
                "properties": {
                    "security-severity": "7.0",
                },
            })

        results.append({
            "ruleId": vuln_id,
            "level": "error",
            "message": {"text": f"{vuln_id}: {summary} ({module_path})"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "go.mod"},
                        "region": {"startLine": 1},
                    }
                }
            ],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "govulncheck",
                        "informationUri": "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)


def _process_finding(
    finding: dict,
    results: list,
    rules: list,
    rule_ids: set,
) -> None:
    """Process a govulncheck finding entry."""
    osv_id = finding.get("osv", "")
    if not osv_id:
        return

    if osv_id not in rule_ids:
        rule_ids.add(osv_id)
        rules.append({
            "id": osv_id,
            "shortDescription": {"text": f"Vulnerability {osv_id}"},
            "helpUri": f"https://pkg.go.dev/vuln/{osv_id}",
            "properties": {
                "security-severity": "7.0",
            },
        })

    # Extract trace info for location — validate attacker-controlled values
    trace = finding.get("trace", [])
    file_path = "go.mod"
    line = 1
    if isinstance(trace, list):
        for frame in trace:
            if isinstance(frame, dict) and "position" in frame:
                pos = frame["position"]
                if isinstance(pos, dict):
                    raw_path = pos.get("filename")
                    if isinstance(raw_path, str) and raw_path:
                        file_path = raw_path
                    raw_line = pos.get("line")
                    if isinstance(raw_line, int) and raw_line >= 1:
                        line = raw_line
                    break

    results.append({
        "ruleId": osv_id,
        "level": "error",
        "message": {"text": f"Vulnerability {osv_id} found"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": line},
                }
            }
        ],
    })


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.sarif>", file=sys.stderr)
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
