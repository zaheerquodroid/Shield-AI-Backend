#!/usr/bin/env python3
"""Convert pip-audit JSON output to SARIF 2.1.0 format.

Usage:
    python pip_audit_to_sarif.py <input.json> <output.sarif>
"""

import json
import os
import sys

MAX_INPUT_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_RESULTS = 10000


def convert(input_path: str, output_path: str) -> None:
    """Read pip-audit JSON and write SARIF 2.1.0.

    Args:
        input_path: Path to pip-audit JSON output.
        output_path: Path to write SARIF file.
    """
    try:
        file_size = os.path.getsize(input_path)
        if file_size > MAX_INPUT_SIZE:
            print(f"::warning::pip-audit input exceeds {MAX_INPUT_SIZE} bytes, skipping", file=sys.stderr)
            data = {"dependencies": []}
        else:
            with open(input_path) as f:
                data = json.load(f)
    except (json.JSONDecodeError, OSError, FileNotFoundError):
        data = {"dependencies": []}

    if not isinstance(data, dict):
        data = {"dependencies": []}

    results = []
    rules = []
    rule_ids = set()

    dependencies = data.get("dependencies", [])
    if isinstance(dependencies, list):
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            vulns = dep.get("vulns", [])
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                if len(results) >= MAX_RESULTS:
                    break
                if not isinstance(vuln, dict):
                    continue
                vuln_id = vuln.get("id") or "UNKNOWN"
                name = dep.get("name") or "unknown"
                version = dep.get("version") or "unknown"
                fix_versions = vuln.get("fix_versions", [])
                fix_str = ", ".join(str(v) for v in fix_versions) if isinstance(fix_versions, list) else ""

                # Build rule
                if vuln_id not in rule_ids:
                    rule_ids.add(vuln_id)
                    rule = {
                        "id": vuln_id,
                        "shortDescription": {"text": f"{vuln_id} in {name}"},
                        "helpUri": f"https://osv.dev/vulnerability/{vuln_id}",
                        "properties": {
                            "security-severity": "7.0",
                        },
                    }
                    rules.append(rule)

                # Build result
                message_text = f"{vuln_id}: {name}@{version}"
                if fix_str:
                    message_text += f" (fix: {fix_str})"

                result = {
                    "ruleId": vuln_id,
                    "level": "error",
                    "message": {"text": message_text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "requirements.txt"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
                results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://github.com/pypa/pip-audit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.sarif>", file=sys.stderr)
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
