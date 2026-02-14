"""Regex-based JavaScript code validator.

No Node.js/tree-sitter dependency — pure regex. Deliberately
overapproximates (false positives OK, false negatives not OK).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from proxy.validation.rules import (
    JS_COMPILED_PATTERNS,
    SHELL_COMPILED_PATTERNS,
    RuleCategory,
    Severity,
)

MAX_CODE_SIZE = 100_000  # 100 KB

# Match JS string literals (single-quoted, double-quoted, backtick)
_JS_STRING_RE = re.compile(
    r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)""",
    re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class Finding:
    """A single validation finding."""

    rule_id: str
    category: RuleCategory
    severity: Severity
    message: str
    line: int
    col: int
    snippet: str


def _line_from_pos(code: str, pos: int) -> int:
    """Calculate 1-based line number from character position."""
    return code[:pos].count("\n") + 1


def _snippet(code: str, match: re.Match) -> str:
    """Extract a truncated snippet around a match."""
    start = max(0, match.start() - 10)
    end = min(len(code), match.end() + 30)
    return code[start:end].replace("\n", " ")[:80]


class JavaScriptValidator:
    """Validate JavaScript code using regex scanning."""

    def validate(self, code: str) -> list[Finding]:
        """Validate JavaScript code. Returns list of findings."""
        findings: list[Finding] = []

        # Size check
        if len(code) > MAX_CODE_SIZE:
            findings.append(Finding(
                rule_id="js-code-too-large",
                category=RuleCategory.code_injection,
                severity=Severity.high,
                message=f"Code exceeds maximum size ({len(code)} > {MAX_CODE_SIZE})",
                line=0,
                col=0,
                snippet="",
            ))
            return findings

        # Scan against JS dangerous patterns
        for pattern, sev, rule_id, desc in JS_COMPILED_PATTERNS:
            for m in pattern.finditer(code):
                findings.append(Finding(
                    rule_id=rule_id,
                    category=RuleCategory.code_injection,
                    severity=sev,
                    message=f"Dangerous JS pattern: {desc}",
                    line=_line_from_pos(code, m.start()),
                    col=0,
                    snippet=_snippet(code, m),
                ))

        # Extract string literals and check for shell patterns
        for string_match in _JS_STRING_RE.finditer(code):
            content = string_match.group(0)[1:-1]  # Strip quotes
            for pattern, sev, rule_id, desc in SHELL_COMPILED_PATTERNS:
                if pattern.search(content):
                    findings.append(Finding(
                        rule_id=rule_id,
                        category=RuleCategory.shell_execution,
                        severity=sev,
                        message=f"Shell pattern in JS string: {desc}",
                        line=_line_from_pos(code, string_match.start()),
                        col=0,
                        snippet=content[:80],
                    ))

        return findings
