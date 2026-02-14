"""Unified code validator dispatching to language-specific validators."""

from __future__ import annotations

from dataclasses import dataclass, field

from proxy.validation.javascript_validator import JavaScriptValidator
from proxy.validation.javascript_validator import Finding as JSFinding
from proxy.validation.python_validator import PythonValidator
from proxy.validation.python_validator import Finding as PyFinding
from proxy.validation.rules import Severity


SUPPORTED_LANGUAGES = {"python", "javascript"}
MAX_FINDINGS = 100


@dataclass(frozen=True, slots=True)
class Finding:
    """Unified finding dataclass."""

    rule_id: str
    category: str
    severity: str
    message: str
    line: int
    col: int
    snippet: str


@dataclass
class ValidationResult:
    """Result of code validation."""

    valid: bool
    language: str
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    truncated: bool = False


def _convert_py_finding(f: PyFinding) -> Finding:
    return Finding(
        rule_id=f.rule_id,
        category=f.category.value,
        severity=f.severity.value,
        message=f.message,
        line=f.line,
        col=f.col,
        snippet=f.snippet,
    )


def _convert_js_finding(f: JSFinding) -> Finding:
    return Finding(
        rule_id=f.rule_id,
        category=f.category.value,
        severity=f.severity.value,
        message=f.message,
        line=f.line,
        col=f.col,
        snippet=f.snippet,
    )


class CodeValidator:
    """Unified code validator — dispatches to language-specific validators."""

    def __init__(
        self,
        *,
        allowed_imports: set[str] | None = None,
        blocked_imports: set[str] | None = None,
        allowed_builtins: set[str] | None = None,
    ) -> None:
        self._python = PythonValidator(
            allowed_imports=allowed_imports,
            blocked_imports=blocked_imports,
            allowed_builtins=allowed_builtins,
        )
        self._javascript = JavaScriptValidator()

    def validate(self, code: str, language: str) -> ValidationResult:
        """Validate code in the given language.

        Returns ValidationResult with valid=False if any CRITICAL or HIGH
        finding exists, or if the language is unsupported (fail-closed).
        """
        lang = language.lower().strip()

        if lang not in SUPPORTED_LANGUAGES:
            return ValidationResult(
                valid=False,
                language=lang,
                findings=[Finding(
                    rule_id="unsupported-language",
                    category="code_injection",
                    severity="high",
                    message=f"Unsupported language: {lang}",
                    line=0,
                    col=0,
                    snippet="",
                )],
                summary={"high": 1},
            )

        try:
            if lang == "python":
                raw = self._python.validate(code)
                findings = [_convert_py_finding(f) for f in raw]
            else:
                raw = self._javascript.validate(code)
                findings = [_convert_js_finding(f) for f in raw]
        except Exception:
            # Fail-closed: validator crash → reject
            return ValidationResult(
                valid=False,
                language=lang,
                findings=[Finding(
                    rule_id="validator-internal-error",
                    category="code_injection",
                    severity="high",
                    message="Internal validator error (fail-closed)",
                    line=0,
                    col=0,
                    snippet="",
                )],
                summary={"high": 1},
            )

        # Cap findings
        truncated = len(findings) > MAX_FINDINGS
        if truncated:
            findings = findings[:MAX_FINDINGS]

        # Build summary
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        # valid = True only if no critical or high findings
        has_blocking = any(
            f.severity in (Severity.critical.value, Severity.high.value)
            for f in findings
        )

        return ValidationResult(
            valid=not has_blocking,
            language=lang,
            findings=findings,
            summary=summary,
            truncated=truncated,
        )
