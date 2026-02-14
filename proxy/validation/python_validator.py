"""AST-based Python code validator.

Uses ast.parse + ast.walk for static analysis — never executes user code.
"""

from __future__ import annotations

import ast
import base64
import re
from dataclasses import dataclass

from proxy.validation.rules import (
    BASE64_DANGER_KEYWORDS,
    PYTHON_DANGEROUS_ATTRS,
    PYTHON_DANGEROUS_BUILTINS,
    PYTHON_DANGEROUS_DUNDER_METHODS,
    PYTHON_DANGEROUS_IMPORTS,
    SHELL_COMPILED_PATTERNS,
    ZERO_WIDTH_CHARS,
    RuleCategory,
    Severity,
)

MAX_CODE_SIZE = 100_000  # 100 KB
MAX_AST_NODES = 50_000

# Base64 pattern: at least 20 chars of valid base64 alphabet
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


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


def _snippet(node: ast.AST) -> str:
    """Extract a truncated source snippet from an AST node."""
    try:
        s = ast.dump(node)
    except Exception:
        s = ""
    return s[:80]


def _snippet_str(value: str) -> str:
    """Truncate a string value for use as a snippet."""
    return value[:80]


class PythonValidator:
    """Validate Python code using AST static analysis."""

    def __init__(
        self,
        *,
        blocked_imports: set[str] | None = None,
        allowed_imports: set[str] | None = None,
        blocked_builtins: set[str] | None = None,
        allowed_builtins: set[str] | None = None,
    ) -> None:
        self._blocked_imports = blocked_imports or set(PYTHON_DANGEROUS_IMPORTS.keys())
        self._allowed_imports = allowed_imports or set()
        self._blocked_builtins = blocked_builtins or set(PYTHON_DANGEROUS_BUILTINS.keys())
        self._allowed_builtins = allowed_builtins or set()

        # Effective sets (blocked minus allowed)
        self._effective_imports = self._blocked_imports - self._allowed_imports
        self._effective_builtins = self._blocked_builtins - self._allowed_builtins

    def validate(self, code: str) -> list[Finding]:
        """Validate Python code. Returns list of findings."""
        findings: list[Finding] = []

        # Size check
        if len(code) > MAX_CODE_SIZE:
            findings.append(Finding(
                rule_id="py-code-too-large",
                category=RuleCategory.code_injection,
                severity=Severity.high,
                message=f"Code exceeds maximum size ({len(code)} > {MAX_CODE_SIZE})",
                line=0,
                col=0,
                snippet="",
            ))
            return findings

        # Parse — fail-closed on syntax error
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            findings.append(Finding(
                rule_id="py-syntax-error",
                category=RuleCategory.code_injection,
                severity=Severity.high,
                message=f"Failed to parse Python code: {exc.msg}",
                line=exc.lineno or 0,
                col=exc.offset or 0,
                snippet="",
            ))
            return findings

        # Count nodes — reject overly complex AST
        nodes = list(ast.walk(tree))
        if len(nodes) > MAX_AST_NODES:
            findings.append(Finding(
                rule_id="py-ast-too-complex",
                category=RuleCategory.code_injection,
                severity=Severity.high,
                message=f"AST too complex ({len(nodes)} nodes > {MAX_AST_NODES})",
                line=0,
                col=0,
                snippet="",
            ))
            return findings

        for node in nodes:
            self._check_imports(node, findings)
            self._check_calls(node, findings)
            self._check_attributes(node, findings)
            self._check_subscripts(node, findings)
            self._check_decorators(node, findings)
            self._check_string_literals(node, findings)
            self._check_class_assignments(node, findings)

        return findings

    def _check_imports(self, node: ast.AST, findings: list[Finding]) -> None:
        """Check import and from-import statements."""
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                if mod in self._effective_imports:
                    sev = PYTHON_DANGEROUS_IMPORTS.get(mod, Severity.high)
                    findings.append(Finding(
                        rule_id=f"py-import-{mod}",
                        category=RuleCategory.dangerous_import,
                        severity=sev,
                        message=f"Dangerous import: {alias.name}",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                mod = node.module.split(".")[0]
                if mod in self._effective_imports:
                    sev = PYTHON_DANGEROUS_IMPORTS.get(mod, Severity.high)
                    findings.append(Finding(
                        rule_id=f"py-import-{mod}",
                        category=RuleCategory.dangerous_import,
                        severity=sev,
                        message=f"Dangerous import: from {node.module}",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))

    def _check_calls(self, node: ast.AST, findings: list[Finding]) -> None:
        """Check function calls for dangerous builtins and patterns."""
        if not isinstance(node, ast.Call):
            return

        func = node.func
        name = None

        # Direct call: eval(), exec(), etc.
        if isinstance(func, ast.Name):
            name = func.id
        # Attribute call: pickle.loads(), importlib.import_module(), etc.
        elif isinstance(func, ast.Attribute):
            attr_name = func.attr
            # Deserialization: pickle/marshal/dill/cloudpickle/shelve .loads/.load
            if attr_name in ("loads", "load") and isinstance(func.value, ast.Name):
                parent = func.value.id
                if parent in ("pickle", "marshal", "dill", "cloudpickle", "shelve"):
                    findings.append(Finding(
                        rule_id=f"py-deserialize-{parent}",
                        category=RuleCategory.deserialization,
                        severity=Severity.critical,
                        message=f"Dangerous deserialization: {parent}.{attr_name}()",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))
            # yaml.load / yaml.unsafe_load / yaml.full_load
            if attr_name in ("load", "unsafe_load", "full_load") and isinstance(func.value, ast.Name):
                if func.value.id == "yaml":
                    findings.append(Finding(
                        rule_id="py-deserialize-yaml",
                        category=RuleCategory.deserialization,
                        severity=Severity.critical,
                        message=f"Dangerous deserialization: yaml.{attr_name}()",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))
            # jsonpickle.decode / jsonpickle.loads
            if attr_name in ("decode", "loads") and isinstance(func.value, ast.Name):
                if func.value.id == "jsonpickle":
                    findings.append(Finding(
                        rule_id="py-deserialize-jsonpickle",
                        category=RuleCategory.deserialization,
                        severity=Severity.critical,
                        message=f"Dangerous deserialization: jsonpickle.{attr_name}()",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))
            # runpy.run_module / runpy.run_path
            if attr_name in ("run_module", "run_path") and isinstance(func.value, ast.Name):
                if func.value.id == "runpy":
                    findings.append(Finding(
                        rule_id="py-runpy-execution",
                        category=RuleCategory.code_injection,
                        severity=Severity.critical,
                        message=f"Code execution via runpy.{attr_name}()",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))
            if attr_name == "import_module" and isinstance(func.value, ast.Name):
                if func.value.id == "importlib":
                    findings.append(Finding(
                        rule_id="py-importlib-import-module",
                        category=RuleCategory.dangerous_import,
                        severity=Severity.high,
                        message="Dynamic import via importlib.import_module()",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))
            if attr_name == "system" and isinstance(func.value, ast.Name):
                if func.value.id == "os":
                    findings.append(Finding(
                        rule_id="py-os-system",
                        category=RuleCategory.shell_execution,
                        severity=Severity.critical,
                        message="Shell execution via os.system()",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))
            if attr_name == "popen" and isinstance(func.value, ast.Name):
                if func.value.id == "os":
                    findings.append(Finding(
                        rule_id="py-os-popen",
                        category=RuleCategory.shell_execution,
                        severity=Severity.critical,
                        message="Shell execution via os.popen()",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))

        # Check direct builtin calls
        if name and name in self._effective_builtins:
            sev = PYTHON_DANGEROUS_BUILTINS.get(name, Severity.high)
            findings.append(Finding(
                rule_id=f"py-builtin-{name}",
                category=RuleCategory.dangerous_builtin,
                severity=sev,
                message=f"Dangerous builtin call: {name}()",
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                snippet=_snippet(node),
            ))

        # getattr bypass detection: getattr(obj, "__import__")
        if name == "getattr" or (isinstance(func, ast.Name) and func.id == "getattr"):
            if len(node.args) >= 2:
                second_arg = node.args[1]
                if isinstance(second_arg, ast.Constant) and isinstance(second_arg.value, str):
                    if second_arg.value in PYTHON_DANGEROUS_ATTRS:
                        findings.append(Finding(
                            rule_id="py-getattr-bypass",
                            category=RuleCategory.introspection,
                            severity=Severity.critical,
                            message=f"getattr bypass accessing {second_arg.value}",
                            line=getattr(node, "lineno", 0),
                            col=getattr(node, "col_offset", 0),
                            snippet=_snippet(node),
                        ))

        # Code object construction: types.CodeType(), types.FunctionType()
        if isinstance(func, ast.Attribute):
            if func.attr in ("CodeType", "FunctionType") and isinstance(func.value, ast.Name):
                if func.value.id == "types":
                    findings.append(Finding(
                        rule_id=f"py-code-object-{func.attr.lower()}",
                        category=RuleCategory.code_injection,
                        severity=Severity.critical,
                        message=f"Code object construction: types.{func.attr}()",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet(node),
                    ))

    def _check_attributes(self, node: ast.AST, findings: list[Finding]) -> None:
        """Check attribute access for dangerous dunder patterns."""
        if not isinstance(node, ast.Attribute):
            return

        if node.attr in PYTHON_DANGEROUS_ATTRS:
            findings.append(Finding(
                rule_id=f"py-attr-{node.attr}",
                category=RuleCategory.introspection,
                severity=Severity.high,
                message=f"Dangerous attribute access: {node.attr}",
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                snippet=_snippet(node),
            ))

    def _check_subscripts(self, node: ast.AST, findings: list[Finding]) -> None:
        """Check subscript access with string keys for dangerous attrs.

        Catches patterns like globals()["__builtins__"] and obj["__import__"].
        """
        if not isinstance(node, ast.Subscript):
            return

        # Only check string-constant subscript keys
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            if key.value in PYTHON_DANGEROUS_ATTRS:
                findings.append(Finding(
                    rule_id=f"py-subscript-{key.value}",
                    category=RuleCategory.introspection,
                    severity=Severity.high,
                    message=f"Dangerous subscript access: ['{key.value}']",
                    line=getattr(node, "lineno", 0),
                    col=getattr(node, "col_offset", 0),
                    snippet=_snippet(node),
                ))

    def _check_decorators(self, node: ast.AST, findings: list[Finding]) -> None:
        """Check decorators for dangerous builtin usage like @exec."""
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return

        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id in self._effective_builtins:
                sev = PYTHON_DANGEROUS_BUILTINS.get(dec.id, Severity.high)
                findings.append(Finding(
                    rule_id=f"py-decorator-{dec.id}",
                    category=RuleCategory.code_injection,
                    severity=sev,
                    message=f"Dangerous builtin used as decorator: @{dec.id}",
                    line=getattr(dec, "lineno", 0),
                    col=getattr(dec, "col_offset", 0),
                    snippet=_snippet(dec),
                ))

    def _check_class_assignments(self, node: ast.AST, findings: list[Finding]) -> None:
        """Detect metaclass/class-level assignment of dangerous builtins.

        Catches patterns like:
          class Meta(type): __getitem__ = exec
          class RCE(Exception): __iadd__ = exec
        These assign a dangerous builtin to a dunder method, enabling code
        execution without an explicit call node in the AST.
        """
        if not isinstance(node, ast.ClassDef):
            return

        for stmt in node.body:
            if not isinstance(stmt, ast.Assign):
                continue
            # Check if the value is a reference to a dangerous builtin
            if not isinstance(stmt.value, ast.Name):
                continue
            if stmt.value.id not in self._effective_builtins:
                continue
            # Check if ANY target is a dunder method name
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id in PYTHON_DANGEROUS_DUNDER_METHODS:
                    findings.append(Finding(
                        rule_id="py-class-assign-builtin",
                        category=RuleCategory.code_injection,
                        severity=Severity.critical,
                        message=f"Dangerous builtin '{stmt.value.id}' assigned to "
                                f"dunder method '{target.id}' in class '{node.name}'",
                        line=getattr(stmt, "lineno", 0),
                        col=getattr(stmt, "col_offset", 0),
                        snippet=_snippet(stmt),
                    ))

    def _check_string_literals(self, node: ast.AST, findings: list[Finding]) -> None:
        """Check string constants for shell patterns and base64 obfuscation."""
        if not isinstance(node, ast.Constant):
            return
        if not isinstance(node.value, str):
            return

        value = node.value

        # Strip zero-width characters before pattern matching to prevent bypass
        stripped = "".join(c for c in value if c not in ZERO_WIDTH_CHARS)

        # Shell pattern detection (use stripped value for regex matching)
        for pattern, sev, rule_id, desc in SHELL_COMPILED_PATTERNS:
            if pattern.search(stripped):
                findings.append(Finding(
                    rule_id=rule_id,
                    category=RuleCategory.shell_execution,
                    severity=sev,
                    message=f"Shell pattern in string: {desc}",
                    line=getattr(node, "lineno", 0),
                    col=getattr(node, "col_offset", 0),
                    snippet=_snippet_str(value),
                ))

        # Base64 obfuscation detection
        for m in _BASE64_RE.finditer(value):
            candidate = m.group(0)
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for keyword in BASE64_DANGER_KEYWORDS:
                if keyword in decoded:
                    findings.append(Finding(
                        rule_id="py-base64-obfuscation",
                        category=RuleCategory.obfuscation,
                        severity=Severity.critical,
                        message=f"Base64-encoded dangerous content (decoded contains '{keyword}')",
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=_snippet_str(candidate),
                    ))
                    break  # One finding per base64 match
