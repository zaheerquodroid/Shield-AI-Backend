"""Unit tests for code validation — Python, JavaScript, and unified validators."""

from __future__ import annotations

import pytest

from proxy.validation.python_validator import PythonValidator, MAX_CODE_SIZE, MAX_AST_NODES
from proxy.validation.javascript_validator import JavaScriptValidator
from proxy.validation.code_validator import CodeValidator, SUPPORTED_LANGUAGES, MAX_FINDINGS


# ---------------------------------------------------------------------------
# Python Validator
# ---------------------------------------------------------------------------


class TestPythonValidator:
    """Unit tests for PythonValidator."""

    def test_clean_code_passes(self):
        validator = PythonValidator()
        findings = validator.validate("x = 5 + 3\nprint(x)")
        # print is not in blocked builtins
        assert not any(f.severity.value in ("critical", "high") for f in findings)

    def test_import_os_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import os")
        assert any(f.rule_id == "py-import-os" for f in findings)
        assert any(f.severity.value == "critical" for f in findings)

    def test_import_subprocess_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import subprocess")
        assert any(f.rule_id == "py-import-subprocess" for f in findings)

    def test_from_import_detected(self):
        validator = PythonValidator()
        findings = validator.validate("from os import path")
        assert any(f.rule_id == "py-import-os" for f in findings)

    def test_import_pickle_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import pickle")
        assert any(f.rule_id == "py-import-pickle" for f in findings)

    def test_import_ctypes_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import ctypes")
        assert any(f.rule_id == "py-import-ctypes" for f in findings)

    def test_import_socket_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import socket")
        assert any(f.rule_id == "py-import-socket" for f in findings)

    def test_eval_detected(self):
        validator = PythonValidator()
        findings = validator.validate("eval('1+1')")
        assert any(f.rule_id == "py-builtin-eval" for f in findings)

    def test_exec_detected(self):
        validator = PythonValidator()
        findings = validator.validate("exec('x=1')")
        assert any(f.rule_id == "py-builtin-exec" for f in findings)

    def test_compile_detected(self):
        validator = PythonValidator()
        findings = validator.validate("compile('x=1', '<string>', 'exec')")
        assert any(f.rule_id == "py-builtin-compile" for f in findings)

    def test_dunder_import_detected(self):
        validator = PythonValidator()
        findings = validator.validate("__import__('os')")
        assert any(f.rule_id == "py-builtin-__import__" for f in findings)

    def test_open_detected(self):
        validator = PythonValidator()
        findings = validator.validate("open('/etc/passwd')")
        assert any(f.rule_id == "py-builtin-open" for f in findings)

    def test_getattr_bypass_detected(self):
        validator = PythonValidator()
        findings = validator.validate("getattr(obj, '__import__')")
        assert any(f.rule_id == "py-getattr-bypass" for f in findings)

    def test_dangerous_attr_access_detected(self):
        validator = PythonValidator()
        findings = validator.validate("x.__globals__")
        assert any("__globals__" in f.rule_id for f in findings)

    def test_pickle_loads_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import pickle\npickle.loads(data)")
        assert any(f.rule_id == "py-deserialize-pickle" for f in findings)

    def test_shell_pattern_in_string(self):
        validator = PythonValidator()
        findings = validator.validate('cmd = "bash -c whoami"')
        assert any(f.rule_id == "shell-bash-c" for f in findings)

    def test_base64_obfuscation_detected(self):
        import base64
        encoded = base64.b64encode(b"import os\nos.system('id')").decode()
        code = f'data = "{encoded}"'
        validator = PythonValidator()
        findings = validator.validate(code)
        assert any(f.rule_id == "py-base64-obfuscation" for f in findings)

    def test_allowlist_overrides_blocked(self):
        """allowed_imports removes modules from blocked list."""
        validator = PythonValidator(allowed_imports={"os", "sys"})
        findings = validator.validate("import os\nimport sys")
        assert not any(f.rule_id in ("py-import-os", "py-import-sys") for f in findings)

    def test_syntax_error_fail_closed(self):
        validator = PythonValidator()
        findings = validator.validate("def foo(:")
        assert any(f.rule_id == "py-syntax-error" for f in findings)
        assert findings[0].severity.value == "high"

    def test_code_too_large(self):
        validator = PythonValidator()
        findings = validator.validate("x = 1\n" * (MAX_CODE_SIZE + 1))
        assert any(f.rule_id == "py-code-too-large" for f in findings)

    def test_line_number_accuracy(self):
        validator = PythonValidator()
        code = "x = 1\ny = 2\nimport os\nz = 3"
        findings = validator.validate(code)
        os_finding = next(f for f in findings if f.rule_id == "py-import-os")
        assert os_finding.line == 3

    def test_importlib_import_module_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import importlib\nimportlib.import_module('os')")
        assert any(f.rule_id == "py-importlib-import-module" for f in findings)

    def test_os_system_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import os\nos.system('id')")
        assert any(f.rule_id == "py-os-system" for f in findings)

    def test_marshal_loads_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import marshal\nmarshal.loads(data)")
        assert any(f.rule_id == "py-deserialize-marshal" for f in findings)

    def test_code_type_construction_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import types\ntypes.CodeType()")
        assert any(f.rule_id == "py-code-object-codetype" for f in findings)

    def test_function_type_construction_detected(self):
        validator = PythonValidator()
        findings = validator.validate("import types\ntypes.FunctionType(code_obj, {})")
        assert any(f.rule_id == "py-code-object-functiontype" for f in findings)


# ---------------------------------------------------------------------------
# JavaScript Validator
# ---------------------------------------------------------------------------


class TestJavaScriptValidator:
    """Unit tests for JavaScriptValidator."""

    def test_clean_code_passes(self):
        validator = JavaScriptValidator()
        findings = validator.validate("const x = 5 + 3;\nconsole.log(x);")
        assert not any(f.severity.value in ("critical", "high") for f in findings)

    def test_eval_detected(self):
        validator = JavaScriptValidator()
        findings = validator.validate("eval('alert(1)')")
        assert any(f.rule_id == "js-eval" for f in findings)

    def test_function_constructor_detected(self):
        validator = JavaScriptValidator()
        findings = validator.validate("new Function('return 1')()")
        assert any(f.rule_id == "js-function-constructor" for f in findings)

    def test_child_process_detected(self):
        validator = JavaScriptValidator()
        findings = validator.validate("const cp = require('child_process')")
        assert any(f.rule_id == "js-child-process" for f in findings)

    def test_fs_require_detected(self):
        validator = JavaScriptValidator()
        findings = validator.validate("const fs = require('fs')")
        assert any(f.rule_id == "js-fs-require" for f in findings)

    def test_process_env_detected(self):
        validator = JavaScriptValidator()
        findings = validator.validate("const secret = process.env.SECRET")
        assert any(f.rule_id == "js-process-env" for f in findings)

    def test_proto_detected(self):
        validator = JavaScriptValidator()
        findings = validator.validate("obj.__proto__.polluted = true")
        assert any(f.rule_id == "js-proto" for f in findings)

    def test_shell_pattern_in_js_string(self):
        validator = JavaScriptValidator()
        findings = validator.validate('const cmd = "bash -c whoami"')
        assert any(f.rule_id == "shell-bash-c" for f in findings)


# ---------------------------------------------------------------------------
# Unified CodeValidator
# ---------------------------------------------------------------------------


class TestCodeValidator:
    """Unit tests for the unified CodeValidator."""

    def test_python_dispatch(self):
        v = CodeValidator()
        result = v.validate("import os", "python")
        assert result.language == "python"
        assert not result.valid

    def test_javascript_dispatch(self):
        v = CodeValidator()
        result = v.validate("eval('x')", "javascript")
        assert result.language == "javascript"
        assert not result.valid

    def test_unsupported_language_rejected(self):
        v = CodeValidator()
        result = v.validate("print('hi')", "ruby")
        assert not result.valid
        assert result.findings[0].rule_id == "unsupported-language"

    def test_clean_python_valid(self):
        v = CodeValidator()
        result = v.validate("x = 5 + 3", "python")
        assert result.valid

    def test_clean_js_valid(self):
        v = CodeValidator()
        result = v.validate("const x = 5 + 3;", "javascript")
        assert result.valid

    def test_summary_counts(self):
        v = CodeValidator()
        result = v.validate("import os\nimport subprocess\nimport socket", "python")
        assert "critical" in result.summary
        assert result.summary["critical"] >= 2

    def test_findings_cap(self):
        """Findings are capped at MAX_FINDINGS."""
        # Generate code with many findings
        lines = [f"import os  # line {i}" for i in range(200)]
        code = "\n".join(lines)
        v = CodeValidator()
        result = v.validate(code, "python")
        assert len(result.findings) <= MAX_FINDINGS
        if len(result.findings) == MAX_FINDINGS:
            assert result.truncated
