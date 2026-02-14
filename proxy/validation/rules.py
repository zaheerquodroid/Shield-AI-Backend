"""Rule definitions for code validation.

Dangerous imports, builtins, shell patterns, and severities used by
both Python (AST) and JavaScript (regex) validators.
"""

from __future__ import annotations

import enum
import re


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class RuleCategory(str, enum.Enum):
    dangerous_import = "dangerous_import"
    dangerous_builtin = "dangerous_builtin"
    shell_execution = "shell_execution"
    code_injection = "code_injection"
    obfuscation = "obfuscation"
    deserialization = "deserialization"
    introspection = "introspection"
    network = "network"
    file_system = "file_system"


# Python dangerous imports: module -> severity
PYTHON_DANGEROUS_IMPORTS: dict[str, Severity] = {
    "os": Severity.critical,
    "subprocess": Severity.critical,
    "shutil": Severity.high,
    "ctypes": Severity.critical,
    "importlib": Severity.high,
    "pickle": Severity.critical,
    "marshal": Severity.critical,
    "pty": Severity.critical,
    "shelve": Severity.high,
    "code": Severity.high,
    "sys": Severity.medium,
    "multiprocessing": Severity.high,
    "signal": Severity.medium,
    "socket": Severity.high,
    "http": Severity.medium,
    "urllib": Severity.medium,
    "requests": Severity.medium,
    "webbrowser": Severity.medium,
    "ftplib": Severity.high,
    "smtplib": Severity.high,
    "telnetlib": Severity.high,
    "xmlrpc": Severity.high,
    "tempfile": Severity.medium,
    "glob": Severity.low,
    "pathlib": Severity.low,
    "io": Severity.low,
    "builtins": Severity.high,
    "gc": Severity.medium,
    "inspect": Severity.medium,
    "dis": Severity.medium,
    "types": Severity.medium,
    "compileall": Severity.high,
    "codeop": Severity.high,
    "dill": Severity.critical,
    "cloudpickle": Severity.critical,
    "joblib": Severity.high,
    "yaml": Severity.critical,
    "jsonpickle": Severity.critical,
    "runpy": Severity.critical,
    "codecs": Severity.medium,
    "zlib": Severity.medium,
    "xml": Severity.high,
}

# Python dangerous builtins: name -> severity
PYTHON_DANGEROUS_BUILTINS: dict[str, Severity] = {
    "exec": Severity.critical,
    "eval": Severity.critical,
    "compile": Severity.high,
    "__import__": Severity.critical,
    "globals": Severity.medium,
    "locals": Severity.medium,
    "getattr": Severity.medium,
    "setattr": Severity.medium,
    "delattr": Severity.medium,
    "breakpoint": Severity.medium,
    "open": Severity.medium,
    "vars": Severity.high,
    "dir": Severity.medium,
    "type": Severity.medium,
    "input": Severity.medium,
    "memoryview": Severity.medium,
}

# Python dangerous attributes (dunder access patterns)
PYTHON_DANGEROUS_ATTRS: set[str] = {
    "__import__",
    "__builtins__",
    "__globals__",
    "__code__",
    "__subclasses__",
    "__bases__",
    "__mro__",
    "__class__",
    "__dict__",
    "__loader__",
    "__spec__",
    "__qualname__",
    # Pickle/copy protocol hooks — can trigger arbitrary code on deserialize
    "__reduce__",
    "__reduce_ex__",
    # Descriptor/metaclass hooks — can execute code at class creation time
    "__init_subclass__",
    "__set_name__",
    "__getattribute__",
    # Traceback frame walking — sandbox escape via frame introspection
    "tb_frame",
    "f_globals",
    "f_builtins",
    "f_locals",
    "f_code",
    # Generator/coroutine/async-generator frame access
    "gi_frame",
    "gi_code",
    "cr_frame",
    "cr_code",
    "ag_frame",
    "ag_code",
}

# JavaScript dangerous patterns: (regex, severity, rule_id, description)
JS_DANGEROUS_PATTERNS: list[tuple[str, Severity, str, str]] = [
    (r"\beval\s*\(", Severity.critical, "js-eval", "eval() call"),
    (r"\bFunction\s*\(", Severity.critical, "js-function-constructor", "Function constructor"),
    (r"\bsetTimeout\s*\(\s*['\"]", Severity.high, "js-settimeout-string", "setTimeout with string argument"),
    (r"\bsetInterval\s*\(\s*['\"]", Severity.high, "js-setinterval-string", "setInterval with string argument"),
    (r"\brequire\s*\(\s*['\"]child_process['\"]", Severity.critical, "js-child-process", "child_process import"),
    (r"\brequire\s*\(\s*['\"]fs['\"]", Severity.high, "js-fs-require", "fs module import"),
    (r"\brequire\s*\(\s*['\"]net['\"]", Severity.high, "js-net-require", "net module import"),
    (r"\brequire\s*\(\s*['\"]dgram['\"]", Severity.high, "js-dgram-require", "dgram module import"),
    (r"\brequire\s*\(\s*['\"]cluster['\"]", Severity.medium, "js-cluster-require", "cluster module import"),
    (r"\brequire\s*\(\s*['\"]vm['\"]", Severity.critical, "js-vm-require", "vm module import"),
    (r"\bprocess\.env\b", Severity.high, "js-process-env", "process.env access"),
    (r"\bprocess\.exit\b", Severity.high, "js-process-exit", "process.exit call"),
    (r"\bexecSync\b", Severity.critical, "js-exec-sync", "execSync call"),
    (r"\bexecFile\b", Severity.critical, "js-exec-file", "execFile call"),
    (r"\bspawnSync\b", Severity.critical, "js-spawn-sync", "spawnSync call"),
    (r"\bspawn\s*\(", Severity.high, "js-spawn", "spawn call"),
    (r"__proto__", Severity.high, "js-proto", "__proto__ access"),
    (r"prototype\s*\[", Severity.high, "js-prototype-bracket", "prototype bracket access"),
    (r"constructor\s*\[", Severity.high, "js-constructor-bracket", "constructor bracket access"),
    (r"Object\.assign\s*\(\s*Object\.prototype", Severity.critical, "js-prototype-pollution", "prototype pollution via Object.assign"),
    (r"\bimport\s*\(\s*['\"]child_process['\"]", Severity.critical, "js-dynamic-import-cp", "dynamic import of child_process"),
    (r"\bglobalThis\b", Severity.medium, "js-globalthis", "globalThis access"),
    (r"\bBuffer\.from\b", Severity.low, "js-buffer-from", "Buffer.from usage"),
    (r"\bnew\s+WebSocket\b", Severity.medium, "js-websocket", "WebSocket creation"),
    (r"\bprocess\.binding\b", Severity.critical, "js-process-binding", "process.binding native access"),
    (r"\bprocess\.dlopen\b", Severity.critical, "js-process-dlopen", "process.dlopen native module"),
    (r"\bReflect\.apply\b", Severity.high, "js-reflect-apply", "Reflect.apply indirect call"),
    (r"\bReflect\.construct\b", Severity.high, "js-reflect-construct", "Reflect.construct indirect call"),
    (r"\bfrom\s+['\"]child_process['\"]", Severity.critical, "js-import-from-cp", "ES6 import from child_process"),
    (r"\bfrom\s+['\"]fs['\"]", Severity.high, "js-import-from-fs", "ES6 import from fs"),
    (r"\bfrom\s+['\"]vm['\"]", Severity.critical, "js-import-from-vm", "ES6 import from vm"),
    (r"\bfrom\s+['\"]net['\"]", Severity.high, "js-import-from-net", "ES6 import from net"),
    (r"""\[\s*['"]\s*eval\s*['"]\s*\]""", Severity.critical, "js-bracket-eval", "bracket notation eval access"),
    (r"""\[\s*['"]\s*constructor\s*['"]\s*\]""", Severity.high, "js-bracket-constructor", "bracket notation constructor access"),
    # Missing Node.js modules — worker_threads, inspector, v8, wasi
    (r"\brequire\s*\(\s*['\"]worker_threads['\"]", Severity.high, "js-worker-threads-require", "worker_threads module import"),
    (r"\brequire\s*\(\s*['\"]inspector['\"]", Severity.critical, "js-inspector-require", "inspector module import"),
    (r"\brequire\s*\(\s*['\"]v8['\"]", Severity.high, "js-v8-require", "v8 module import"),
    (r"\brequire\s*\(\s*['\"]wasi['\"]", Severity.high, "js-wasi-require", "wasi module import"),
    (r"\bfrom\s+['\"]worker_threads['\"]", Severity.high, "js-import-from-worker-threads", "ES6 import from worker_threads"),
    (r"\bfrom\s+['\"]inspector['\"]", Severity.critical, "js-import-from-inspector", "ES6 import from inspector"),
    (r"\bfrom\s+['\"]v8['\"]", Severity.high, "js-import-from-v8", "ES6 import from v8"),
    (r"\bfrom\s+['\"]wasi['\"]", Severity.high, "js-import-from-wasi", "ES6 import from wasi"),
    # import.meta access — information disclosure in ESM context
    (r"\bimport\.meta\b", Severity.medium, "js-import-meta", "import.meta access"),
    # String.fromCharCode obfuscation
    (r"\bString\.fromCharCode\b", Severity.high, "js-string-fromcharcode", "String.fromCharCode obfuscation"),
    # --- Round 3: Additional bypass patterns from PortSwigger/HackTricks research ---
    # node: protocol prefix bypass (require('node:child_process') etc.)
    (r"\brequire\s*\(\s*['\"]node:", Severity.critical, "js-node-prefix-require", "require with node: protocol prefix"),
    (r"\bfrom\s+['\"]node:", Severity.critical, "js-node-prefix-import", "ES6 import with node: protocol prefix"),
    (r"\bimport\s*\(\s*['\"]node:", Severity.critical, "js-node-prefix-dynamic-import", "dynamic import with node: protocol prefix"),
    # Constructor chain via dot access — sandbox escape
    (r"\.constructor\.constructor\s*\(", Severity.critical, "js-constructor-chain", "constructor chain sandbox escape"),
    (r"\.constructor\s*\(", Severity.high, "js-constructor-call", "constructor call"),
    # process.mainModule — sandbox escape
    (r"\bprocess\.mainModule\b", Severity.critical, "js-process-mainmodule", "process.mainModule sandbox escape"),
    (r"\bprocess\?\.\s*mainModule\b", Severity.critical, "js-process-mainmodule-optional", "process?.mainModule sandbox escape"),
    # Indirect eval: (0, eval)('code')
    (r"\(\s*0\s*,\s*eval\s*\)", Severity.critical, "js-indirect-eval", "indirect eval via (0, eval)"),
    # eval.call / eval.apply / eval.bind
    (r"\beval\.(call|apply|bind)\b", Severity.critical, "js-eval-indirect-call", "eval.call/apply/bind indirect call"),
    # window.eval / self.eval / frames.eval / top.eval / global.eval
    (r"\b(?:window|self|frames|top|global)\.eval\b", Severity.critical, "js-global-eval", "global object eval access"),
    # atob — base64 decode obfuscation
    (r"\batob\s*\(", Severity.high, "js-atob", "atob base64 decode obfuscation"),
    # Tagged template literals: eval`...`, Function`...`
    (r"\beval\s*`", Severity.critical, "js-eval-tagged-template", "eval tagged template literal"),
    (r"\bFunction\s*`", Severity.critical, "js-function-tagged-template", "Function tagged template literal"),
    # with statement — scope manipulation
    (r"\bwith\s*\(", Severity.high, "js-with-statement", "with statement scope manipulation"),
    # Object.defineProperty / Object.setPrototypeOf — prototype manipulation
    (r"\bObject\.defineProperty\b", Severity.high, "js-object-defineproperty", "Object.defineProperty prototype manipulation"),
    (r"\bObject\.setPrototypeOf\b", Severity.high, "js-object-setprototypeof", "Object.setPrototypeOf prototype manipulation"),
    (r"\bReflect\.setPrototypeOf\b", Severity.high, "js-reflect-setprototypeof", "Reflect.setPrototypeOf prototype manipulation"),
    (r"\bReflect\.defineProperty\b", Severity.high, "js-reflect-defineproperty", "Reflect.defineProperty prototype manipulation"),
    # document.write — DOM injection
    (r"\bdocument\.write\b", Severity.high, "js-document-write", "document.write DOM injection"),
    # Legacy dangerous accessors
    (r"__lookupGetter__", Severity.high, "js-lookup-getter", "__lookupGetter__ legacy accessor"),
    (r"__lookupSetter__", Severity.high, "js-lookup-setter", "__lookupSetter__ legacy accessor"),
    (r"__defineGetter__", Severity.high, "js-define-getter", "__defineGetter__ legacy accessor"),
    (r"__defineSetter__", Severity.high, "js-define-setter", "__defineSetter__ legacy accessor"),
    # Optional chaining on process — bypasses process\.env regex
    (r"\bprocess\?\.\s*env\b", Severity.high, "js-process-env-optional", "process?.env optional chaining"),
    # Dynamic import with variable (broader pattern)
    (r"\bimport\s*\(\s*[^'\"]", Severity.high, "js-dynamic-import-variable", "dynamic import with variable"),
]

# Pre-compiled JS patterns
JS_COMPILED_PATTERNS: list[tuple[re.Pattern, Severity, str, str]] = [
    (re.compile(pat), sev, rid, desc)
    for pat, sev, rid, desc in JS_DANGEROUS_PATTERNS
]

# Shell patterns (checked in string literals): (regex, severity, rule_id, description)
SHELL_PATTERNS: list[tuple[str, Severity, str, str]] = [
    (r"bash\s+-c\b", Severity.critical, "shell-bash-c", "bash -c execution"),
    (r"sh\s+-c\b", Severity.critical, "shell-sh-c", "sh -c execution"),
    (r"\bcurl\b.*?\|\s*(?:bash|sh)\b", Severity.critical, "shell-curl-pipe", "curl piped to shell"),
    (r"\bwget\b.*?\|\s*(?:bash|sh)\b", Severity.critical, "shell-wget-pipe", "wget piped to shell"),
    (r"\bnc\s+-[elp]", Severity.critical, "shell-netcat", "netcat listener/exec"),
    (r"\bncat\b", Severity.critical, "shell-ncat", "ncat usage"),
    (r"\brm\s+-rf\s+/", Severity.critical, "shell-rm-rf-root", "rm -rf /"),
    (r"/etc/passwd", Severity.high, "shell-etc-passwd", "/etc/passwd access"),
    (r"/etc/shadow", Severity.critical, "shell-etc-shadow", "/etc/shadow access"),
    (r"/dev/tcp/", Severity.critical, "shell-dev-tcp", "/dev/tcp reverse shell"),
    (r"\bmkfifo\b", Severity.high, "shell-mkfifo", "mkfifo (named pipe)"),
    (r"\bchmod\s+[0-7]*777\b", Severity.high, "shell-chmod-777", "chmod 777"),
    (r"\bcrontab\b", Severity.medium, "shell-crontab", "crontab manipulation"),
    (r"\bsocat\b", Severity.critical, "shell-socat", "socat usage"),
    (r"\bpython\d?\s+-c\b", Severity.high, "shell-python-c", "python -c execution"),
    (r"\bperl\s+-e\b", Severity.high, "shell-perl-e", "perl -e execution"),
    (r"\bchmod\s+[u+]*s\b", Severity.critical, "shell-chmod-setuid", "setuid via chmod"),
]

# Pre-compiled shell patterns
SHELL_COMPILED_PATTERNS: list[tuple[re.Pattern, Severity, str, str]] = [
    (re.compile(pat, re.IGNORECASE), sev, rid, desc)
    for pat, sev, rid, desc in SHELL_PATTERNS
]

# Dangerous dunder methods that enable code execution when assigned to builtins.
# Metaclass and exception-handler bypass: class Meta(type): __getitem__ = exec
PYTHON_DANGEROUS_DUNDER_METHODS: set[str] = {
    "__getitem__", "__setitem__", "__delitem__",
    "__getattr__", "__setattr__", "__delattr__",
    "__call__", "__enter__", "__exit__",
    "__add__", "__radd__", "__iadd__",
    "__sub__", "__rsub__", "__isub__",
    "__mul__", "__rmul__", "__imul__",
    "__eq__", "__ne__", "__lt__", "__gt__", "__le__", "__ge__",
    "__str__", "__repr__", "__format__",
    "__iter__", "__next__",
    "__len__", "__contains__",
    "__bool__", "__hash__",
    "__del__", "__init__",
    "__new__", "__init_subclass__", "__set_name__",
    "__get__", "__set__", "__delete__",
}

# Zero-width characters that can bypass regex pattern matching
ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\ufeff\u00ad\u2060\u180e")

# Keywords to check in decoded base64 content
BASE64_DANGER_KEYWORDS: list[str] = [
    "import os",
    "import subprocess",
    "exec(",
    "eval(",
    "__import__",
    "system(",
    "popen(",
    "/bin/sh",
    "/bin/bash",
    "pickle.loads",
    "marshal.loads",
]
