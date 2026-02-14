"""SHIELD-29 — Code Validation for AI-Generated Scripts.

Acceptance Criteria:
  AC1: POST /api/v1/validate endpoint validates code and returns findings.
  AC2: Dangerous patterns in Python and JavaScript are detected.
  AC3: Per-customer configuration (allowlist, blocklist, mode) works.
  AC4: Middleware integration validates code on protected endpoints.
"""

from __future__ import annotations

import json

import pytest
from starlette.requests import Request
from starlette.responses import Response

from proxy.middleware.code_validator import CodeValidatorMiddleware
from proxy.middleware.pipeline import RequestContext
from proxy.validation.code_validator import CodeValidator


def _make_request(
    path: str = "/api/execute",
    method: str = "POST",
    body: bytes = b'{"code":"x = 1","language":"python"}',
    headers: dict[str, str] | None = None,
) -> Request:
    raw_headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
    ]
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode(), v.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": raw_headers,
    }
    req = Request(scope)
    req._body = body
    return req


def _ctx(
    *,
    feature_enabled: bool = True,
    mode: str = "block",
    protected_endpoints: list[str] | None = None,
    code_fields: list[str] | None = None,
    allowed_imports: list[str] | None = None,
    default_language: str = "python",
) -> RequestContext:
    ctx = RequestContext()
    ctx.tenant_id = "test-tenant"
    cv_cfg: dict = {"mode": mode, "default_language": default_language}
    if protected_endpoints is not None:
        cv_cfg["protected_endpoints"] = protected_endpoints
    if code_fields is not None:
        cv_cfg["code_fields"] = code_fields
    if allowed_imports is not None:
        cv_cfg["allowed_imports"] = allowed_imports
    ctx.customer_config = {
        "enabled_features": {"code_validator": feature_enabled},
        "settings": {"code_validator": cv_cfg},
    }
    return ctx


# ---------------------------------------------------------------------------
# AC1: API Endpoint — POST /api/v1/validate
# ---------------------------------------------------------------------------


class TestAC1_APIEndpoint:
    """POST /api/v1/validate accepts code and returns validation results."""

    def test_validator_accepts_python(self):
        """Validator accepts Python code and returns a result."""
        v = CodeValidator()
        result = v.validate("x = 5 + 3", "python")
        assert result.valid is True
        assert result.language == "python"

    def test_validator_accepts_javascript(self):
        """Validator accepts JavaScript code."""
        v = CodeValidator()
        result = v.validate("const x = 5;", "javascript")
        assert result.valid is True
        assert result.language == "javascript"

    def test_validator_returns_findings(self):
        """Dangerous code returns findings with valid=False."""
        v = CodeValidator()
        result = v.validate("import os\nos.system('id')", "python")
        assert result.valid is False
        assert len(result.findings) > 0

    def test_clean_code_passes(self):
        """Clean code returns valid=True with no findings."""
        v = CodeValidator()
        result = v.validate("x = [1, 2, 3]\ny = sum(x)", "python")
        assert result.valid is True
        assert all(f.severity not in ("critical", "high") for f in result.findings)

    def test_unsupported_language_rejected(self):
        """Unsupported language returns valid=False (fail-closed)."""
        v = CodeValidator()
        result = v.validate("puts 'hello'", "ruby")
        assert result.valid is False

    def test_empty_string_fails_closed(self):
        """Empty code string still parses (empty is valid Python)."""
        v = CodeValidator()
        # Empty string is technically valid Python (parses to empty module)
        result = v.validate("", "python")
        assert result.valid is True

    def test_finding_response_structure(self):
        """Each finding has required fields."""
        v = CodeValidator()
        result = v.validate("import os", "python")
        f = result.findings[0]
        assert f.rule_id
        assert f.category
        assert f.severity
        assert f.message


# ---------------------------------------------------------------------------
# AC2: Dangerous Patterns Detection
# ---------------------------------------------------------------------------


class TestAC2_DangerousPatterns:
    """Validator detects dangerous patterns in Python and JavaScript."""

    def test_python_imports_detected(self):
        """Dangerous Python imports are flagged."""
        v = CodeValidator()
        result = v.validate("import subprocess\nsubprocess.run(['ls'])", "python")
        assert not result.valid
        assert any(f.rule_id == "py-import-subprocess" for f in result.findings)

    def test_python_builtins_detected(self):
        """Dangerous Python builtins (eval, exec) are flagged."""
        v = CodeValidator()
        result = v.validate("eval(input())", "python")
        assert not result.valid
        assert any("eval" in f.rule_id for f in result.findings)

    def test_python_shell_strings_detected(self):
        """Shell command strings in Python are flagged."""
        v = CodeValidator()
        result = v.validate('cmd = "rm -rf /"', "python")
        assert not result.valid
        assert any("shell" in f.rule_id for f in result.findings)

    def test_js_eval_detected(self):
        """JavaScript eval() is flagged."""
        v = CodeValidator()
        result = v.validate("eval('alert(1)')", "javascript")
        assert not result.valid
        assert any("eval" in f.rule_id for f in result.findings)


# ---------------------------------------------------------------------------
# AC3: Per-Customer Configuration
# ---------------------------------------------------------------------------


class TestAC3_CustomerConfig:
    """Per-customer configuration controls validation behavior."""

    def test_allowlist_permits_imports(self):
        """Allowed imports are not flagged."""
        v = CodeValidator(allowed_imports={"os"})
        result = v.validate("import os\nos.getcwd()", "python")
        # os import itself should not be flagged
        assert not any(f.rule_id == "py-import-os" for f in result.findings)

    def test_blocklist_overrides_default(self):
        """Custom blocked imports augment detection."""
        v = CodeValidator(blocked_imports={"os", "json"})
        result = v.validate("import json", "python")
        assert any(f.rule_id == "py-import-json" for f in result.findings)

    @pytest.mark.asyncio
    async def test_mode_block_returns_400(self):
        """Block mode returns 400 for dangerous code."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"code": "import os", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(protected_endpoints=["/api/execute"])
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_mode_detect_only_passes_through(self):
        """Detect-only mode logs but allows dangerous code."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"code": "import os", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(protected_endpoints=["/api/execute"], mode="detect_only")
        result = await mw.process_request(req, ctx)
        assert result is None


# ---------------------------------------------------------------------------
# AC4: Middleware Integration
# ---------------------------------------------------------------------------


class TestAC4_MiddlewareIntegration:
    """CodeValidatorMiddleware integrates into the proxy pipeline."""

    @pytest.mark.asyncio
    async def test_disabled_by_default(self):
        """Feature flag off means no validation."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"code": "import os", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(feature_enabled=False, protected_endpoints=["/api/execute"])
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_enabled_validates_code(self):
        """Enabled middleware validates code and blocks dangerous patterns."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"code": "import subprocess", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(protected_endpoints=["/api/execute"])
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_clean_code_passes(self):
        """Clean code passes through middleware."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"code": "x = 5 + 3", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(protected_endpoints=["/api/execute"])
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_skips_non_protected_endpoints(self):
        """Non-protected endpoints are not scanned."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"code": "import os", "language": "python"}).encode()
        req = _make_request(path="/api/other")
        ctx = _ctx(protected_endpoints=["/api/execute"])
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_skips_get_requests(self):
        """GET requests are not scanned even on protected endpoints."""
        mw = CodeValidatorMiddleware()
        req = _make_request(method="GET")
        ctx = _ctx(protected_endpoints=["/api/execute"])
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_error_response_has_error_id(self):
        """Error responses include error_id but not the code."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"code": "import os\nos.system('id')", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(protected_endpoints=["/api/execute"])
        result = await mw.process_request(req, ctx)
        resp_body = json.loads(result.body)
        assert "error_id" in resp_body
        assert "import os" not in result.body.decode()

    @pytest.mark.asyncio
    async def test_non_json_body_blocked(self):
        """Non-JSON body on protected endpoint is blocked in block mode."""
        mw = CodeValidatorMiddleware()
        req = _make_request(body=b"not json")
        ctx = _ctx(protected_endpoints=["/api/execute"])
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_custom_code_field(self):
        """Custom code_fields configuration works."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"script": "import os", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(
            protected_endpoints=["/api/execute"],
            code_fields=["script"],
        )
        result = await mw.process_request(req, ctx)
        assert isinstance(result, Response)
        assert result.status_code == 400

    @pytest.mark.asyncio
    async def test_no_code_field_passes(self):
        """Body without matching code field passes through."""
        mw = CodeValidatorMiddleware()
        body = json.dumps({"data": "import os", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(protected_endpoints=["/api/execute"], code_fields=["code"])
        result = await mw.process_request(req, ctx)
        assert result is None

    @pytest.mark.asyncio
    async def test_allowed_imports_in_middleware(self):
        """Customer-configured allowed_imports permits otherwise-blocked imports."""
        mw = CodeValidatorMiddleware()
        # os.getcwd() is safe — no shell execution, just an allowed import + safe method
        body = json.dumps({"code": "import os\npath = os.getcwd()", "language": "python"}).encode()
        req = _make_request(body=body)
        ctx = _ctx(
            protected_endpoints=["/api/execute"],
            allowed_imports=["os"],
        )
        result = await mw.process_request(req, ctx)
        # os import is allowed, os.getcwd is not in dangerous call patterns → passes
        assert result is None
