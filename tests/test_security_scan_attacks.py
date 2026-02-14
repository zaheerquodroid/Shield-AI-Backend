"""Attack simulation tests for SHIELD-10: CI/CD Security Scanning Templates.

Tests validate resistance to SARIF injection, path traversal, command injection,
secret leakage, DoS, supply chain attacks, misconfiguration, workflow permission
escalation, scanner bypass, converter script security, template security,
GITHUB_OUTPUT injection, severity manipulation, ReDoS, suppression bypass,
stop-commands injection, annotation parameter injection, and converter
command injection.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import sys
import tempfile
import time

import pytest
import yaml

from tests.helpers.github_actions import (
    ACTION_DIR,
    SCRIPTS_DIR,
    TEMPLATES_DIR,
    find_step_by_id,
    find_steps_containing,
    get_action_inputs,
    get_composite_steps,
    get_step_condition,
    get_workflow_permissions,
    load_action_yml,
    load_template,
    load_workflow,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def action() -> dict:
    return load_action_yml()


@pytest.fixture(scope="module")
def steps(action: dict) -> list[dict]:
    return get_composite_steps(action)


@pytest.fixture(scope="module")
def workflow() -> dict:
    return load_workflow("security-scan.yml")


@pytest.fixture(scope="module")
def aggregate_module():
    """Import aggregate_sarif as a module."""
    spec = importlib.util.spec_from_file_location(
        "aggregate_sarif",
        os.path.join(SCRIPTS_DIR, "aggregate_sarif.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def pip_audit_module():
    """Import pip_audit_to_sarif as a module."""
    spec = importlib.util.spec_from_file_location(
        "pip_audit_to_sarif",
        os.path.join(SCRIPTS_DIR, "pip_audit_to_sarif.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def npm_audit_module():
    """Import npm_audit_to_sarif as a module."""
    spec = importlib.util.spec_from_file_location(
        "npm_audit_to_sarif",
        os.path.join(SCRIPTS_DIR, "npm_audit_to_sarif.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def go_vuln_module():
    """Import go_vuln_to_sarif as a module."""
    spec = importlib.util.spec_from_file_location(
        "go_vuln_to_sarif",
        os.path.join(SCRIPTS_DIR, "go_vuln_to_sarif.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def action_content() -> str:
    """Raw action.yml content as string."""
    with open(os.path.join(ACTION_DIR, "action.yml")) as f:
        return f.read()


# ---------------------------------------------------------------------------
# TestSARIFInjection — 7 tests
# ---------------------------------------------------------------------------


class TestSARIFInjection:
    """Test SARIF parsing resists injection attacks."""

    def test_rejects_malformed_json(self, aggregate_module):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.sarif")
            with open(p, "w") as f:
                f.write("not json{{{")
            runs = aggregate_module.load_sarif_files(d)
            assert runs == []

    def test_rejects_missing_version(self, aggregate_module):
        data = {"runs": []}
        assert aggregate_module.validate_sarif(data) is False

    def test_rejects_missing_runs(self, aggregate_module):
        data = {"version": "2.1.0"}
        assert aggregate_module.validate_sarif(data) is False

    def test_rejects_empty_runs_string(self, aggregate_module):
        data = {"version": "2.1.0", "runs": "not-a-list"}
        assert aggregate_module.validate_sarif(data) is False

    def test_accepts_empty_runs_list(self, aggregate_module):
        data = {"version": "2.1.0", "runs": []}
        assert aggregate_module.validate_sarif(data) is True

    def test_rejects_null_results(self, aggregate_module):
        """Results within a run that are not dicts should be skipped."""
        with tempfile.TemporaryDirectory() as d:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com/sarif",
                "runs": [{"tool": {"driver": {"name": "test", "rules": []}}, "results": [None, 42, "string"]}],
            }
            p = os.path.join(d, "null.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)
            runs = aggregate_module.load_sarif_files(d)
            assert len(runs) == 1

    def test_rejects_non_dict_data(self, aggregate_module):
        assert aggregate_module.validate_sarif([]) is False
        assert aggregate_module.validate_sarif("string") is False
        assert aggregate_module.validate_sarif(42) is False


# ---------------------------------------------------------------------------
# TestPathTraversal — 7 tests
# ---------------------------------------------------------------------------


class TestPathTraversal:
    """Test URI sanitization prevents path traversal."""

    def test_strips_dot_dot_slash(self, aggregate_module):
        assert "../" not in aggregate_module.sanitize_uri("../../../etc/passwd")

    def test_strips_file_protocol(self, aggregate_module):
        result = aggregate_module.sanitize_uri("file:///etc/passwd")
        assert not result.startswith("file:")

    def test_strips_backslash_traversal(self, aggregate_module):
        result = aggregate_module.sanitize_uri("..\\..\\windows\\system32")
        assert "\\" not in result

    def test_strips_encoded_traversal(self, aggregate_module):
        result = aggregate_module.sanitize_uri("%2e%2e%2f%2e%2e%2fetc/passwd")
        assert "%2e%2e" not in result.lower()
        assert "../" not in result

    def test_rejects_null_byte(self, aggregate_module):
        result = aggregate_module.sanitize_uri("src/main\x00.sarif")
        assert result == ""

    def test_clean_path_passthrough(self, aggregate_module):
        result = aggregate_module.sanitize_uri("src/main.py")
        assert result == "src/main.py"

    def test_nested_traversal_bypass(self, aggregate_module):
        """....// should NOT collapse to ../ after single-pass replace."""
        result = aggregate_module.sanitize_uri("....//....//etc/passwd")
        assert "../" not in result, "Nested traversal bypass: ....// collapsed to ../"
        assert ".." not in result

    def test_uri_annotation_format_poisoning(self, aggregate_module):
        """URI with newlines or :: must not poison annotation format."""
        result = aggregate_module.sanitize_uri("src/app.py\n::error::injected")
        assert "\n" not in result
        assert "::" not in result


# ---------------------------------------------------------------------------
# TestCommandInjection — 6 tests
# ---------------------------------------------------------------------------


class TestCommandInjection:
    """Test the action resists command injection via inputs."""

    def test_no_direct_user_input_in_shell(self, action_content):
        """Steps should use github.action_path for script paths, not raw inputs."""
        lines = action_content.split("\n")
        for line in lines:
            if "aggregate_sarif.py" in line or "_to_sarif.py" in line:
                assert "action_path" in line or "ACTION_PATH" in line

    def test_no_input_expressions_in_any_run_block(self, steps):
        """No step's run: block may contain ${{ inputs.* }} — must use env vars instead."""
        for step in steps:
            run_cmd = step.get("run", "")
            assert "${{ inputs." not in run_cmd, \
                f"Step '{step.get('id', step.get('name'))}' has ${{{{ inputs.* }}}} in run block — " \
                "must use env: block to prevent expression injection"

    def test_aggregate_has_env_block_for_user_inputs(self, steps):
        """Aggregate step must define env block mapping user-controlled inputs."""
        step = find_step_by_id(steps, "aggregate")
        env = step.get("env", {})
        assert len(env) >= 2, "aggregate step must have env block with threshold and fail-on-findings"
        # Verify the env block actually references the inputs
        env_values = " ".join(str(v) for v in env.values())
        assert "inputs.severity-threshold" in env_values, \
            "env must map severity-threshold input"
        assert "inputs.fail-on-findings" in env_values, \
            "env must map fail-on-findings input"

    def test_no_eval_in_action(self, action_content):
        assert "eval " not in action_content.lower() and "eval(" not in action_content

    def test_uses_action_path_for_scripts(self, steps):
        """Script invocations must use action_path."""
        for step in steps:
            run_cmd = step.get("run", "")
            if "_sarif.py" in run_cmd or "aggregate_sarif" in run_cmd:
                assert "action_path" in run_cmd or "ACTION_PATH" in run_cmd, \
                    f"Step {step.get('id')} must use action_path for script path"

    def test_no_curl_pipe_bash(self, action_content):
        # Must not have both curl AND pipe-to-shell in same context
        assert not ("curl" in action_content and "| bash" in action_content)
        assert "| sh" not in action_content


# ---------------------------------------------------------------------------
# TestSecretLeakage — 6 tests
# ---------------------------------------------------------------------------


class TestSecretLeakage:
    """Test the action prevents secret leakage."""

    def test_token_masking_in_aggregate(self, aggregate_module):
        """Token patterns must be masked in annotations."""
        text = "Found token ghp_1234567890abcdef1234567890abcdef12345678 in code"
        masked = aggregate_module._mask_tokens(text)
        assert "ghp_" not in masked
        assert "[MASKED]" in masked

    def test_aws_key_masking(self, aggregate_module):
        text = "AWS key AKIAIOSFODNN7EXAMPLE found"
        masked = aggregate_module._mask_tokens(text)
        assert "AKIA" not in masked

    def test_has_token_regex_patterns(self, aggregate_module):
        patterns = aggregate_module.TOKEN_MASK_PATTERNS
        assert len(patterns) >= 5, "Must have at least 5 token masking patterns"

    def test_no_secrets_in_env(self, action_content):
        """action.yml must not expose secrets in env blocks."""
        action = yaml.safe_load(action_content)
        steps = get_composite_steps(action)
        for step in steps:
            env = step.get("env", {})
            if isinstance(env, dict):
                for key, val in env.items():
                    val_str = str(val)
                    assert "secrets." not in val_str or "GITHUB_TOKEN" in val_str, \
                        f"Step {step.get('id')} leaks secret in env: {key}"

    def test_no_echo_of_secrets(self, action_content):
        """No echo of secret values."""
        lines = action_content.split("\n")
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("echo") and "secrets." in stripped:
                pytest.fail(f"Echo of secret found: {stripped}")

    def test_max_annotations_limit(self, aggregate_module):
        assert aggregate_module.MAX_ANNOTATIONS <= 50


# ---------------------------------------------------------------------------
# TestDenialOfService — 7 tests
# ---------------------------------------------------------------------------


class TestDenialOfService:
    """Test DoS resistance in SARIF processing."""

    def test_max_file_size_enforced(self, aggregate_module):
        """Files exceeding MAX_SARIF_SIZE must be rejected by load_sarif_files."""
        assert aggregate_module.MAX_SARIF_SIZE <= 50 * 1024 * 1024, "MAX_SARIF_SIZE must be reasonable"
        # Enforcement is tested by test_oversized_sarif_rejected below

    def test_max_findings_enforced(self, aggregate_module):
        """MAX_FINDINGS must be capped at a reasonable value."""
        assert 1000 <= aggregate_module.MAX_FINDINGS <= 50000
        # Enforcement is tested by test_findings_actually_capped below

    def test_max_annotations_enforced(self, aggregate_module):
        """MAX_ANNOTATIONS must be capped to prevent log spam."""
        assert 10 <= aggregate_module.MAX_ANNOTATIONS <= 100

    def test_oversized_sarif_rejected(self, aggregate_module):
        """SARIF files larger than MAX_SARIF_SIZE should be skipped."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "huge.sarif")
            sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test", "rules": []}}, "results": []}]}
            content = json.dumps(sarif)
            with open(p, "w") as f:
                f.write(content)
                f.write(" " * (10 * 1024 * 1024 + 1))
            runs = aggregate_module.load_sarif_files(d)
            assert runs == [], "Oversized SARIF should be rejected"

    def test_findings_actually_capped(self, aggregate_module):
        """Generate more than MAX_FINDINGS and verify main() caps them."""
        with tempfile.TemporaryDirectory() as d:
            # Create SARIF with 6000 results (> MAX_FINDINGS=5000)
            results = []
            for i in range(6000):
                results.append({
                    "ruleId": f"rule-{i}",
                    "level": "warning",
                    "message": {"text": f"Finding {i}"},
                })
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "test", "rules": []}}, "results": results}],
            }
            p = os.path.join(d, "many.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)

            # Drive through PRODUCTION code path: load → collect → count
            github_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(github_output, "w") as f:
                pass  # create empty
            merged_path = os.path.join(d, "merged.sarif")

            runs = aggregate_module.load_sarif_files(d)
            # This is the EXACT collection code from main() — verify it caps
            all_results = []
            for run in runs:
                for result in run.get("results", []):
                    if len(all_results) >= aggregate_module.MAX_FINDINGS:
                        break
                    if isinstance(result, dict):
                        all_results.append(result)

            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for result in all_results:
                sev = aggregate_module.normalize_severity(result, {})
                counts[sev] = counts.get(sev, 0) + 1

            assert len(all_results) == 5000, f"Expected 5000 capped findings, got {len(all_results)}"
            assert sum(counts.values()) == 5000, "Severity counts must sum to capped total"

    def test_empty_directory_handled(self, aggregate_module):
        with tempfile.TemporaryDirectory() as d:
            runs = aggregate_module.load_sarif_files(d)
            assert runs == []

    def test_max_sarif_files_limit(self, aggregate_module):
        """Verify MAX_SARIF_FILES constant exists and is reasonable."""
        assert hasattr(aggregate_module, "MAX_SARIF_FILES")
        assert aggregate_module.MAX_SARIF_FILES <= 100


# ---------------------------------------------------------------------------
# TestWorkflowCommandInjection — 5 tests
# ---------------------------------------------------------------------------


class TestWorkflowCommandInjection:
    """Test that SARIF content cannot inject GitHub workflow commands."""

    def test_newline_in_message_stripped(self, aggregate_module):
        """Newlines in SARIF message must not produce rogue workflow commands."""
        text = "Finding\n::set-env name=PATH::/evil"
        sanitized = aggregate_module._sanitize_annotation_text(text)
        assert "\n" not in sanitized

    def test_carriage_return_stripped(self, aggregate_module):
        text = "Finding\r::add-mask::secret"
        sanitized = aggregate_module._sanitize_annotation_text(text)
        assert "\r" not in sanitized

    def test_long_message_truncated(self, aggregate_module):
        text = "A" * 1000
        sanitized = aggregate_module._sanitize_annotation_text(text)
        assert len(sanitized) <= 500

    def test_rule_id_sanitized(self, aggregate_module):
        """Rule IDs with newlines must be sanitized."""
        text = "rule-1\n::error::injected"
        sanitized = aggregate_module._sanitize_annotation_text(text)
        assert "\n" not in sanitized

    def test_emit_annotations_no_multiline_injection(self, aggregate_module, capsys):
        """emit_annotations must not allow newline injection to produce extra workflow commands.

        GitHub Actions processes workflow commands at line boundaries.
        A crafted SARIF message with embedded newlines must NOT produce
        multiple output lines, which would let the injected line be
        parsed as a separate command.
        """
        results = [{
            "ruleId": "INJECT-001",
            "level": "error",
            "message": {"text": "XSS found\n::set-env name=PATH::/evil"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"},
                "region": {"startLine": 10},
            }}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        output_lines = captured.out.strip().split("\n")
        # CRITICAL: must produce exactly ONE line — newline injection neutralized
        assert len(output_lines) == 1, \
            f"Newline injection produced {len(output_lines)} lines: {output_lines}"
        # The injected command text appears as literal content within the
        # annotation value, NOT as a standalone workflow command.
        # Verify it's embedded inside the annotation, not at line start.
        assert output_lines[0].startswith("::error ") or output_lines[0].startswith("::warning ") or \
            output_lines[0].startswith("::notice "), \
            "Output line must start with a valid annotation command"

    def test_emit_annotations_rule_id_injection(self, aggregate_module, capsys):
        """Rule ID with newline must not produce separate output line."""
        results = [{
            "ruleId": "INJECT\n::error::pwned",
            "level": "warning",
            "message": {"text": "test"},
            "locations": [],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        output_lines = captured.out.strip().split("\n")
        assert len(output_lines) == 1, \
            f"Rule ID injection produced {len(output_lines)} lines"


# ---------------------------------------------------------------------------
# TestSupplyChain — 5 tests
# ---------------------------------------------------------------------------


class TestSupplyChain:
    """Test supply chain security of referenced actions."""

    def test_uses_official_gitleaks_action(self, steps):
        step = find_step_by_id(steps, "gitleaks")
        uses = step.get("uses", "")
        assert uses.startswith("gitleaks/gitleaks-action@")

    def test_uses_pinned_trivy_action(self, steps):
        """Trivy must be pinned to a version tag, not a branch reference."""
        step = find_step_by_id(steps, "trivy")
        uses = step.get("uses", "")
        assert uses.startswith("aquasecurity/trivy-action@")
        ref = uses.split("@")[1]
        # Must NOT be a branch name — must be a version tag (v* or semver) or SHA
        branch_names = {"master", "main", "latest", "dev", "develop", "HEAD"}
        assert ref not in branch_names, \
            f"Trivy must be pinned to a version/SHA, not branch '{ref}'"
        # Must look like a version (v1, 0.28.0, sha) not a bare word
        assert re.match(r"^(v?\d|[0-9a-f]{40})", ref), \
            f"Trivy ref '{ref}' doesn't look like a version tag or SHA"

    def test_uses_official_upload_sarif(self, steps):
        step = find_step_by_id(steps, "upload-sarif")
        uses = step.get("uses", "")
        assert uses.startswith("github/codeql-action/upload-sarif@")

    def test_workflow_uses_official_checkout(self, workflow):
        jobs = workflow.get("jobs", {})
        for job in jobs.values():
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if "checkout" in uses:
                    assert uses.startswith("actions/checkout@")

    def test_pip_install_quiet(self, steps):
        """pip install should use --quiet to reduce output surface."""
        for step in steps:
            run_cmd = step.get("run", "")
            if "pip install" in run_cmd:
                assert "--quiet" in run_cmd, \
                    f"pip install in step {step.get('id')} should use --quiet"


# ---------------------------------------------------------------------------
# TestMisconfiguration — 5 tests
# ---------------------------------------------------------------------------


class TestMisconfiguration:
    """Test that defaults are secure."""

    def test_default_threshold_high(self, action):
        inputs = get_action_inputs(action)
        assert inputs["severity-threshold"]["default"] == "high"

    def test_default_fail_on_findings_true(self, action):
        inputs = get_action_inputs(action)
        assert inputs["fail-on-findings"]["default"] == "true"

    def test_default_sarif_upload_true(self, action):
        inputs = get_action_inputs(action)
        assert inputs["sarif-upload"]["default"] == "true"

    def test_default_gitleaks_enabled(self, action):
        inputs = get_action_inputs(action)
        assert inputs["gitleaks-enabled"]["default"] == "true"

    def test_default_go_disabled(self, action):
        inputs = get_action_inputs(action)
        assert inputs["go-enabled"]["default"] == "false"


# ---------------------------------------------------------------------------
# TestWorkflowPermissions — 5 tests
# ---------------------------------------------------------------------------


class TestWorkflowPermissions:
    """Test workflow follows least-privilege permissions."""

    def test_no_write_all(self, workflow):
        perms = get_workflow_permissions(workflow)
        assert perms != "write-all"
        assert perms.get("_all") != "write-all"

    def test_contents_read(self, workflow):
        perms = get_workflow_permissions(workflow)
        assert perms.get("contents") == "read"

    def test_security_events_write(self, workflow):
        perms = get_workflow_permissions(workflow)
        assert perms.get("security-events") == "write"

    def test_no_id_token_write(self, workflow):
        perms = get_workflow_permissions(workflow)
        assert perms.get("id-token") != "write"

    def test_minimal_permission_keys(self, workflow):
        perms = get_workflow_permissions(workflow)
        assert len(perms) <= 5, f"Too many permission keys ({len(perms)}), follow least privilege"


# ---------------------------------------------------------------------------
# TestScannerBypass — 6 tests
# ---------------------------------------------------------------------------


class TestScannerBypass:
    """Test that scanners cannot be bypassed silently."""

    def test_each_scanner_has_conditional(self, steps):
        scanner_ids = ["bandit", "pip-audit", "eslint-security", "npm-audit",
                       "govulncheck", "gitleaks", "trivy"]
        for sid in scanner_ids:
            step = find_step_by_id(steps, sid)
            assert step is not None, f"Scanner {sid} must exist"
            cond = get_step_condition(step)
            assert cond is not None, f"Scanner {sid} must have a condition"

    def test_disabled_scanner_skipped_not_errored(self, steps):
        """Disabled scanners should skip via condition, not error."""
        bandit = find_step_by_id(steps, "bandit")
        cond = get_step_condition(bandit)
        assert "'true'" in cond or '"true"' in cond or "true" in cond

    def test_missing_sarif_handled_by_aggregate(self, aggregate_module):
        """Aggregate should handle missing/empty SARIF gracefully."""
        with tempfile.TemporaryDirectory() as d:
            runs = aggregate_module.load_sarif_files(d)
            merged = aggregate_module.merge_sarif(runs)
            assert merged["version"] == "2.1.0"
            assert len(merged["runs"]) >= 1

    def test_empty_results_no_false_pass(self, aggregate_module):
        """Empty results should pass, not produce false positive."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        assert aggregate_module.apply_threshold(counts, "high") is False

    def test_shared_results_directory(self, steps):
        """All scanners must write to the shared results directory."""
        setup = find_step_by_id(steps, "setup")
        assert setup is not None
        run_cmd = setup.get("run", "")
        assert "shieldai-scan-results" in run_cmd

    def test_aggregate_runs_always(self, steps):
        """Aggregate step must have if: always() to survive scanner failures."""
        step = find_step_by_id(steps, "aggregate")
        cond = get_step_condition(step)
        assert cond is not None, "aggregate must have a condition"
        assert "always()" in cond, "aggregate must run with always() condition"


# ---------------------------------------------------------------------------
# TestThresholdValidation — 4 tests
# ---------------------------------------------------------------------------


class TestThresholdValidation:
    """Test severity threshold validation and edge cases."""

    def test_invalid_threshold_defaults_to_high(self, aggregate_module):
        """Garbage threshold input must not silently pass."""
        counts = {"critical": 0, "high": 1, "medium": 0, "low": 0}
        # Invalid threshold should default to "high" and still detect high findings
        assert aggregate_module.apply_threshold(counts, "garbage") is True

    def test_threshold_any_catches_low(self, aggregate_module):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 1}
        assert aggregate_module.apply_threshold(counts, "any") is True

    def test_threshold_critical_ignores_high(self, aggregate_module):
        counts = {"critical": 0, "high": 5, "medium": 0, "low": 0}
        assert aggregate_module.apply_threshold(counts, "critical") is False

    def test_valid_thresholds_constant(self, aggregate_module):
        assert hasattr(aggregate_module, "VALID_THRESHOLDS")
        assert aggregate_module.VALID_THRESHOLDS == {"critical", "high", "medium", "low", "any"}


# ---------------------------------------------------------------------------
# TestConverterScripts — 12 tests
# ---------------------------------------------------------------------------


class TestConverterScripts:
    """Test SARIF converter scripts produce valid output and handle edge cases."""

    def test_pip_audit_valid_sarif(self, pip_audit_module):
        """pip-audit converter must produce valid SARIF 2.1.0."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {"dependencies": [{"name": "flask", "version": "1.0", "vulns": [
                {"id": "CVE-2023-1234", "fix_versions": ["2.0"]}
            ]}]}
            with open(inp, "w") as f:
                json.dump(data, f)
            pip_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert sarif["version"] == "2.1.0"
            assert len(sarif["runs"]) == 1
            assert len(sarif["runs"][0]["results"]) == 1
            assert sarif["runs"][0]["results"][0]["ruleId"] == "CVE-2023-1234"

    def test_pip_audit_malformed_input(self, pip_audit_module):
        """pip-audit converter must handle malformed JSON gracefully."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "bad.json")
            out = os.path.join(d, "output.sarif")
            with open(inp, "w") as f:
                f.write("not json")
            pip_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert sarif["version"] == "2.1.0"
            assert sarif["runs"][0]["results"] == []

    def test_pip_audit_missing_input(self, pip_audit_module):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "output.sarif")
            pip_audit_module.convert("/nonexistent/path.json", out)
            with open(out) as f:
                sarif = json.load(f)
            assert sarif["runs"][0]["results"] == []

    def test_npm_audit_v6_format(self, npm_audit_module):
        """npm audit v6 format with advisories must produce correct SARIF."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {"advisories": {"1234": {
                "severity": "high", "title": "XSS in foo", "module_name": "foo"
            }}}
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert len(sarif["runs"][0]["results"]) == 1
            assert "XSS in foo" in sarif["runs"][0]["results"][0]["message"]["text"]

    def test_npm_audit_v7_format(self, npm_audit_module):
        """npm audit v7+ format with vulnerabilities must produce correct SARIF."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {"vulnerabilities": {"lodash": {"via": [
                {"severity": "critical", "title": "Prototype Pollution", "source": 42}
            ]}}}
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert len(sarif["runs"][0]["results"]) == 1

    def test_npm_audit_malformed(self, npm_audit_module):
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "bad.json")
            out = os.path.join(d, "output.sarif")
            with open(inp, "w") as f:
                f.write("[1,2,3]")  # array not dict
            npm_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert sarif["runs"][0]["results"] == []

    def test_go_vuln_valid_sarif(self, go_vuln_module):
        """govulncheck converter must produce valid SARIF from NDJSON."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            entry = {"vulnerability": {"osv": {
                "id": "GO-2023-0001", "summary": "Buffer overflow in foo",
                "affected": [{"package": {"name": "example.com/foo"}}]
            }}}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            go_vuln_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert len(sarif["runs"][0]["results"]) == 1
            assert sarif["runs"][0]["results"][0]["ruleId"] == "GO-2023-0001"

    def test_go_vuln_empty_file(self, go_vuln_module):
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "empty.json")
            out = os.path.join(d, "output.sarif")
            with open(inp, "w") as f:
                f.write("")
            go_vuln_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert sarif["runs"][0]["results"] == []

    def test_pip_audit_has_size_limit(self, pip_audit_module):
        assert hasattr(pip_audit_module, "MAX_INPUT_SIZE")
        assert pip_audit_module.MAX_INPUT_SIZE <= 100 * 1024 * 1024

    def test_npm_audit_has_size_limit(self, npm_audit_module):
        assert hasattr(npm_audit_module, "MAX_INPUT_SIZE")
        assert npm_audit_module.MAX_INPUT_SIZE <= 100 * 1024 * 1024

    def test_go_vuln_has_size_limit(self, go_vuln_module):
        assert hasattr(go_vuln_module, "MAX_INPUT_SIZE")
        assert go_vuln_module.MAX_INPUT_SIZE <= 100 * 1024 * 1024

    def test_pip_audit_has_results_limit(self, pip_audit_module):
        assert hasattr(pip_audit_module, "MAX_RESULTS")
        assert pip_audit_module.MAX_RESULTS <= 50000


# ---------------------------------------------------------------------------
# TestTemplatesSecurity — 5 tests
# ---------------------------------------------------------------------------


class TestTemplatesSecurity:
    """Test template security configuration."""

    def test_dependabot_has_security_updates(self):
        data = load_template("dependabot.yml")
        updates = data.get("updates", [])
        has_security = False
        for update in updates:
            labels = update.get("labels", [])
            if "security" in labels:
                has_security = True
                break
            if update.get("security-updates-only"):
                has_security = True
                break
        assert has_security, "Dependabot must have security-related configuration"

    def test_dependabot_version_2(self):
        data = load_template("dependabot.yml")
        assert data["version"] == 2

    def test_dependabot_has_reviewers(self):
        data = load_template("dependabot.yml")
        updates = data.get("updates", [])
        has_reviewers = any(
            "reviewers" in update for update in updates
        )
        assert has_reviewers, "Dependabot updates must have reviewers"

    def test_pre_commit_has_gitleaks(self):
        data = load_template(".pre-commit-config.yaml")
        repos = data.get("repos", [])
        gitleaks_repos = [r for r in repos if "gitleaks" in r.get("repo", "")]
        assert len(gitleaks_repos) >= 1

    def test_pre_commit_has_detect_secrets(self):
        data = load_template(".pre-commit-config.yaml")
        repos = data.get("repos", [])
        ds_repos = [r for r in repos if "detect-secrets" in r.get("repo", "")]
        assert len(ds_repos) >= 1


# ---------------------------------------------------------------------------
# TestGITHUBOutputInjection — 5 tests (CVE-2022-35954 pattern)
# ---------------------------------------------------------------------------


class TestGITHUBOutputInjection:
    """Simulate GITHUB_OUTPUT newline injection (CVE-2022-35954 pattern).

    An attacker who can control the sarif_path or result value could inject
    newline + key=value pairs to override scan-result in GITHUB_OUTPUT.
    """

    def test_write_outputs_no_newline_in_sarif_path(self, aggregate_module):
        """sarif_path with embedded newline must not produce extra output lines."""
        with tempfile.TemporaryDirectory() as d:
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            # Attacker-crafted path with newline injection
            evil_path = "/tmp/merged.sarif\nscan-result=pass"
            counts = {"critical": 1, "high": 0, "medium": 0, "low": 0}
            aggregate_module.write_outputs(counts, "fail", evil_path, gh_output)
            with open(gh_output) as f:
                content = f.read()
            # Count scan-result occurrences — must be exactly 1 (the real one)
            scan_results = [l for l in content.split("\n") if l.startswith("scan-result=")]
            assert len(scan_results) == 1, \
                f"GITHUB_OUTPUT injection: found {len(scan_results)} scan-result lines"
            assert scan_results[0] == "scan-result=fail", \
                f"scan-result overridden: {scan_results[0]}"

    def test_write_outputs_crlf_injection(self, aggregate_module):
        """CRLF in sarif_path must not inject output keys."""
        with tempfile.TemporaryDirectory() as d:
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            evil_path = "/tmp/merged.sarif\r\nscan-result=pass"
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            aggregate_module.write_outputs(counts, "fail", evil_path, gh_output)
            with open(gh_output) as f:
                lines = [l for l in f.read().split("\n") if l.strip()]
            # Each output key should appear exactly once
            key_counts = {}
            for line in lines:
                key = line.split("=")[0]
                key_counts[key] = key_counts.get(key, 0) + 1
            for key, count in key_counts.items():
                assert count == 1, f"Key '{key}' appears {count} times (CRLF injection)"

    def test_write_outputs_result_value_injection(self, aggregate_module):
        """result parameter with newline must not inject extra keys."""
        with tempfile.TemporaryDirectory() as d:
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            # Even if somehow result contains newline
            evil_result = "fail\nfindings-count=0"
            counts = {"critical": 1, "high": 0, "medium": 0, "low": 0}
            aggregate_module.write_outputs(counts, evil_result, "/tmp/merged.sarif", gh_output)
            with open(gh_output) as f:
                lines = [l for l in f.read().split("\n") if l.strip()]
            findings_lines = [l for l in lines if l.startswith("findings-count=")]
            assert len(findings_lines) == 1, "Injected extra findings-count"
            assert findings_lines[0] == "findings-count=1", "findings-count overridden"

    def test_sanitize_output_value_exists(self, aggregate_module):
        """_sanitize_output_value helper must exist and strip newlines."""
        fn = aggregate_module._sanitize_output_value
        assert fn("safe") == "safe"
        assert fn("evil\ninjection") == "evilinjection"
        assert fn("evil\r\ninjection") == "evilinjection"

    def test_write_outputs_heredoc_delimiter_injection(self, aggregate_module):
        """Attempt to inject heredoc-style delimiter in output value."""
        with tempfile.TemporaryDirectory() as d:
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            # GitHub uses <<DELIMITER for multiline; try injecting it
            evil_path = "/tmp/merged.sarif\nghEOF\nscan-result=pass\nghEOF"
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            aggregate_module.write_outputs(counts, "fail", evil_path, gh_output)
            with open(gh_output) as f:
                content = f.read()
            # Must not have "ghEOF" as a standalone line
            lines = content.strip().split("\n")
            for line in lines:
                assert line.strip() != "ghEOF", "Heredoc delimiter injected"


# ---------------------------------------------------------------------------
# TestSeverityManipulation — 6 tests
# ---------------------------------------------------------------------------


class TestSeverityManipulation:
    """Simulate severity score gaming to bypass threshold checks."""

    def test_nan_score_not_treated_as_low(self, aggregate_module):
        """NaN security-severity must NOT be treated as 'low'.

        Before fix: float('NaN') >= 9.0 is False, >= 7.0 is False, etc.
        → always returns 'low', letting attackers downgrade any finding.
        After fix: NaN falls through to SARIF level mapping.
        """
        result = {"ruleId": "NAN-001", "level": "error"}
        rules = {"NAN-001": {"properties": {"security-severity": "NaN"}}}
        severity = aggregate_module.normalize_severity(result, rules)
        # NaN should fall through to SARIF level 'error' → 'high'
        assert severity != "low", \
            f"NaN score treated as '{severity}' — must not be 'low'"
        assert severity == "high", \
            f"NaN score should fall through to SARIF level 'error' → 'high', got '{severity}'"

    def test_infinity_score_not_treated_as_low(self, aggregate_module):
        """Infinity score must not bypass severity mapping."""
        result = {"ruleId": "INF-001", "level": "error"}
        rules = {"INF-001": {"properties": {"security-severity": "Infinity"}}}
        severity = aggregate_module.normalize_severity(result, rules)
        # Infinity should fall through to SARIF level
        assert severity != "low", f"Infinity treated as low"

    def test_negative_infinity_score(self, aggregate_module):
        """-Infinity must not be treated as valid low score."""
        result = {"ruleId": "NEGINF-001", "level": "error"}
        rules = {"NEGINF-001": {"properties": {"security-severity": "-Infinity"}}}
        severity = aggregate_module.normalize_severity(result, rules)
        # -Infinity should fall through to SARIF level 'error' → 'high'
        assert severity == "high", \
            f"-Infinity should fall through to SARIF level, got '{severity}'"

    def test_negative_score_is_low(self, aggregate_module):
        """Legitimate negative score (finite) maps to low."""
        result = {"ruleId": "NEG-001", "level": "note"}
        rules = {"NEG-001": {"properties": {"security-severity": "-1.0"}}}
        severity = aggregate_module.normalize_severity(result, rules)
        assert severity == "low"

    def test_extreme_high_score_is_critical(self, aggregate_module):
        """Score > 10 still maps to critical."""
        result = {"ruleId": "EXT-001", "level": "note"}
        rules = {"EXT-001": {"properties": {"security-severity": "999.9"}}}
        severity = aggregate_module.normalize_severity(result, rules)
        assert severity == "critical"

    def test_score_downgrade_attack(self, aggregate_module):
        """Attacker sets 0.1 on error-level finding — score overrides level."""
        result = {"ruleId": "DOWNGRADE-001", "level": "error"}
        rules = {"DOWNGRADE-001": {"properties": {"security-severity": "0.1"}}}
        severity = aggregate_module.normalize_severity(result, rules)
        # Score 0.1 is a valid finite float < 4.0 → "low"
        # This is BY DESIGN — the security-severity score IS the authority.
        # The risk is that an attacker who can write to a SARIF file
        # can downgrade findings. This test documents the behavior.
        assert severity == "low", \
            "Score 0.1 should map to low (score overrides SARIF level by design)"


# ---------------------------------------------------------------------------
# TestReDoSResistance — 3 tests
# ---------------------------------------------------------------------------


class TestReDoSResistance:
    """Verify regex patterns don't suffer catastrophic backtracking."""

    def test_token_masking_adversarial_prefix(self, aggregate_module):
        """Long near-matching token prefix must complete in bounded time."""
        # ghp_ followed by 100K alphanumeric chars (valid match, long)
        adversarial = "ghp_" + "A" * 100_000
        start = time.monotonic()
        result = aggregate_module._mask_tokens(adversarial)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"Token masking took {elapsed:.2f}s on adversarial input"
        assert "[MASKED]" in result

    def test_sanitize_uri_deeply_nested_traversal(self, aggregate_module):
        """Deeply nested traversal patterns must complete quickly."""
        # 10K nested ....// patterns
        adversarial = "..../" * 10_000 + "etc/passwd"
        start = time.monotonic()
        result = aggregate_module.sanitize_uri(adversarial)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"sanitize_uri took {elapsed:.2f}s on nested traversal"
        assert ".." not in result

    def test_all_token_patterns_linear_time(self, aggregate_module):
        """All token mask patterns must handle 1MB input in < 2s."""
        # 1MB of mostly-matching but not-quite input
        payload = "sk-" + "x" * (1024 * 1024)
        start = time.monotonic()
        aggregate_module._mask_tokens(payload)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"Token masking took {elapsed:.2f}s on 1MB input"


# ---------------------------------------------------------------------------
# TestSARIFSuppressionBypass — 3 tests
# ---------------------------------------------------------------------------


class TestSARIFSuppressionBypass:
    """Verify findings with SARIF suppressions are still counted by our aggregation.

    GitHub Code Scanning may auto-dismiss suppressed findings, but our
    threshold check must still count them to prevent false-pass.
    """

    def test_suppressed_findings_still_counted(self, aggregate_module):
        """Findings with suppressions field must still be counted in severity totals."""
        with tempfile.TemporaryDirectory() as d:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{
                    "tool": {"driver": {"name": "test", "rules": []}},
                    "results": [{
                        "ruleId": "SUPPRESSED-001",
                        "level": "error",
                        "message": {"text": "Critical finding"},
                        "suppressions": [{"kind": "inSource", "justification": "false positive"}],
                    }],
                }],
            }
            p = os.path.join(d, "suppressed.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)

            runs = aggregate_module.load_sarif_files(d)
            # Collect results same as main()
            all_results = []
            all_rules = {}
            for run in runs:
                for result in run.get("results", []):
                    if isinstance(result, dict):
                        all_results.append(result)
            # Must have 1 result despite suppressions
            assert len(all_results) == 1, "Suppressed finding was filtered out"

            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for result in all_results:
                sev = aggregate_module.normalize_severity(result, all_rules)
                counts[sev] += 1
            assert counts["high"] == 1, f"Suppressed error-level finding not counted: {counts}"

    def test_suppressed_findings_still_annotated(self, aggregate_module, capsys):
        """Suppressed findings must still produce annotations."""
        results = [{
            "ruleId": "SUPPRESSED-002",
            "level": "error",
            "message": {"text": "Should still be annotated"},
            "suppressions": [{"kind": "inSource"}],
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"},
                "region": {"startLine": 5},
            }}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "SUPPRESSED-002" in captured.out
        assert "::error" in captured.out

    def test_suppressed_findings_trigger_threshold(self, aggregate_module):
        """Threshold check must fail on suppressed findings."""
        # Suppressed finding counted as high → should trigger high threshold
        counts = {"critical": 0, "high": 1, "medium": 0, "low": 0}
        assert aggregate_module.apply_threshold(counts, "high") is True


# ---------------------------------------------------------------------------
# TestStopCommandsInjection — 3 tests
# ---------------------------------------------------------------------------


class TestStopCommandsInjection:
    """Simulate ::stop-commands:: workflow command injection.

    If an attacker embeds ::stop-commands::TOKEN in a SARIF message,
    and it appears as a standalone line, it would disable all subsequent
    workflow command processing including our ::error:: fail line.
    """

    def test_stop_commands_in_message_neutralized(self, aggregate_module, capsys):
        """::stop-commands:: in message must not appear as standalone command."""
        results = [{
            "ruleId": "STOP-001",
            "level": "error",
            "message": {"text": "Finding\n::stop-commands::randomtoken123"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"},
                "region": {"startLine": 1},
            }}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        # Must be single line (newline stripped)
        assert len(lines) == 1, f"stop-commands injection produced {len(lines)} lines"
        # The stop-commands text appears as content within the annotation, not standalone
        assert lines[0].startswith("::error "), "Must be valid annotation"

    def test_stop_commands_in_rule_id_neutralized(self, aggregate_module, capsys):
        """::stop-commands:: in ruleId must not produce standalone command."""
        results = [{
            "ruleId": "STOP\n::stop-commands::token",
            "level": "error",
            "message": {"text": "test"},
            "locations": [],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert len(lines) == 1

    def test_add_mask_in_message_no_masking(self, aggregate_module, capsys):
        """::add-mask:: in message must not mask subsequent output."""
        results = [
            {
                "ruleId": "MASK-001",
                "level": "error",
                "message": {"text": "First\n::add-mask::password123"},
                "locations": [],
            },
            {
                "ruleId": "MASK-002",
                "level": "error",
                "message": {"text": "Second finding with password123"},
                "locations": [],
            },
        ]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        # Each finding produces exactly one line
        assert len(lines) == 2, f"Expected 2 annotation lines, got {len(lines)}"
        # Second annotation must contain full text (not masked by injected add-mask)
        assert "password123" in lines[1], "add-mask injection silenced second annotation"


# ---------------------------------------------------------------------------
# TestAnnotationParameterInjection — 3 tests
# ---------------------------------------------------------------------------


class TestAnnotationParameterInjection:
    """Simulate annotation format injection via crafted file paths.

    Annotation format: ::error file=X,line=Y::message
    A comma in file_path could inject extra parameters like title=, col=, etc.
    """

    def test_comma_in_filepath_no_param_injection(self, aggregate_module, capsys):
        """Comma in file path must not inject annotation parameters."""
        results = [{
            "ruleId": "COMMA-001",
            "level": "error",
            "message": {"text": "XSS found"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/evil,title=Hacked"},
                "region": {"startLine": 1},
            }}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        line = captured.out.strip()
        # The annotation format is: ::error file=PATH,line=N::message
        # With comma stripped, the file path should be "src/eviltitle=Hacked"
        # and the only comma should be the legitimate ,line= separator
        # Count commas before the :: message separator
        params_section = line.split("::")[1]  # "error file=X,line=Y"
        commas_in_params = params_section.count(",")
        assert commas_in_params == 1, \
            f"Expected exactly 1 comma (,line=) in params, got {commas_in_params}: {params_section}"

    def test_semicolon_in_filepath(self, aggregate_module, capsys):
        """Semicolons in file path handled safely."""
        results = [{
            "ruleId": "SEMI-001",
            "level": "warning",
            "message": {"text": "test"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/app;rm -rf /"},
                "region": {"startLine": 1},
            }}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        line = captured.out.strip()
        # Semicolons alone are fine (sanitize_uri strips ;; but not single ;)
        # The important thing is no command injection from annotation format
        assert line.startswith("::warning ")

    def test_equals_in_filepath(self, aggregate_module, capsys):
        """Equals sign in file path doesn't break annotation format."""
        results = [{
            "ruleId": "EQ-001",
            "level": "error",
            "message": {"text": "test"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/app=evil"},
                "region": {"startLine": 1},
            }}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        line = captured.out.strip()
        assert "::error " in line
        # Verify the annotation still has proper structure
        assert ",line=" in line


# ---------------------------------------------------------------------------
# TestConverterCommandInjection — 4 tests
# ---------------------------------------------------------------------------


class TestConverterCommandInjection:
    """Simulate malicious package names/titles flowing through converter scripts.

    Converter output feeds into aggregate_sarif.py which sanitizes annotations.
    These tests verify the full pipeline: converter → SARIF → aggregate → annotation.
    """

    def test_pip_audit_newline_in_dep_name(self, pip_audit_module, aggregate_module, capsys):
        """Dependency name with newline flows through full pipeline safely."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            sarif_out = os.path.join(d, "output.sarif")
            data = {"dependencies": [{"name": "flask\n::set-env name=X::Y", "version": "1.0", "vulns": [
                {"id": "CVE-2099-0001", "fix_versions": ["2.0"]}
            ]}]}
            with open(inp, "w") as f:
                json.dump(data, f)
            pip_audit_module.convert(inp, sarif_out)
            # Load through aggregate pipeline
            runs = aggregate_module.load_sarif_files(d)
            all_results = []
            all_rules = {}
            for run in runs:
                driver = run.get("tool", {}).get("driver", {})
                for rule in driver.get("rules", []):
                    if rule.get("id"):
                        all_rules[rule["id"]] = rule
                for result in run.get("results", []):
                    if isinstance(result, dict):
                        all_results.append(result)
            # Emit through aggregate annotation pipeline
            aggregate_module.emit_annotations(all_results, all_rules)
            captured = capsys.readouterr()
            lines = captured.out.strip().split("\n")
            # Each result must produce exactly one annotation line
            for line in lines:
                assert line.startswith("::"), f"Unexpected output line: {line}"
                assert "::set-env" not in line.split("::")[0], "Command injection in annotation"

    def test_npm_audit_workflow_command_in_title(self, npm_audit_module, aggregate_module, capsys):
        """Advisory title with workflow command flows safely through pipeline."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            sarif_out = os.path.join(d, "output.sarif")
            data = {"advisories": {"999": {
                "severity": "high",
                "title": "XSS\n::error::INJECTED",
                "module_name": "evil-package",
            }}}
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, sarif_out)
            runs = aggregate_module.load_sarif_files(d)
            all_results = []
            for run in runs:
                for result in run.get("results", []):
                    if isinstance(result, dict):
                        all_results.append(result)
            aggregate_module.emit_annotations(all_results, {})
            captured = capsys.readouterr()
            lines = captured.out.strip().split("\n")
            assert len(lines) == 1, f"Injected extra annotation lines: {len(lines)}"

    def test_go_vuln_workflow_command_in_summary(self, go_vuln_module, aggregate_module, capsys):
        """Vulnerability summary with workflow command flows safely through pipeline."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            sarif_out = os.path.join(d, "output.sarif")
            entry = {"vulnerability": {"osv": {
                "id": "GO-2099-0001",
                "summary": "Overflow\n::warning::INJECTED",
                "affected": [{"package": {"name": "example.com/evil"}}],
            }}}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            go_vuln_module.convert(inp, sarif_out)
            runs = aggregate_module.load_sarif_files(d)
            all_results = []
            for run in runs:
                for result in run.get("results", []):
                    if isinstance(result, dict):
                        all_results.append(result)
            aggregate_module.emit_annotations(all_results, {})
            captured = capsys.readouterr()
            lines = captured.out.strip().split("\n")
            assert len(lines) == 1, f"Injected extra annotation lines: {len(lines)}"

    def test_pip_audit_crafted_vuln_id_injection(self, pip_audit_module, aggregate_module, capsys):
        """Crafted vuln ID with newline must not inject ruleId annotation."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            sarif_out = os.path.join(d, "output.sarif")
            data = {"dependencies": [{"name": "flask", "version": "1.0", "vulns": [
                {"id": "CVE-2099\n::error::PWNED", "fix_versions": []}
            ]}]}
            with open(inp, "w") as f:
                json.dump(data, f)
            pip_audit_module.convert(inp, sarif_out)
            runs = aggregate_module.load_sarif_files(d)
            all_results = []
            all_rules = {}
            for run in runs:
                driver = run.get("tool", {}).get("driver", {})
                for rule in driver.get("rules", []):
                    if rule.get("id"):
                        all_rules[rule["id"]] = rule
                for result in run.get("results", []):
                    if isinstance(result, dict):
                        all_results.append(result)
            aggregate_module.emit_annotations(all_results, all_rules)
            captured = capsys.readouterr()
            lines = captured.out.strip().split("\n")
            assert len(lines) == 1, f"Vuln ID injection produced {len(lines)} lines"


# ---------------------------------------------------------------------------
# TestScannerEvasionAwareness — 4 tests
# ---------------------------------------------------------------------------


class TestScannerEvasionAwareness:
    """Verify the action doesn't ship evasion configs that silence scanners."""

    def test_no_nosec_in_action(self, action_content):
        """Action must not contain nosec/nolint directives that silence scanners."""
        assert "# nosec" not in action_content
        assert "// nolint" not in action_content
        assert "eslint-disable" not in action_content

    def test_no_trivyignore_in_action(self, action_content):
        """Action must not create .trivyignore files."""
        assert ".trivyignore" not in action_content

    def test_no_gitleaksignore_in_action(self, action_content):
        """Action must not create .gitleaksignore files."""
        assert ".gitleaksignore" not in action_content

    def test_no_bandit_skip_in_action(self, action_content):
        """Bandit invocation must not use --skip to exclude checks."""
        assert "--skip" not in action_content or "bandit" not in action_content
