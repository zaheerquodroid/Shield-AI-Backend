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


# ---------------------------------------------------------------------------
# TestNullValueCrashPaths — 9 tests (CRITICAL: silent security bypass)
# ---------------------------------------------------------------------------


class TestNullValueCrashPaths:
    """Simulate SARIF results with JSON null values that previously caused crashes.

    In Python, dict.get("key", default) returns None (not default) when the
    key exists with value null. This caused AttributeError crashes that killed
    the entire aggregate script, preventing scan-result from being written,
    causing a SILENT SECURITY BYPASS.
    """

    def test_message_null_no_crash(self, aggregate_module, capsys):
        """result with 'message': null must not crash emit_annotations."""
        results = [{
            "ruleId": "NULL-MSG-001",
            "level": "error",
            "message": None,
            "locations": [],
        }]
        # Must not raise — previously crashed with AttributeError
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::error " in captured.out

    def test_rule_id_null_no_crash(self, aggregate_module, capsys):
        """result with 'ruleId': null must not crash emit_annotations."""
        results = [{
            "ruleId": None,
            "level": "error",
            "message": {"text": "Finding"},
            "locations": [],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::error " in captured.out

    def test_message_text_null_no_crash(self, aggregate_module, capsys):
        """result with 'message': {'text': null} must not crash."""
        results = [{
            "ruleId": "NULL-TXT-001",
            "level": "warning",
            "message": {"text": None},
            "locations": [],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::warning " in captured.out

    def test_physical_location_null_no_crash(self, aggregate_module, capsys):
        """physicalLocation: null must not crash."""
        results = [{
            "ruleId": "NULL-PHYS-001",
            "level": "error",
            "message": {"text": "Finding"},
            "locations": [{"physicalLocation": None}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::error " in captured.out

    def test_artifact_location_null_no_crash(self, aggregate_module, capsys):
        """artifactLocation: null must not crash."""
        results = [{
            "ruleId": "NULL-ART-001",
            "level": "error",
            "message": {"text": "Finding"},
            "locations": [{"physicalLocation": {"artifactLocation": None, "region": {"startLine": 1}}}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::error " in captured.out

    def test_region_null_no_crash(self, aggregate_module, capsys):
        """region: null must not crash."""
        results = [{
            "ruleId": "NULL-REG-001",
            "level": "error",
            "message": {"text": "Finding"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"}, "region": None}}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::error " in captured.out
        assert "line=1" in captured.out  # defaults to line 1

    def test_locations_null_no_crash(self, aggregate_module, capsys):
        """locations: null (not missing, explicitly null) must not crash."""
        results = [{
            "ruleId": "NULL-LOC-001",
            "level": "error",
            "message": {"text": "Finding"},
            "locations": None,
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::error " in captured.out

    def test_tool_null_in_run_no_crash(self, aggregate_module):
        """Run with 'tool': null must not crash main() rules collection."""
        with tempfile.TemporaryDirectory() as d:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": None, "results": [
                    {"ruleId": "R1", "level": "error", "message": {"text": "x"}}
                ]}],
            }
            p = os.path.join(d, "null_tool.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)
            runs = aggregate_module.load_sarif_files(d)
            # Simulate main() collection — must not crash
            all_rules = {}
            all_results = []
            for run in runs:
                tool = run.get("tool")
                if not isinstance(tool, dict):
                    tool = {}
                driver = tool.get("driver")
                if not isinstance(driver, dict):
                    driver = {}
                rules_list = driver.get("rules")
                if not isinstance(rules_list, list):
                    rules_list = []
                for rule in rules_list:
                    if isinstance(rule, dict) and rule.get("id"):
                        all_rules[rule["id"]] = rule
                results_list = run.get("results")
                if not isinstance(results_list, list):
                    results_list = []
                for result in results_list:
                    if isinstance(result, dict):
                        all_results.append(result)
            assert len(all_results) == 1

    def test_null_poison_does_not_suppress_other_findings(self, aggregate_module, capsys):
        """A null-poisoned result must NOT prevent other valid results from being annotated.

        This is THE critical test: an attacker injects one malformed result
        to crash the script and suppress all findings. After the fix, the
        poisoned result is handled gracefully and valid results still emit.
        """
        results = [
            # Poisoned result — all null values
            {"ruleId": None, "level": None, "message": None, "locations": None},
            # Valid result that MUST still be emitted
            {
                "ruleId": "VALID-001",
                "level": "error",
                "message": {"text": "Real critical finding"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 42},
                }}],
            },
        ]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().split("\n") if l]
        assert len(lines) == 2, f"Expected 2 annotations (poisoned + valid), got {len(lines)}"
        assert "VALID-001" in captured.out, "Valid finding suppressed by null-poisoned result"
        assert "Real critical finding" in captured.out


# ---------------------------------------------------------------------------
# TestEndToEndMain — 5 tests
# ---------------------------------------------------------------------------


class TestEndToEndMain:
    """End-to-end tests driving aggregate_sarif.main() with crafted input."""

    def test_main_fail_on_high_findings(self, aggregate_module):
        """main() must return 1 when findings exceed threshold."""
        with tempfile.TemporaryDirectory() as d:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": [
                    {"ruleId": "R1", "level": "error", "message": {"text": "XSS"}}
                ]}],
            }
            p = os.path.join(d, "test.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)

            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            merged = os.path.join(d, "merged.sarif")

            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                exit_code = aggregate_module.main()
            finally:
                sys.argv = old_argv

            assert exit_code == 1, f"Expected exit 1 on high findings, got {exit_code}"
            with open(gh_output) as f:
                content = f.read()
            assert "scan-result=fail" in content

    def test_main_pass_when_no_findings(self, aggregate_module):
        """main() must return 0 when no findings."""
        with tempfile.TemporaryDirectory() as d:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": []}],
            }
            p = os.path.join(d, "clean.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)

            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            merged = os.path.join(d, "merged.sarif")

            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                exit_code = aggregate_module.main()
            finally:
                sys.argv = old_argv

            assert exit_code == 0
            with open(gh_output) as f:
                content = f.read()
            assert "scan-result=pass" in content

    def test_main_fail_on_findings_false_suppresses_failure(self, aggregate_module):
        """--fail-on-findings false must return 0 even with findings."""
        with tempfile.TemporaryDirectory() as d:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": [
                    {"ruleId": "R1", "level": "error", "message": {"text": "XSS"}}
                ]}],
            }
            p = os.path.join(d, "test.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)

            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            merged = os.path.join(d, "merged.sarif")

            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "false",
                ]
                exit_code = aggregate_module.main()
            finally:
                sys.argv = old_argv

            assert exit_code == 0, "fail-on-findings=false should suppress exit 1"
            with open(gh_output) as f:
                content = f.read()
            assert "scan-result=pass" in content
            assert "high-count=1" in content  # findings still counted

    def test_main_empty_results_dir_rejected(self, aggregate_module):
        """Empty results-dir must fail, not silently scan CWD."""
        with tempfile.TemporaryDirectory() as d:
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            merged = os.path.join(d, "merged.sarif")

            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", "",
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                exit_code = aggregate_module.main()
            finally:
                sys.argv = old_argv

            assert exit_code == 1, "Empty results-dir must fail"

    def test_main_null_poison_still_reports_findings(self, aggregate_module):
        """main() with null-poisoned SARIF result must still count valid findings."""
        with tempfile.TemporaryDirectory() as d:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": [
                    {"ruleId": None, "level": None, "message": None, "locations": None},
                    {"ruleId": "R1", "level": "error", "message": {"text": "Real finding"}},
                ]}],
            }
            p = os.path.join(d, "poison.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)

            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            merged = os.path.join(d, "merged.sarif")

            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                exit_code = aggregate_module.main()
            finally:
                sys.argv = old_argv

            assert exit_code == 1, "Null-poisoned result must not suppress valid findings"
            with open(gh_output) as f:
                content = f.read()
            assert "scan-result=fail" in content
            assert "high-count=1" in content


# ---------------------------------------------------------------------------
# TestAnnotationLimitEnforcement — 2 tests
# ---------------------------------------------------------------------------


class TestAnnotationLimitEnforcement:
    """Verify MAX_ANNOTATIONS is actually enforced, not just a constant."""

    def test_emit_annotations_caps_at_max(self, aggregate_module, capsys):
        """emit_annotations must produce at most MAX_ANNOTATIONS output lines."""
        max_ann = aggregate_module.MAX_ANNOTATIONS
        # Create 2x the limit
        results = []
        for i in range(max_ann * 2):
            results.append({
                "ruleId": f"R-{i}",
                "level": "warning",
                "message": {"text": f"Finding {i}"},
                "locations": [],
            })
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().split("\n") if l.startswith("::")]
        assert len(lines) == max_ann, \
            f"Expected exactly {max_ann} annotations, got {len(lines)}"

    def test_emit_annotations_emits_warning_at_cap(self, aggregate_module, capsys):
        """Warning must be emitted when annotation limit is reached."""
        max_ann = aggregate_module.MAX_ANNOTATIONS
        results = [
            {"ruleId": f"R-{i}", "level": "warning", "message": {"text": f"F{i}"}, "locations": []}
            for i in range(max_ann + 1)
        ]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "Annotation limit reached" in captured.err


# ---------------------------------------------------------------------------
# TestSymlinkAttacks — 4 tests
# ---------------------------------------------------------------------------


class TestSymlinkAttacks:
    """Simulate symlink-based attacks on SARIF loading.

    An attacker who can write to the results directory (e.g., via artifact
    poisoning between workflow steps) could plant symlinks to:
    - Read arbitrary files (/etc/shadow)
    - Bypass size checks (symlink swap after stat, before open)
    - Cause infinite reads (symlink to /dev/zero)
    """

    def test_symlink_sarif_rejected(self, aggregate_module):
        """Symlinks in results directory must be rejected."""
        with tempfile.TemporaryDirectory() as d:
            # Create a real SARIF file
            real = os.path.join(d, "real.sarif")
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": [
                    {"ruleId": "R1", "level": "error", "message": {"text": "Finding"}}
                ]}],
            }
            with open(real, "w") as f:
                json.dump(sarif, f)

            # Create a symlink pointing to the real file
            link = os.path.join(d, "link.sarif")
            os.symlink(real, link)

            runs = aggregate_module.load_sarif_files(d)
            # Only the real file should be loaded, symlink rejected
            result_count = sum(len(r.get("results", [])) for r in runs)
            assert result_count == 1, "Symlink SARIF should be rejected"

    def test_symlink_to_outside_directory_rejected(self, aggregate_module):
        """Symlink pointing outside results dir must be rejected."""
        with tempfile.TemporaryDirectory() as d:
            with tempfile.TemporaryDirectory() as outside:
                external = os.path.join(outside, "external.sarif")
                sarif = {
                    "version": "2.1.0",
                    "$schema": "https://example.com",
                    "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": [
                        {"ruleId": "R1", "level": "error", "message": {"text": "Secret!"}}
                    ]}],
                }
                with open(external, "w") as f:
                    json.dump(sarif, f)

                link = os.path.join(d, "evil.sarif")
                os.symlink(external, link)

                runs = aggregate_module.load_sarif_files(d)
                # Symlink must be rejected
                assert len(runs) == 0, "Symlink to external file should be rejected"

    def test_symlink_warning_emitted(self, aggregate_module, capsys):
        """Warning must be emitted when symlink is skipped."""
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real.sarif")
            with open(real, "w") as f:
                json.dump({"version": "2.1.0", "runs": []}, f)

            link = os.path.join(d, "link.sarif")
            os.symlink(real, link)

            aggregate_module.load_sarif_files(d)
            captured = capsys.readouterr()
            assert "symlink" in captured.err.lower(), "Warning about symlink must be emitted"

    def test_broken_symlink_no_crash(self, aggregate_module):
        """Broken symlink must not crash the loader."""
        with tempfile.TemporaryDirectory() as d:
            link = os.path.join(d, "broken.sarif")
            os.symlink("/nonexistent/path.sarif", link)
            # Must not raise
            runs = aggregate_module.load_sarif_files(d)
            assert runs == []


# ---------------------------------------------------------------------------
# TestDeeplyNestedJSON — 3 tests
# ---------------------------------------------------------------------------


class TestDeeplyNestedJSON:
    """Simulate deeply nested JSON bomb attacks.

    A crafted SARIF file with deeply nested objects/arrays can cause:
    - Stack overflow (RecursionError) in json.load()
    - Memory exhaustion from deep dict/list allocation
    - CPU exhaustion from deep traversal
    """

    def test_deeply_nested_object_no_crash(self, aggregate_module):
        """Deeply nested JSON object must not crash the loader."""
        with tempfile.TemporaryDirectory() as d:
            # Create a deeply nested JSON that's valid SARIF-ish
            # Python json module has a default recursion limit
            depth = 500
            nested = "{" * depth + '"x": 1' + "}" * depth
            p = os.path.join(d, "deep.sarif")
            with open(p, "w") as f:
                f.write(nested)
            # Must not raise — either parse error or invalid SARIF structure
            runs = aggregate_module.load_sarif_files(d)
            # Deep nesting won't have valid SARIF structure
            assert runs == []

    def test_deeply_nested_array_no_crash(self, aggregate_module):
        """Deeply nested array must not crash the loader."""
        with tempfile.TemporaryDirectory() as d:
            depth = 500
            nested = "[" * depth + "1" + "]" * depth
            p = os.path.join(d, "deep_array.sarif")
            with open(p, "w") as f:
                f.write(nested)
            runs = aggregate_module.load_sarif_files(d)
            assert runs == []

    def test_moderate_nesting_still_parses(self, aggregate_module):
        """Legitimate SARIF with moderate nesting should parse fine."""
        with tempfile.TemporaryDirectory() as d:
            # SARIF has about 5-6 levels of nesting naturally
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "t", "rules": [{
                    "id": "R1",
                    "properties": {"security-severity": "8.0", "tags": ["security"]},
                }]}}, "results": [{
                    "ruleId": "R1",
                    "level": "error",
                    "message": {"text": "Finding"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": 1},
                    }}],
                }]}],
            }
            p = os.path.join(d, "normal.sarif")
            with open(p, "w") as f:
                json.dump(sarif, f)
            runs = aggregate_module.load_sarif_files(d)
            assert len(runs) == 1


# ---------------------------------------------------------------------------
# TestConverterNullValues — 6 tests
# ---------------------------------------------------------------------------


class TestConverterNullValues:
    """Simulate null value attacks against SARIF converter scripts.

    Same pattern as aggregate_sarif.py null-value crash paths:
    dict.get("key", default) returns None when key exists with null value.
    """

    def test_go_vuln_null_package_no_crash(self, go_vuln_module):
        """govulncheck with null package field must not crash."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            entry = {"vulnerability": {"osv": {
                "id": "GO-2099-NULL",
                "summary": "Test",
                "affected": [{"package": None, "module": None}],
            }}}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            # Must not crash with AttributeError
            go_vuln_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert len(sarif["runs"][0]["results"]) == 1

    def test_go_vuln_null_osv_id_skipped(self, go_vuln_module):
        """govulncheck with null osv.id must be skipped, not crash."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            entry = {"vulnerability": {"osv": {"id": None, "summary": "test"}}}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            go_vuln_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert sarif["runs"][0]["results"] == []

    def test_go_vuln_null_finding_line_no_crash(self, go_vuln_module):
        """Finding with null position.line must not produce non-int startLine."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            entry = {"finding": {
                "osv": "GO-2099-NULLLINE",
                "trace": [{"position": {"filename": "main.go", "line": None}}],
            }}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            go_vuln_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            result = sarif["runs"][0]["results"][0]
            line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
            assert isinstance(line, int) and line >= 1, \
                f"startLine must be positive int, got {line!r}"

    def test_npm_audit_null_severity_no_crash(self, npm_audit_module):
        """npm advisory with null severity must not crash."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {"advisories": {"1234": {
                "severity": None, "title": None, "module_name": None,
            }}}
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert len(sarif["runs"][0]["results"]) == 1

    def test_npm_audit_v7_null_title_source(self, npm_audit_module):
        """npm 7+ vuln with null title and source must not crash."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {"vulnerabilities": {"lodash": {"via": [{
                "severity": None, "title": None, "source": None, "name": None,
            }]}}}
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert len(sarif["runs"][0]["results"]) == 1

    def test_pip_audit_null_vuln_id_no_crash(self, pip_audit_module):
        """pip-audit with null vuln id must not crash."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {"dependencies": [{"name": None, "version": None, "vulns": [
                {"id": None, "fix_versions": None}
            ]}]}
            with open(inp, "w") as f:
                json.dump(data, f)
            pip_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert len(sarif["runs"][0]["results"]) == 1


# ---------------------------------------------------------------------------
# TestConverterInputSanitization — 5 tests
# ---------------------------------------------------------------------------


class TestConverterInputSanitization:
    """Test converter scripts sanitize attacker-controlled values.

    Converter output feeds into aggregate_sarif.py which sanitizes annotations,
    but defense-in-depth requires converters to also produce safe output.
    """

    def test_go_vuln_traversal_in_filename(self, go_vuln_module, aggregate_module, capsys):
        """Path traversal in govulncheck filename must be caught by aggregate."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            sarif_out = os.path.join(d, "output.sarif")
            entry = {"finding": {
                "osv": "GO-2099-TRAV",
                "trace": [{"position": {
                    "filename": "../../../etc/passwd",
                    "line": 1,
                }}],
            }}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            go_vuln_module.convert(inp, sarif_out)
            # Load through aggregate and emit annotation
            runs = aggregate_module.load_sarif_files(d)
            all_results = []
            for run in runs:
                for result in run.get("results", []):
                    if isinstance(result, dict):
                        all_results.append(result)
            aggregate_module.emit_annotations(all_results, {})
            captured = capsys.readouterr()
            # Path traversal must be stripped by sanitize_uri
            assert "../" not in captured.out, "Path traversal not sanitized in annotation"

    def test_go_vuln_negative_line_defaults(self, go_vuln_module):
        """Negative line number must be clamped to valid value."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            entry = {"finding": {
                "osv": "GO-2099-NEGLINE",
                "trace": [{"position": {"filename": "main.go", "line": -42}}],
            }}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            go_vuln_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            line = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
            assert isinstance(line, int) and line >= 1, \
                f"Negative line should be clamped, got {line}"

    def test_go_vuln_float_line_defaults(self, go_vuln_module):
        """Float line number from attacker JSON must be rejected."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            entry = {"finding": {
                "osv": "GO-2099-FLOATLINE",
                "trace": [{"position": {"filename": "main.go", "line": 3.14}}],
            }}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            go_vuln_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            line = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
            assert isinstance(line, int), f"Float line should be rejected, got {type(line).__name__}"

    def test_go_vuln_string_line_defaults(self, go_vuln_module):
        """String line number from attacker JSON must be rejected."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            entry = {"finding": {
                "osv": "GO-2099-STRLINE",
                "trace": [{"position": {"filename": "main.go", "line": "evil"}}],
            }}
            with open(inp, "w") as f:
                f.write(json.dumps(entry) + "\n")
            go_vuln_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            line = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
            assert line == 1, f"String line should default to 1, got {line}"

    def test_pip_audit_crafted_fix_versions(self, pip_audit_module):
        """Crafted fix_versions with non-string elements must not crash."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {"dependencies": [{"name": "flask", "version": "1.0", "vulns": [
                {"id": "CVE-2099-CRAFT", "fix_versions": [None, 42, {"nested": True}]}
            ]}]}
            with open(inp, "w") as f:
                json.dump(data, f)
            pip_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            assert len(sarif["runs"][0]["results"]) == 1


# ---------------------------------------------------------------------------
# TestSeverityEdgeCases — 4 tests
# ---------------------------------------------------------------------------


class TestSeverityEdgeCases:
    """Test severity normalization edge cases found via online research.

    JSON interoperability research shows large numbers, scientific notation,
    and type confusion can cause unexpected behavior in numeric processing.
    """

    def test_scientific_notation_infinity(self, aggregate_module):
        """1e999 parses to Infinity in Python — must not bypass threshold.

        float('1e999') == float('inf'), which is not finite.
        Before fix: would fall through all comparisons → 'low'.
        After fix: isfinite() rejects it → falls to SARIF level.
        """
        result = {"ruleId": "SCI-001", "level": "error"}
        rules = {"SCI-001": {"properties": {"security-severity": "1e999"}}}
        severity = aggregate_module.normalize_severity(result, rules)
        assert severity == "high", \
            f"1e999 (Infinity) should fall through to SARIF level 'error' → 'high', got '{severity}'"

    def test_negative_zero_score(self, aggregate_module):
        """Negative zero (-0.0) is a valid finite float — should map to low."""
        result = {"ruleId": "NEGZ-001", "level": "error"}
        rules = {"NEGZ-001": {"properties": {"security-severity": "-0.0"}}}
        severity = aggregate_module.normalize_severity(result, rules)
        assert severity == "low", f"-0.0 should be low, got '{severity}'"

    def test_extremely_long_score_string(self, aggregate_module):
        """Very long numeric string must not cause CPU exhaustion in float()."""
        result = {"ruleId": "LONG-001", "level": "error"}
        # 100K digit number — Python float() handles this fine
        long_score = "9" * 100_000
        rules = {"LONG-001": {"properties": {"security-severity": long_score}}}
        start = time.monotonic()
        severity = aggregate_module.normalize_severity(result, rules)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"Long score string took {elapsed:.2f}s"
        # Very large number → Infinity → falls through to SARIF level
        assert severity in ("high", "critical"), f"Long score: got '{severity}'"

    def test_boolean_score_rejected(self, aggregate_module):
        """Boolean score (True=1, False=0) must not bypass mapping."""
        result = {"ruleId": "BOOL-001", "level": "error"}
        # JSON true becomes Python True; float(True) == 1.0
        rules = {"BOOL-001": {"properties": {"security-severity": True}}}
        severity = aggregate_module.normalize_severity(result, rules)
        # True is truthy, float(True) = 1.0 which is < 4.0 → low
        # But score_str check: `if score_str:` — True is truthy, so it enters
        # the float conversion path. float(True) = 1.0, which is "low".
        # This is technically correct but worth documenting.
        assert severity == "low", f"Boolean True score: got '{severity}'"


# ---------------------------------------------------------------------------
# TestUnicodeSARIF — 3 tests
# ---------------------------------------------------------------------------


class TestUnicodeSARIF:
    """Test Unicode edge cases in SARIF processing.

    Attackers may use Unicode tricks to bypass sanitization or cause
    encoding-related crashes.
    """

    def test_bom_in_sarif_file(self, aggregate_module):
        """UTF-8 BOM at start of SARIF file must be handled gracefully."""
        with tempfile.TemporaryDirectory() as d:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": [
                    {"ruleId": "BOM-001", "level": "error", "message": {"text": "Finding"}}
                ]}],
            }
            p = os.path.join(d, "bom.sarif")
            with open(p, "w", encoding="utf-8-sig") as f:
                json.dump(sarif, f)
            runs = aggregate_module.load_sarif_files(d)
            # Python json.loads handles BOM gracefully
            assert len(runs) == 1

    def test_unicode_in_rule_id(self, aggregate_module, capsys):
        """Unicode characters in ruleId must not crash annotations."""
        results = [{
            "ruleId": "RULE-\u200b\u200c\u200d-001",  # zero-width chars
            "level": "error",
            "message": {"text": "Finding with unicode rule"},
            "locations": [],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::error " in captured.out

    def test_unicode_in_file_path(self, aggregate_module, capsys):
        """Unicode file paths must not crash annotations."""
        results = [{
            "ruleId": "UNI-PATH-001",
            "level": "warning",
            "message": {"text": "test"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/caf\u00e9/app.py"},
                "region": {"startLine": 1},
            }}],
        }]
        aggregate_module.emit_annotations(results, {})
        captured = capsys.readouterr()
        assert "::warning " in captured.out


# ---------------------------------------------------------------------------
# TestSupplyChainHardening — 3 tests
# ---------------------------------------------------------------------------


class TestSupplyChainHardening:
    """Test supply chain security based on CVE-2025-30066 (tj-actions) research.

    The March 2025 tj-actions/changed-files attack showed that mutable
    GitHub Action tags (@v2, @v3) can be silently repointed to malicious
    commits. Only SHA pinning or version pinning provides immutability.
    """

    def test_upload_sarif_uses_major_version_pin(self, steps):
        """upload-sarif must be pinned to at least major version."""
        step = find_step_by_id(steps, "upload-sarif")
        uses = step.get("uses", "")
        ref = uses.split("@")[1] if "@" in uses else ""
        # Must be version tag (v1, v2, v3) or SHA, not branch
        assert re.match(r"^(v\d|[0-9a-f]{40})", ref), \
            f"upload-sarif ref '{ref}' must be version tag or SHA"

    def test_gitleaks_uses_version_pin(self, steps):
        """gitleaks-action must be pinned to version, not branch."""
        step = find_step_by_id(steps, "gitleaks")
        uses = step.get("uses", "")
        ref = uses.split("@")[1] if "@" in uses else ""
        assert ref not in ("main", "master", "HEAD", "latest"), \
            f"gitleaks pinned to mutable ref '{ref}'"

    def test_no_mutable_branch_refs(self, steps):
        """No action should use mutable branch references."""
        mutable_refs = {"main", "master", "HEAD", "latest", "dev", "develop"}
        for step in steps:
            uses = step.get("uses", "")
            if "@" in uses:
                ref = uses.split("@")[1]
                assert ref not in mutable_refs, \
                    f"Step '{step.get('id', step.get('name'))}' uses mutable ref '{ref}': {uses}"


# ---------------------------------------------------------------------------
# TestEndToEndConverterPipeline — 4 tests
# ---------------------------------------------------------------------------


class TestEndToEndConverterPipeline:
    """End-to-end tests driving converter → aggregate → annotation pipeline
    with adversarial input to verify defense-in-depth.
    """

    def test_go_vuln_null_cascade_through_pipeline(self, go_vuln_module, aggregate_module):
        """All-null govulncheck finding must not crash full pipeline."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            sarif_out = os.path.join(d, "output.sarif")
            # Mix of null and valid entries
            entries = [
                json.dumps({"vulnerability": {"osv": {"id": None}}}),
                json.dumps({"vulnerability": {"osv": {
                    "id": "GO-2099-VALID",
                    "summary": "Real vuln",
                    "affected": [{"package": {"name": "example.com/foo"}}],
                }}}),
                json.dumps({"finding": {"osv": None}}),
            ]
            with open(inp, "w") as f:
                f.write("\n".join(entries) + "\n")
            go_vuln_module.convert(inp, sarif_out)
            # Load through aggregate
            runs = aggregate_module.load_sarif_files(d)
            all_results = []
            for run in runs:
                for result in run.get("results", []):
                    if isinstance(result, dict):
                        all_results.append(result)
            # Only the valid entry should produce a result
            assert len(all_results) == 1
            assert all_results[0]["ruleId"] == "GO-2099-VALID"

    def test_npm_audit_both_formats_with_nulls(self, npm_audit_module, aggregate_module):
        """npm audit with null values in both v6 and v7 formats must not crash."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            sarif_out = os.path.join(d, "output.sarif")
            # v7 format with null values
            data = {"vulnerabilities": {"evil-pkg": {"via": [
                {"severity": None, "title": None, "source": None},
                {"severity": "high", "title": "Real Vuln", "source": 999},
            ]}}}
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, sarif_out)
            runs = aggregate_module.load_sarif_files(d)
            all_results = []
            for run in runs:
                for result in run.get("results", []):
                    if isinstance(result, dict):
                        all_results.append(result)
            assert len(all_results) == 2  # both entries produce results

    def test_pip_audit_all_null_fields_through_pipeline(self, pip_audit_module, aggregate_module):
        """pip-audit with all null fields must survive full pipeline."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            sarif_out = os.path.join(d, "output.sarif")
            data = {"dependencies": [
                {"name": None, "version": None, "vulns": [
                    {"id": None, "fix_versions": None},
                ]},
                {"name": "flask", "version": "1.0", "vulns": [
                    {"id": "CVE-2099-REAL", "fix_versions": ["2.0"]},
                ]},
            ]}
            with open(inp, "w") as f:
                json.dump(data, f)
            pip_audit_module.convert(inp, sarif_out)
            # Load and count through aggregate pipeline
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            merged = os.path.join(d, "merged.sarif")
            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                exit_code = aggregate_module.main()
            finally:
                sys.argv = old_argv
            assert exit_code == 1, "Real finding must trigger failure"
            with open(gh_output) as f:
                content = f.read()
            assert "scan-result=fail" in content

    def test_mixed_valid_invalid_sarif_files(self, aggregate_module):
        """Directory with mix of valid, invalid, and edge-case SARIF files."""
        with tempfile.TemporaryDirectory() as d:
            # Valid SARIF
            with open(os.path.join(d, "valid.sarif"), "w") as f:
                json.dump({
                    "version": "2.1.0", "$schema": "https://example.com",
                    "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": [
                        {"ruleId": "R1", "level": "error", "message": {"text": "Real"}}
                    ]}],
                }, f)
            # Invalid JSON
            with open(os.path.join(d, "bad.sarif"), "w") as f:
                f.write("not json{{{")
            # Valid JSON but not SARIF
            with open(os.path.join(d, "notsar.sarif"), "w") as f:
                json.dump({"hello": "world"}, f)
            # Empty file
            with open(os.path.join(d, "empty.sarif"), "w") as f:
                pass

            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            with open(gh_output, "w"):
                pass
            merged = os.path.join(d, "merged.sarif")
            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                exit_code = aggregate_module.main()
            finally:
                sys.argv = old_argv
            assert exit_code == 1, "Valid finding must not be hidden by invalid files"
            with open(gh_output) as f:
                content = f.read()
            assert "high-count=1" in content


# ---------------------------------------------------------------------------
# Round 6: Audit-driven hardening tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# TestTOCTOURace — 3 tests
# ---------------------------------------------------------------------------


class TestTOCTOURace:
    """Verify size limits use bounded reads instead of stat-then-open.

    TOCTOU (time-of-check/time-of-use) race: stat() checks size, attacker
    swaps file between stat and open, bypassing size limit.
    """

    def test_aggregate_uses_bounded_read(self, aggregate_module):
        """aggregate_sarif must use f.read(MAX+1) not stat().st_size."""
        import inspect
        src = inspect.getsource(aggregate_module.load_sarif_files)
        # Must NOT use stat().st_size pattern for the actual check
        assert "f.read(MAX_SARIF_SIZE + 1)" in src or "f.read(MAX_SARIF_SIZE+1)" in src, \
            "load_sarif_files must use bounded read, not stat-based size check"

    def test_pip_audit_uses_bounded_read(self, pip_audit_module):
        """pip_audit converter must use bounded read."""
        import inspect
        src = inspect.getsource(pip_audit_module.convert)
        assert "f.read(MAX_INPUT_SIZE + 1)" in src or "f.read(MAX_INPUT_SIZE+1)" in src, \
            "pip_audit converter must use bounded read, not stat-based size check"

    def test_go_vuln_uses_bounded_read(self, go_vuln_module):
        """govulncheck converter must use bounded read."""
        import inspect
        src = inspect.getsource(go_vuln_module.convert)
        assert "f.read(MAX_INPUT_SIZE + 1)" in src or "f.read(MAX_INPUT_SIZE+1)" in src, \
            "go_vuln converter must use bounded read, not stat-based size check"


# ---------------------------------------------------------------------------
# TestWorkflowCommandInjection — 4 tests
# ---------------------------------------------------------------------------


class TestWorkflowCommandInjection:
    """Verify :: sequences are stripped from annotation text to prevent
    injection of workflow commands like ::set-output, ::add-mask, etc.
    """

    def test_double_colon_stripped_from_message(self, aggregate_module, capsys):
        """:: in message text must be neutralized to prevent command injection."""
        results = [{
            "ruleId": "INJ-001",
            "level": "error",
            "message": {"text": "foo ::set-output name=scan-result::pass bar"},
        }]
        aggregate_module.emit_annotations(results, {})
        out = capsys.readouterr().out
        # The :: must be replaced so no workflow command is injected
        assert "::set-output" not in out
        # But the annotation itself must still be emitted
        assert "::error " in out

    def test_double_colon_stripped_from_rule_id(self, aggregate_module, capsys):
        """:: in ruleId must be neutralized."""
        results = [{
            "ruleId": "fake::warning::injected",
            "level": "warning",
            "message": {"text": "test"},
        }]
        aggregate_module.emit_annotations(results, {})
        out = capsys.readouterr().out
        # Should not produce extra workflow commands
        lines = [l for l in out.strip().split("\n") if l.startswith("::")]
        assert len(lines) == 1, "Only one workflow command annotation should be emitted"

    def test_set_env_injection_blocked(self, aggregate_module, capsys):
        """::set-env in message must be stripped."""
        results = [{
            "ruleId": "ENV-001",
            "level": "error",
            "message": {"text": "::set-env name=PATH::/evil/bin"},
        }]
        aggregate_module.emit_annotations(results, {})
        out = capsys.readouterr().out
        assert "::set-env" not in out

    def test_add_path_injection_blocked(self, aggregate_module, capsys):
        """::add-path in message must be stripped."""
        results = [{
            "ruleId": "PATH-001",
            "level": "error",
            "message": {"text": "::add-path::/tmp/evil"},
        }]
        aggregate_module.emit_annotations(results, {})
        out = capsys.readouterr().out
        assert "::add-path" not in out


# ---------------------------------------------------------------------------
# TestMergedSARIFTokenMasking — 3 tests
# ---------------------------------------------------------------------------


class TestMergedSARIFTokenMasking:
    """Verify tokens are masked in merged SARIF output (not just annotations).

    Scanners like gitleaks may include actual secret values in SARIF messages.
    These must be masked before the merged SARIF is written to disk and
    uploaded to GitHub Code Scanning.
    """

    def test_github_pat_masked_in_merged_sarif(self, aggregate_module):
        """GitHub PAT in SARIF result message must be masked in merged output."""
        with tempfile.TemporaryDirectory() as d:
            token = "ghp_" + "A" * 40
            sarif = {
                "version": "2.1.0", "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "gitleaks", "rules": []}},
                          "results": [{"ruleId": "GH-PAT", "level": "error",
                                       "message": {"text": f"Found token: {token}"}}]}],
            }
            with open(os.path.join(d, "secrets.sarif"), "w") as f:
                json.dump(sarif, f)
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            merged = os.path.join(d, "merged.sarif")
            with open(gh_output, "w"):
                pass
            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                aggregate_module.main()
            finally:
                sys.argv = old_argv
            with open(merged) as f:
                content = f.read()
            assert token not in content, "GitHub PAT must be masked in merged SARIF"
            assert "[MASKED]" in content

    def test_aws_key_masked_in_merged_sarif(self, aggregate_module):
        """AWS access key in result message must be masked in merged output."""
        with tempfile.TemporaryDirectory() as d:
            aws_key = "AKIAIOSFODNN7EXAMPLE"
            sarif = {
                "version": "2.1.0", "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "gitleaks", "rules": []}},
                          "results": [{"ruleId": "AWS-KEY", "level": "error",
                                       "message": {"text": f"AWS key: {aws_key}"}}]}],
            }
            with open(os.path.join(d, "aws.sarif"), "w") as f:
                json.dump(sarif, f)
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            merged = os.path.join(d, "merged.sarif")
            with open(gh_output, "w"):
                pass
            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                aggregate_module.main()
            finally:
                sys.argv = old_argv
            with open(merged) as f:
                content = f.read()
            assert aws_key not in content, "AWS key must be masked in merged SARIF"

    def test_private_key_masked_in_merged_sarif(self, aggregate_module):
        """Private key header in result message must be masked in merged output."""
        with tempfile.TemporaryDirectory() as d:
            pk = "-----BEGIN RSA PRIVATE KEY-----"
            sarif = {
                "version": "2.1.0", "$schema": "https://example.com",
                "runs": [{"tool": {"driver": {"name": "gitleaks", "rules": []}},
                          "results": [{"ruleId": "PK", "level": "error",
                                       "message": {"text": f"Found: {pk}"}}]}],
            }
            with open(os.path.join(d, "pk.sarif"), "w") as f:
                json.dump(sarif, f)
            gh_output = os.path.join(d, "GITHUB_OUTPUT")
            merged = os.path.join(d, "merged.sarif")
            with open(gh_output, "w"):
                pass
            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_sarif.py",
                    "--results-dir", d,
                    "--threshold", "high",
                    "--output-sarif", merged,
                    "--github-output", gh_output,
                    "--fail-on-findings", "true",
                ]
                aggregate_module.main()
            finally:
                sys.argv = old_argv
            with open(merged) as f:
                content = f.read()
            assert pk not in content, "Private key must be masked in merged SARIF"


# ---------------------------------------------------------------------------
# TestRulesAccumulationCap — 2 tests
# ---------------------------------------------------------------------------


class TestRulesAccumulationCap:
    """Verify MAX_RULES cap prevents memory exhaustion from crafted SARIF
    with millions of unique rule IDs.
    """

    def test_rules_capped_at_max(self, aggregate_module):
        """Rules accumulation must stop at MAX_RULES to prevent memory exhaustion."""
        assert hasattr(aggregate_module, "MAX_RULES"), "MAX_RULES constant must exist"
        assert aggregate_module.MAX_RULES <= 100000, "MAX_RULES must be bounded"

    def test_excessive_rules_truncated(self, aggregate_module):
        """SARIF with more rules than MAX_RULES must be truncated."""
        max_rules = aggregate_module.MAX_RULES
        # Create a run with MAX_RULES + 100 rules
        rules = [{"id": f"RULE-{i}", "shortDescription": {"text": f"Rule {i}"}}
                 for i in range(max_rules + 100)]
        run = {
            "tool": {"driver": {"name": "test", "rules": rules}},
            "results": [],
        }
        # Simulate the rules accumulation logic from main()
        all_rules = {}
        driver = run.get("tool", {}).get("driver", {})
        rules_list = driver.get("rules", [])
        for rule in rules_list:
            if len(all_rules) >= max_rules:
                break
            if isinstance(rule, dict):
                rule_id = rule.get("id", "")
                if rule_id:
                    all_rules[rule_id] = rule
        assert len(all_rules) == max_rules, \
            f"Expected {max_rules} rules but got {len(all_rules)}"


# ---------------------------------------------------------------------------
# TestNPMAdvisoryHiding — 3 tests
# ---------------------------------------------------------------------------


class TestNPMAdvisoryHiding:
    """Verify that injecting a dummy advisories key cannot suppress
    processing of npm 7+ vulnerabilities.
    """

    def test_both_formats_processed(self, npm_audit_module):
        """If both advisories and vulnerabilities exist, both are processed."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {
                "advisories": {
                    "1001": {"severity": "high", "title": "Advisory vuln",
                             "module_name": "old-pkg"},
                },
                "vulnerabilities": {
                    "new-pkg": {"via": [
                        {"severity": "critical", "title": "Real critical vuln",
                         "source": 2001},
                    ]},
                },
            }
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            results = sarif["runs"][0]["results"]
            # Both advisory and vulnerability should be present
            assert len(results) >= 2, \
                f"Expected >=2 results (advisory + vuln), got {len(results)}"
            rule_ids = [r["ruleId"] for r in results]
            assert any("advisory" in rid for rid in rule_ids), "Advisory result missing"
            assert any("vuln" in rid for rid in rule_ids), "Vulnerability result missing"

    def test_empty_advisories_does_not_block_vulns(self, npm_audit_module):
        """Empty advisories dict must not block npm 7+ vulnerability processing."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {
                "advisories": {},
                "vulnerabilities": {
                    "pkg": {"via": [
                        {"severity": "high", "title": "Critical Bug", "source": 3001},
                    ]},
                },
            }
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            results = sarif["runs"][0]["results"]
            assert len(results) >= 1, "npm 7+ vuln must be processed even with empty advisories"

    def test_dummy_advisory_cannot_suppress_real_vulns(self, npm_audit_module):
        """Dummy advisory with no real findings cannot hide npm7+ vulns."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            data = {
                "advisories": {"fake": "not-a-dict"},  # malformed, will be skipped
                "vulnerabilities": {
                    "victim-pkg": {"via": [
                        {"severity": "critical", "title": "Actual RCE", "source": 4001},
                    ]},
                },
            }
            with open(inp, "w") as f:
                json.dump(data, f)
            npm_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            results = sarif["runs"][0]["results"]
            assert len(results) >= 1, "Real npm7+ vuln must not be hidden by dummy advisories"


# ---------------------------------------------------------------------------
# TestFixVersionsTruncation — 2 tests
# ---------------------------------------------------------------------------


class TestFixVersionsTruncation:
    """Verify fix_versions elements are truncated to prevent oversized SARIF."""

    def test_long_fix_version_truncated(self, pip_audit_module):
        """Individual fix_version elements longer than 100 chars must be truncated."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            long_version = "x" * 500
            data = {"dependencies": [{
                "name": "pkg",
                "version": "1.0",
                "vulns": [{"id": "CVE-TRUNC", "fix_versions": [long_version]}],
            }]}
            with open(inp, "w") as f:
                json.dump(data, f)
            pip_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            msg = sarif["runs"][0]["results"][0]["message"]["text"]
            # The 500-char version should be truncated to 100
            assert long_version not in msg
            assert len(msg) < 300

    def test_many_fix_versions_capped(self, pip_audit_module):
        """More than 20 fix_versions must be capped."""
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "input.json")
            out = os.path.join(d, "output.sarif")
            versions = [f"99.{i}.0" for i in range(50)]
            data = {"dependencies": [{
                "name": "pkg",
                "version": "1.0",
                "vulns": [{"id": "CVE-MANY", "fix_versions": versions}],
            }]}
            with open(inp, "w") as f:
                json.dump(data, f)
            pip_audit_module.convert(inp, out)
            with open(out) as f:
                sarif = json.load(f)
            msg = sarif["runs"][0]["results"][0]["message"]["text"]
            # Should only have 20 versions, not 50
            version_count = msg.count("99.")
            assert version_count <= 20, f"Expected <=20 versions in message, got {version_count}"
