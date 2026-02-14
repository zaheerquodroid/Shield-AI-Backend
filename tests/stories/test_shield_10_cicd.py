"""Story acceptance tests for SHIELD-10: CI/CD Security Scanning Templates.

Each test class maps to an acceptance criterion (AC) from the story.
"""

from __future__ import annotations

import os

import pytest

from tests.helpers.github_actions import (
    ACTION_DIR,
    SCRIPTS_DIR,
    find_step_by_id,
    find_steps_containing,
    get_action_inputs,
    get_action_outputs,
    get_composite_steps,
    get_step_condition,
    get_workflow_permissions,
    load_action_yml,
    load_template,
    load_workflow,
)


@pytest.fixture(scope="module")
def action() -> dict:
    return load_action_yml()


@pytest.fixture(scope="module")
def steps(action: dict) -> list[dict]:
    return get_composite_steps(action)


@pytest.fixture(scope="module")
def workflow() -> dict:
    return load_workflow("security-scan.yml")


# ---------------------------------------------------------------------------
# AC1: Composite GitHub Action with SAST, SCA, secrets, container scanning
# ---------------------------------------------------------------------------


class TestAC1_CompositeAction:
    """AC1: Must be a composite action with SAST, SCA, secrets, and container scanning."""

    def test_is_composite_action(self, action):
        assert action["runs"]["using"] == "composite"

    def test_has_sast_and_sca_and_secrets(self, steps):
        step_ids = [s.get("id", "") for s in steps]
        # SAST
        assert "bandit" in step_ids, "Must have SAST scanner (bandit)"
        # SCA
        assert "pip-audit" in step_ids, "Must have SCA scanner (pip-audit)"
        # Secrets
        assert "gitleaks" in step_ids, "Must have secret scanner (gitleaks)"

    def test_at_least_7_scanner_steps(self, steps):
        scanner_ids = {"bandit", "pip-audit", "eslint-security", "npm-audit",
                       "govulncheck", "gitleaks", "trivy"}
        found = [s for s in steps if s.get("id") in scanner_ids]
        assert len(found) >= 7, f"Expected >= 7 scanner steps, got {len(found)}"


# ---------------------------------------------------------------------------
# AC2: Python support (Bandit SAST + pip-audit SCA)
# ---------------------------------------------------------------------------


class TestAC2_PythonSupport:
    """AC2: Must support Python with Bandit SAST and pip-audit SCA."""

    def test_bandit_present(self, steps):
        step = find_step_by_id(steps, "bandit")
        assert step is not None
        assert "bandit" in step.get("run", "")

    def test_pip_audit_present(self, steps):
        step = find_step_by_id(steps, "pip-audit")
        assert step is not None
        assert "pip-audit" in step.get("run", "") or "pip_audit" in step.get("run", "")

    def test_python_conditional(self, steps):
        bandit = find_step_by_id(steps, "bandit")
        pip_audit = find_step_by_id(steps, "pip-audit")
        assert "python-enabled" in get_step_condition(bandit)
        assert "python-enabled" in get_step_condition(pip_audit)


# ---------------------------------------------------------------------------
# AC3: JavaScript support (eslint-security SAST + npm audit SCA)
# ---------------------------------------------------------------------------


class TestAC3_JavaScriptSupport:
    """AC3: Must support JavaScript with eslint-security and npm audit."""

    def test_eslint_present(self, steps):
        step = find_step_by_id(steps, "eslint-security")
        assert step is not None

    def test_npm_audit_present(self, steps):
        step = find_step_by_id(steps, "npm-audit")
        assert step is not None

    def test_javascript_conditional(self, steps):
        eslint = find_step_by_id(steps, "eslint-security")
        npm = find_step_by_id(steps, "npm-audit")
        assert "javascript-enabled" in get_step_condition(eslint)
        assert "javascript-enabled" in get_step_condition(npm)


# ---------------------------------------------------------------------------
# AC4: Go support (govulncheck SCA)
# ---------------------------------------------------------------------------


class TestAC4_GoSupport:
    """AC4: Must support Go with govulncheck SCA."""

    def test_govulncheck_present(self, steps):
        step = find_step_by_id(steps, "govulncheck")
        assert step is not None

    def test_go_conditional(self, steps):
        step = find_step_by_id(steps, "govulncheck")
        cond = get_step_condition(step)
        assert "go-enabled" in cond


# ---------------------------------------------------------------------------
# AC5: Secret scanning (gitleaks)
# ---------------------------------------------------------------------------


class TestAC5_SecretScanning:
    """AC5: Must have gitleaks secret scanning producing SARIF."""

    def test_gitleaks_present(self, steps):
        step = find_step_by_id(steps, "gitleaks")
        assert step is not None

    def test_gitleaks_produces_sarif(self, steps):
        step = find_step_by_id(steps, "gitleaks")
        uses = step.get("uses", "")
        with_args = step.get("with", {})
        args_str = with_args.get("args", "")
        assert "gitleaks" in uses, "gitleaks must use official action"
        assert "sarif" in args_str, "gitleaks must produce SARIF output"


# ---------------------------------------------------------------------------
# AC6: PR annotations via SARIF upload
# ---------------------------------------------------------------------------


class TestAC6_PRAnnotations:
    """AC6: Must upload SARIF for PR annotations."""

    def test_sarif_upload_step(self, steps):
        step = find_step_by_id(steps, "upload-sarif")
        assert step is not None

    def test_aggregate_emits_workflow_commands(self):
        """Aggregate script must emit ::error/::warning/::notice commands."""
        script_path = os.path.join(SCRIPTS_DIR, "aggregate_sarif.py")
        with open(script_path) as f:
            content = f.read()
        assert "::error" in content or "::warning" in content

    def test_sarif_upload_has_category(self, steps):
        step = find_step_by_id(steps, "upload-sarif")
        with_block = step.get("with", {})
        assert "category" in with_block

    def test_aggregate_script_exists(self):
        assert os.path.isfile(os.path.join(SCRIPTS_DIR, "aggregate_sarif.py"))


# ---------------------------------------------------------------------------
# AC7: Configurable severity threshold
# ---------------------------------------------------------------------------


class TestAC7_SeverityThreshold:
    """AC7: Must have configurable severity threshold with default high."""

    def test_threshold_input_exists(self, action):
        inputs = get_action_inputs(action)
        assert "severity-threshold" in inputs

    def test_threshold_default_high(self, action):
        inputs = get_action_inputs(action)
        assert inputs["severity-threshold"]["default"] == "high"

    def test_fail_on_findings_input(self, action):
        inputs = get_action_inputs(action)
        assert "fail-on-findings" in inputs
        assert inputs["fail-on-findings"]["default"] == "true"
