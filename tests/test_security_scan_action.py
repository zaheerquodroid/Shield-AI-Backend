"""Unit tests for the ShieldAI Security Scan composite GitHub Action.

Tests validate YAML structure, inputs, outputs, scanner steps,
aggregation logic, SARIF upload, workflow configuration, and templates.
"""

from __future__ import annotations

import os

import pytest
import yaml

from tests.helpers.github_actions import (
    ACTION_DIR,
    SCRIPTS_DIR,
    find_step_by_id,
    find_step_by_name,
    find_steps_containing,
    get_action_inputs,
    get_action_outputs,
    get_composite_steps,
    get_step_condition,
    get_workflow_jobs,
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


# ---------------------------------------------------------------------------
# TestActionStructure — 8 tests
# ---------------------------------------------------------------------------


class TestActionStructure:
    """Validate the basic structure of action.yml."""

    def test_action_file_exists(self):
        path = os.path.join(ACTION_DIR, "action.yml")
        assert os.path.isfile(path), "action.yml must exist"

    def test_valid_yaml(self):
        path = os.path.join(ACTION_DIR, "action.yml")
        with open(path) as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict), "action.yml must be a valid YAML dict"

    def test_has_name(self, action):
        assert "name" in action, "action.yml must have a name"
        assert isinstance(action["name"], str)

    def test_has_description(self, action):
        assert "description" in action, "action.yml must have a description"
        assert isinstance(action["description"], str)

    def test_is_composite(self, action):
        assert action.get("runs", {}).get("using") == "composite", \
            "action must be a composite action"

    def test_has_steps(self, action):
        steps = get_composite_steps(action)
        assert len(steps) >= 7, f"Expected at least 7 steps, got {len(steps)}"

    def test_has_branding(self, action):
        branding = action.get("branding", {})
        assert "icon" in branding, "action.yml must have branding.icon"
        assert "color" in branding, "action.yml must have branding.color"

    def test_scripts_directory_exists(self):
        assert os.path.isdir(SCRIPTS_DIR), "scripts/ directory must exist"


# ---------------------------------------------------------------------------
# TestInputs — 8 tests
# ---------------------------------------------------------------------------


class TestInputs:
    """Validate all action inputs exist with correct defaults."""

    def test_has_severity_threshold(self, action):
        inputs = get_action_inputs(action)
        assert "severity-threshold" in inputs

    def test_severity_threshold_default(self, action):
        inputs = get_action_inputs(action)
        assert inputs["severity-threshold"].get("default") == "high"

    def test_has_python_enabled(self, action):
        inputs = get_action_inputs(action)
        assert "python-enabled" in inputs
        assert inputs["python-enabled"].get("default") == "true"

    def test_has_javascript_enabled(self, action):
        inputs = get_action_inputs(action)
        assert "javascript-enabled" in inputs
        assert inputs["javascript-enabled"].get("default") == "true"

    def test_has_go_enabled(self, action):
        inputs = get_action_inputs(action)
        assert "go-enabled" in inputs
        assert inputs["go-enabled"].get("default") == "false"

    def test_has_gitleaks_enabled(self, action):
        inputs = get_action_inputs(action)
        assert "gitleaks-enabled" in inputs
        assert inputs["gitleaks-enabled"].get("default") == "true"

    def test_has_trivy_enabled(self, action):
        inputs = get_action_inputs(action)
        assert "trivy-enabled" in inputs
        assert inputs["trivy-enabled"].get("default") == "true"

    def test_has_fail_on_findings(self, action):
        inputs = get_action_inputs(action)
        assert "fail-on-findings" in inputs
        assert inputs["fail-on-findings"].get("default") == "true"


# ---------------------------------------------------------------------------
# TestOutputs — 7 tests
# ---------------------------------------------------------------------------


class TestOutputs:
    """Validate all action outputs exist."""

    def test_has_scan_result(self, action):
        outputs = get_action_outputs(action)
        assert "scan-result" in outputs

    def test_has_findings_count(self, action):
        outputs = get_action_outputs(action)
        assert "findings-count" in outputs

    def test_has_critical_count(self, action):
        outputs = get_action_outputs(action)
        assert "critical-count" in outputs

    def test_has_high_count(self, action):
        outputs = get_action_outputs(action)
        assert "high-count" in outputs

    def test_has_medium_count(self, action):
        outputs = get_action_outputs(action)
        assert "medium-count" in outputs

    def test_has_low_count(self, action):
        outputs = get_action_outputs(action)
        assert "low-count" in outputs

    def test_has_sarif_file(self, action):
        outputs = get_action_outputs(action)
        assert "sarif-file" in outputs


# ---------------------------------------------------------------------------
# TestScannerSteps — 8 tests
# ---------------------------------------------------------------------------


class TestScannerSteps:
    """Validate scanner steps exist with correct conditions."""

    def test_bandit_step_exists(self, steps):
        step = find_step_by_id(steps, "bandit")
        assert step is not None, "bandit step must exist"

    def test_bandit_conditional_on_python(self, steps):
        step = find_step_by_id(steps, "bandit")
        cond = get_step_condition(step)
        assert cond is not None, "bandit must have a condition"
        assert "python-enabled" in cond

    def test_pip_audit_step_exists(self, steps):
        step = find_step_by_id(steps, "pip-audit")
        assert step is not None, "pip-audit step must exist"

    def test_eslint_step_exists(self, steps):
        step = find_step_by_id(steps, "eslint-security")
        assert step is not None, "eslint-security step must exist"

    def test_npm_audit_step_exists(self, steps):
        step = find_step_by_id(steps, "npm-audit")
        assert step is not None, "npm-audit step must exist"

    def test_gitleaks_step_exists(self, steps):
        step = find_step_by_id(steps, "gitleaks")
        assert step is not None, "gitleaks step must exist"

    def test_trivy_step_exists(self, steps):
        step = find_step_by_id(steps, "trivy")
        assert step is not None, "trivy step must exist"

    def test_govulncheck_step_exists(self, steps):
        step = find_step_by_id(steps, "govulncheck")
        assert step is not None, "govulncheck step must exist"


# ---------------------------------------------------------------------------
# TestAggregation — 4 tests
# ---------------------------------------------------------------------------


class TestAggregation:
    """Validate the aggregation step."""

    def test_aggregate_step_exists(self, steps):
        step = find_step_by_id(steps, "aggregate")
        assert step is not None, "aggregate step must exist"

    def test_aggregate_has_id(self, steps):
        step = find_step_by_id(steps, "aggregate")
        assert step.get("id") == "aggregate"

    def test_aggregate_calls_script(self, steps):
        step = find_step_by_id(steps, "aggregate")
        run_cmd = step.get("run", "")
        assert "aggregate_sarif.py" in run_cmd

    def test_aggregate_passes_threshold(self, steps):
        step = find_step_by_id(steps, "aggregate")
        run_cmd = step.get("run", "")
        assert "--threshold" in run_cmd


# ---------------------------------------------------------------------------
# TestSARIFUpload — 3 tests
# ---------------------------------------------------------------------------


class TestSARIFUpload:
    """Validate the SARIF upload step."""

    def test_upload_step_exists(self, steps):
        step = find_step_by_id(steps, "upload-sarif")
        assert step is not None, "upload-sarif step must exist"

    def test_upload_conditional(self, steps):
        step = find_step_by_id(steps, "upload-sarif")
        cond = get_step_condition(step)
        assert cond is not None, "upload-sarif must have a condition"
        assert "sarif-upload" in cond

    def test_upload_continue_on_error(self, steps):
        step = find_step_by_id(steps, "upload-sarif")
        assert step.get("continue-on-error") is True


# ---------------------------------------------------------------------------
# TestWorkflow — 4 tests
# ---------------------------------------------------------------------------


class TestWorkflow:
    """Validate the example workflow."""

    def test_workflow_valid_yaml(self, workflow):
        assert isinstance(workflow, dict)

    def test_workflow_has_permissions(self, workflow):
        perms = get_workflow_permissions(workflow)
        assert len(perms) > 0, "Workflow must have permissions"

    def test_workflow_security_events_write(self, workflow):
        perms = get_workflow_permissions(workflow)
        assert perms.get("security-events") == "write"

    def test_workflow_references_action(self, workflow):
        jobs = get_workflow_jobs(workflow)
        assert len(jobs) > 0
        for job_name, job in jobs.items():
            steps = job.get("steps", [])
            for step in steps:
                uses = step.get("uses", "")
                if "security-scan" in uses:
                    return
            with_keys = [s.get("with", {}) for s in steps]
        # Check uses field in any step
        all_uses = []
        for job in jobs.values():
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if uses:
                    all_uses.append(uses)
        assert any("security-scan" in u for u in all_uses), \
            "Workflow must reference the security-scan action"


# ---------------------------------------------------------------------------
# TestTemplates — 3 tests
# ---------------------------------------------------------------------------


class TestTemplates:
    """Validate template files."""

    def test_dependabot_valid_yaml(self):
        data = load_template("dependabot.yml")
        assert isinstance(data, dict)

    def test_dependabot_version_2(self):
        data = load_template("dependabot.yml")
        assert data.get("version") == 2

    def test_pre_commit_valid_and_has_gitleaks(self):
        data = load_template(".pre-commit-config.yaml")
        assert isinstance(data, dict)
        repos = data.get("repos", [])
        repo_urls = [r.get("repo", "") for r in repos]
        assert any("gitleaks" in url for url in repo_urls), \
            "pre-commit config must include gitleaks"
