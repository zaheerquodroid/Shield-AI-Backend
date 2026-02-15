"""Story acceptance tests for SHIELD-11: SBOM & Supply Chain Security.

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
    get_workflow_jobs,
    get_workflow_permissions,
    load_action_yml,
    load_workflow,
)


@pytest.fixture(scope="module")
def action() -> dict:
    return load_action_yml()


@pytest.fixture(scope="module")
def steps(action: dict) -> list[dict]:
    return get_composite_steps(action)


@pytest.fixture(scope="module")
def sbom_workflow() -> dict:
    return load_workflow("sbom-generate.yml")


# ---------------------------------------------------------------------------
# AC1: CycloneDX JSON output format
# ---------------------------------------------------------------------------


class TestAC1_CycloneDXFormat:
    """AC1: SBOM must be in CycloneDX JSON format."""

    def test_sbom_format_default(self, action):
        inputs = get_action_inputs(action)
        assert inputs["sbom-format"]["default"] == "cyclonedx-json"

    def test_output_is_cdx_json(self, steps):
        step = find_step_by_id(steps, "sbom-merge")
        assert step is not None
        run = step.get("run", "")
        assert ".cdx.json" in run


# ---------------------------------------------------------------------------
# AC2: Python SBOM support
# ---------------------------------------------------------------------------


class TestAC2_PythonSupport:
    """AC2: Must support Python SBOM generation with cyclonedx-py."""

    def test_uses_cyclonedx_py(self, steps):
        step = find_step_by_id(steps, "sbom-python")
        assert step is not None
        run = step.get("run", "")
        assert "cyclonedx-py" in run or "cyclonedx-bom" in run

    def test_python_conditional(self, steps):
        step = find_step_by_id(steps, "sbom-python")
        cond = get_step_condition(step)
        assert "sbom-enabled" in cond
        assert "sbom-python" in cond


# ---------------------------------------------------------------------------
# AC3: JavaScript SBOM support
# ---------------------------------------------------------------------------


class TestAC3_JavaScriptSupport:
    """AC3: Must support JavaScript SBOM generation with cyclonedx-npm."""

    def test_uses_cyclonedx_npm(self, steps):
        step = find_step_by_id(steps, "sbom-javascript")
        assert step is not None
        run = step.get("run", "")
        assert "cyclonedx-npm" in run

    def test_javascript_conditional(self, steps):
        step = find_step_by_id(steps, "sbom-javascript")
        cond = get_step_condition(step)
        assert "sbom-enabled" in cond
        assert "sbom-javascript" in cond


# ---------------------------------------------------------------------------
# AC4: Go SBOM support
# ---------------------------------------------------------------------------


class TestAC4_GoSupport:
    """AC4: Must support Go SBOM generation with cyclonedx-gomod."""

    def test_uses_cyclonedx_gomod(self, steps):
        step = find_step_by_id(steps, "sbom-go")
        assert step is not None
        run = step.get("run", "")
        assert "cyclonedx-gomod" in run

    def test_go_conditional(self, steps):
        step = find_step_by_id(steps, "sbom-go")
        cond = get_step_condition(step)
        assert "sbom-enabled" in cond
        assert "sbom-go" in cond


# ---------------------------------------------------------------------------
# AC5: Docker image SBOM support
# ---------------------------------------------------------------------------


class TestAC5_DockerSupport:
    """AC5: Must support Docker image SBOM generation with syft."""

    def test_uses_syft(self, steps):
        step = find_step_by_id(steps, "sbom-image")
        assert step is not None
        run = step.get("run", "")
        assert "syft" in run

    def test_image_conditional_on_ref(self, steps):
        step = find_step_by_id(steps, "sbom-image")
        cond = get_step_condition(step)
        assert "sbom-image-ref" in cond


# ---------------------------------------------------------------------------
# AC6: Build artifact upload
# ---------------------------------------------------------------------------


class TestAC6_BuildArtifact:
    """AC6: Merged SBOM must be uploaded as a build artifact."""

    def test_merged_sbom_uploaded(self, steps):
        step = find_step_by_id(steps, "upload-sbom")
        assert step is not None
        assert "upload-artifact" in step.get("uses", "")

    def test_upload_conditional(self, steps):
        step = find_step_by_id(steps, "upload-sbom")
        cond = get_step_condition(step)
        assert "sbom-enabled" in cond


# ---------------------------------------------------------------------------
# AC7: Release-triggered SBOM workflow
# ---------------------------------------------------------------------------


class TestAC7_ReleaseWorkflow:
    """AC7: Release-published event must trigger SBOM generation."""

    def test_release_trigger(self, sbom_workflow):
        # PyYAML parses 'on' as boolean True
        triggers = sbom_workflow.get(True, sbom_workflow.get("on", {}))
        assert "release" in triggers

    def test_uploads_release_asset(self, sbom_workflow):
        jobs = get_workflow_jobs(sbom_workflow)
        assert "sbom" in jobs
        steps = jobs["sbom"].get("steps", [])
        upload_steps = [s for s in steps if "release upload" in s.get("run", "").lower()
                        or "gh release upload" in s.get("run", "")]
        assert len(upload_steps) > 0, "Must upload SBOM to release"

    def test_runs_security_scan(self, sbom_workflow):
        jobs = get_workflow_jobs(sbom_workflow)
        steps = jobs["sbom"].get("steps", [])
        scan_steps = [s for s in steps if "security-scan" in str(s.get("uses", ""))]
        assert len(scan_steps) > 0, "Must run security-scan action"
