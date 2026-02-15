"""Unit tests for SHIELD-11: SBOM & Supply Chain Security.

Tests validate_sbom.py, merge_sboms.py, action.yml SBOM inputs/outputs/steps,
sbom-generate.yml workflow structure, and upload step configuration.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile

import pytest
import yaml

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

# ---------------------------------------------------------------------------
# Import SBOM scripts by adding scripts dir to path
# ---------------------------------------------------------------------------

_scripts_dir = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "github-actions", "security-scan", "scripts",
)
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

import validate_sbom  # noqa: E402
import merge_sboms  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sbom(
    components: list[dict] | None = None,
    bom_format: str = "CycloneDX",
    spec_version: str = "1.5",
    metadata: dict | None = None,
) -> dict:
    """Build a minimal valid CycloneDX SBOM dict."""
    sbom: dict = {
        "bomFormat": bom_format,
        "specVersion": spec_version,
        "version": 1,
        "components": components if components is not None else [
            {"type": "library", "name": "requests", "version": "2.31.0",
             "purl": "pkg:pypi/requests@2.31.0"},
        ],
    }
    if metadata is not None:
        sbom["metadata"] = metadata
    return sbom


def _write_sbom(dir_path: str, name: str, sbom: dict) -> str:
    """Write an SBOM dict to a .cdx.json file."""
    path = os.path.join(dir_path, name)
    with open(path, "w") as f:
        json.dump(sbom, f)
    return path


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
def sbom_workflow() -> dict:
    return load_workflow("sbom-generate.yml")


# ---------------------------------------------------------------------------
# TestValidateSBOM — 10 tests
# ---------------------------------------------------------------------------


class TestValidateSBOM:
    """Validate CycloneDX SBOM structure validation."""

    def test_valid_cyclonedx(self):
        sbom = _make_sbom()
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is True
        assert errors == []

    def test_missing_bom_format(self):
        sbom = _make_sbom()
        del sbom["bomFormat"]
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False
        assert any("bomFormat" in e for e in errors)

    def test_wrong_spec_version(self):
        sbom = _make_sbom(spec_version="2.0")
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False
        assert any("specVersion" in e for e in errors)

    def test_empty_components(self):
        sbom = _make_sbom(components=[])
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is True
        assert errors == []

    def test_missing_type(self):
        sbom = _make_sbom(components=[{"name": "foo"}])
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False
        assert any("type" in e for e in errors)

    def test_missing_name(self):
        sbom = _make_sbom(components=[{"type": "library"}])
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False
        assert any("name" in e for e in errors)

    def test_null_values(self):
        sbom = _make_sbom(components=[{"type": None, "name": None}])
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False

    def test_non_dict(self):
        valid, errors = validate_sbom.validate_cyclonedx("not a dict")
        assert valid is False
        assert any("not a JSON object" in e for e in errors)

    def test_oversized_components(self):
        components = [
            {"type": "library", "name": f"pkg-{i}", "version": "1.0.0"}
            for i in range(validate_sbom.MAX_COMPONENTS + 1)
        ]
        sbom = _make_sbom(components=components)
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False
        assert any("exceeds limit" in e for e in errors)

    def test_non_dict_component(self):
        sbom = _make_sbom(components=["not a dict"])
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False
        assert any("not a dict" in e for e in errors)


# ---------------------------------------------------------------------------
# TestLoadAndValidate — 4 tests
# ---------------------------------------------------------------------------


class TestLoadAndValidate:
    """Test load_and_validate file loading with security guards."""

    def test_valid_file(self, tmp_path):
        sbom = _make_sbom()
        path = _write_sbom(str(tmp_path), "test.cdx.json", sbom)
        data, errors = validate_sbom.load_and_validate(path)
        assert data is not None
        assert errors == []

    def test_symlink_rejected(self, tmp_path):
        sbom = _make_sbom()
        real = _write_sbom(str(tmp_path), "real.cdx.json", sbom)
        link = os.path.join(str(tmp_path), "link.cdx.json")
        os.symlink(real, link)
        data, errors = validate_sbom.load_and_validate(link)
        assert data is None
        assert any("symlink" in e for e in errors)

    def test_bom_stripped(self, tmp_path):
        sbom = _make_sbom()
        path = os.path.join(str(tmp_path), "bom.cdx.json")
        with open(path, "w") as f:
            f.write("\ufeff" + json.dumps(sbom))
        data, errors = validate_sbom.load_and_validate(path)
        assert data is not None
        assert errors == []

    def test_invalid_json(self, tmp_path):
        path = os.path.join(str(tmp_path), "bad.cdx.json")
        with open(path, "w") as f:
            f.write("{invalid json")
        data, errors = validate_sbom.load_and_validate(path)
        assert data is None
        assert any("invalid JSON" in e for e in errors)


# ---------------------------------------------------------------------------
# TestValidateComponent — 5 tests
# ---------------------------------------------------------------------------


class TestValidateComponent:
    """Test individual component validation."""

    def test_valid_component(self):
        errors = validate_sbom.validate_component({
            "type": "library", "name": "flask", "version": "3.0.0",
            "purl": "pkg:pypi/flask@3.0.0",
        })
        assert errors == []

    def test_invalid_type(self):
        errors = validate_sbom.validate_component({
            "type": "malware", "name": "bad",
        })
        assert any("invalid component type" in e for e in errors)

    def test_invalid_purl_format(self):
        errors = validate_sbom.validate_component({
            "type": "library", "name": "x", "purl": "http://not-a-purl",
        })
        assert any("invalid purl" in e for e in errors)

    def test_version_not_string(self):
        errors = validate_sbom.validate_component({
            "type": "library", "name": "x", "version": 123,
        })
        assert any("version" in e for e in errors)

    def test_purl_not_string(self):
        errors = validate_sbom.validate_component({
            "type": "library", "name": "x", "purl": 42,
        })
        assert any("purl" in e for e in errors)


# ---------------------------------------------------------------------------
# TestMergeSBOMs — 8 tests
# ---------------------------------------------------------------------------


class TestMergeSBOMs:
    """Test SBOM merging and deduplication."""

    def test_merge_two_sboms(self):
        sbom1 = _make_sbom(components=[
            {"type": "library", "name": "a", "version": "1.0", "purl": "pkg:pypi/a@1.0"},
        ])
        sbom2 = _make_sbom(components=[
            {"type": "library", "name": "b", "version": "2.0", "purl": "pkg:pypi/b@2.0"},
        ])
        merged = merge_sboms.merge_sboms([sbom1, sbom2])
        assert len(merged["components"]) == 2

    def test_dedup_by_purl(self):
        comp = {"type": "library", "name": "a", "version": "1.0", "purl": "pkg:pypi/a@1.0"}
        sbom1 = _make_sbom(components=[comp])
        sbom2 = _make_sbom(components=[comp.copy()])
        merged = merge_sboms.merge_sboms([sbom1, sbom2])
        assert len(merged["components"]) == 1

    def test_dedup_by_name_version(self):
        comp1 = {"type": "library", "name": "a", "version": "1.0"}
        comp2 = {"type": "library", "name": "a", "version": "1.0"}
        sbom1 = _make_sbom(components=[comp1])
        sbom2 = _make_sbom(components=[comp2])
        merged = merge_sboms.merge_sboms([sbom1, sbom2])
        assert len(merged["components"]) == 1

    def test_merge_metadata(self):
        sbom1 = _make_sbom(metadata={
            "timestamp": "2024-01-01T00:00:00Z",
            "tools": [{"name": "cyclonedx-py"}],
        })
        sbom2 = _make_sbom(metadata={
            "timestamp": "2024-06-01T00:00:00Z",
            "tools": [{"name": "syft"}],
        })
        merged = merge_sboms.merge_sboms([sbom1, sbom2])
        metadata = merged["metadata"]
        assert metadata["timestamp"] == "2024-06-01T00:00:00Z"
        tool_names = [t.get("name") for t in metadata["tools"]]
        assert "sbom-merge" in tool_names

    def test_empty_input(self):
        merged = merge_sboms.merge_sboms([])
        assert merged["bomFormat"] == "CycloneDX"
        assert merged["components"] == []

    def test_single_passthrough(self):
        sbom = _make_sbom(components=[
            {"type": "library", "name": "solo", "version": "1.0", "purl": "pkg:pypi/solo@1.0"},
        ])
        merged = merge_sboms.merge_sboms([sbom])
        assert len(merged["components"]) == 1
        assert merged["components"][0]["name"] == "solo"

    def test_component_cap(self):
        components = [
            {"type": "library", "name": f"pkg-{i}", "version": "1.0"}
            for i in range(merge_sboms.MAX_COMPONENTS + 100)
        ]
        sbom = _make_sbom(components=components)
        merged = merge_sboms.merge_sboms([sbom])
        assert len(merged["components"]) <= merge_sboms.MAX_COMPONENTS

    def test_token_masking(self):
        comp = {
            "type": "library",
            "name": "ghp_" + "A" * 40,
            "version": "1.0",
        }
        sbom = _make_sbom(components=[comp])
        merged = merge_sboms.merge_sboms([sbom])
        assert "[MASKED]" in merged["components"][0]["name"]


# ---------------------------------------------------------------------------
# TestLoadSBOMFiles — 4 tests
# ---------------------------------------------------------------------------


class TestLoadSBOMFiles:
    """Test loading SBOM files from directory."""

    def test_loads_valid_files(self, tmp_path):
        _write_sbom(str(tmp_path), "a.cdx.json", _make_sbom())
        result = merge_sboms.load_sbom_files(str(tmp_path))
        assert len(result) == 1

    def test_skips_symlinks(self, tmp_path):
        real = _write_sbom(str(tmp_path), "real.cdx.json", _make_sbom())
        link = os.path.join(str(tmp_path), "link.cdx.json")
        os.symlink(real, link)
        result = merge_sboms.load_sbom_files(str(tmp_path))
        assert len(result) == 1  # only real file, not symlink

    def test_skips_invalid_json(self, tmp_path):
        path = os.path.join(str(tmp_path), "bad.cdx.json")
        with open(path, "w") as f:
            f.write("not json")
        result = merge_sboms.load_sbom_files(str(tmp_path))
        assert len(result) == 0

    def test_empty_dir(self, tmp_path):
        result = merge_sboms.load_sbom_files(str(tmp_path))
        assert result == []


# ---------------------------------------------------------------------------
# TestActionSBOMInputs — 6 tests
# ---------------------------------------------------------------------------


class TestActionSBOMInputs:
    """Validate all SBOM-related action inputs."""

    def test_sbom_enabled_input(self, action):
        inputs = get_action_inputs(action)
        assert "sbom-enabled" in inputs
        assert inputs["sbom-enabled"]["default"] == "false"

    def test_sbom_format_input(self, action):
        inputs = get_action_inputs(action)
        assert "sbom-format" in inputs
        assert inputs["sbom-format"]["default"] == "cyclonedx-json"

    def test_sbom_python_input(self, action):
        inputs = get_action_inputs(action)
        assert "sbom-python" in inputs
        assert inputs["sbom-python"]["default"] == "true"

    def test_sbom_javascript_input(self, action):
        inputs = get_action_inputs(action)
        assert "sbom-javascript" in inputs
        assert inputs["sbom-javascript"]["default"] == "true"

    def test_sbom_go_input(self, action):
        inputs = get_action_inputs(action)
        assert "sbom-go" in inputs
        assert inputs["sbom-go"]["default"] == "true"

    def test_sbom_image_ref_input(self, action):
        inputs = get_action_inputs(action)
        assert "sbom-image-ref" in inputs
        assert inputs["sbom-image-ref"]["default"] == ""


# ---------------------------------------------------------------------------
# TestActionSBOMOutputs — 2 tests
# ---------------------------------------------------------------------------


class TestActionSBOMOutputs:
    """Validate SBOM-related action outputs."""

    def test_sbom_file_output(self, action):
        outputs = get_action_outputs(action)
        assert "sbom-file" in outputs

    def test_component_count_output(self, action):
        outputs = get_action_outputs(action)
        assert "component-count" in outputs


# ---------------------------------------------------------------------------
# TestActionSBOMSteps — 8 tests
# ---------------------------------------------------------------------------


class TestActionSBOMSteps:
    """Validate SBOM generation steps in action.yml."""

    def test_python_sbom_step_exists(self, steps):
        step = find_step_by_id(steps, "sbom-python")
        assert step is not None, "sbom-python step must exist"

    def test_python_sbom_conditional(self, steps):
        step = find_step_by_id(steps, "sbom-python")
        cond = get_step_condition(step)
        assert "sbom-enabled" in cond
        assert "sbom-python" in cond

    def test_javascript_sbom_step_exists(self, steps):
        step = find_step_by_id(steps, "sbom-javascript")
        assert step is not None, "sbom-javascript step must exist"

    def test_go_sbom_step_exists(self, steps):
        step = find_step_by_id(steps, "sbom-go")
        assert step is not None, "sbom-go step must exist"

    def test_image_sbom_step_exists(self, steps):
        step = find_step_by_id(steps, "sbom-image")
        assert step is not None, "sbom-image step must exist"

    def test_image_sbom_conditional(self, steps):
        step = find_step_by_id(steps, "sbom-image")
        cond = get_step_condition(step)
        assert "sbom-image-ref" in cond

    def test_merge_step_exists(self, steps):
        step = find_step_by_id(steps, "sbom-merge")
        assert step is not None, "sbom-merge step must exist"

    def test_merge_step_uses_merge_script(self, steps):
        step = find_step_by_id(steps, "sbom-merge")
        assert "merge_sboms.py" in step.get("run", "")


# ---------------------------------------------------------------------------
# TestSBOMWorkflow — 3 tests
# ---------------------------------------------------------------------------


class TestSBOMWorkflow:
    """Validate sbom-generate.yml workflow."""

    def test_valid_yaml(self, sbom_workflow):
        assert isinstance(sbom_workflow, dict)

    def test_release_trigger(self, sbom_workflow):
        # PyYAML parses 'on' as boolean True
        triggers = sbom_workflow.get(True, sbom_workflow.get("on", {}))
        assert "release" in triggers
        release = triggers["release"]
        assert "published" in release.get("types", [])

    def test_permissions(self, sbom_workflow):
        perms = get_workflow_permissions(sbom_workflow)
        assert perms.get("contents") == "write"


# ---------------------------------------------------------------------------
# TestUploadStep — 3 tests
# ---------------------------------------------------------------------------


class TestUploadStep:
    """Validate SBOM upload step in action.yml."""

    def test_upload_step_exists(self, steps):
        step = find_step_by_id(steps, "upload-sbom")
        assert step is not None, "upload-sbom step must exist"

    def test_upload_step_conditional(self, steps):
        step = find_step_by_id(steps, "upload-sbom")
        cond = get_step_condition(step)
        assert "sbom-enabled" in cond

    def test_upload_uses_artifact_action(self, steps):
        step = find_step_by_id(steps, "upload-sbom")
        assert "actions/upload-artifact@v4" in step.get("uses", "")


# ---------------------------------------------------------------------------
# TestSanitizeText — 3 tests
# ---------------------------------------------------------------------------


class TestSanitizeText:
    """Test _sanitize_text helper."""

    def test_strips_null_bytes(self):
        assert "\x00" not in validate_sbom._sanitize_text("he\x00llo")

    def test_strips_newlines(self):
        result = validate_sbom._sanitize_text("line1\nline2")
        assert "\n" not in result

    def test_strips_colons(self):
        result = validate_sbom._sanitize_text("a::b")
        assert "::" not in result


# ---------------------------------------------------------------------------
# TestWriteOutputs — 2 tests
# ---------------------------------------------------------------------------


class TestWriteOutputs:
    """Test GITHUB_OUTPUT writing."""

    def test_writes_outputs(self, tmp_path):
        out = os.path.join(str(tmp_path), "GITHUB_OUTPUT")
        with open(out, "w"):
            pass
        merge_sboms.write_outputs(42, "/path/to/sbom.json", True, out)
        with open(out) as f:
            content = f.read()
        assert "component-count=42" in content
        assert "sbom-file=" in content

    def test_sanitizes_newlines(self, tmp_path):
        out = os.path.join(str(tmp_path), "GITHUB_OUTPUT")
        with open(out, "w"):
            pass
        merge_sboms.write_outputs(1, "/path\ninjected=evil", True, out)
        with open(out) as f:
            lines = f.read().strip().split("\n")
        # The newline must not create a separate output line
        # (i.e. no line starts with "injected=")
        for line in lines:
            assert not line.startswith("injected="), \
                "Newline injection must not create separate output key"
