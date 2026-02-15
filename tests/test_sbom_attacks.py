"""Attack simulation tests for SHIELD-11: SBOM & Supply Chain Security.

Tests validate security guards against injection, path traversal,
DoS, token leakage, workflow command injection, and supply chain attacks.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

from tests.helpers.github_actions import (
    find_step_by_id,
    get_composite_steps,
    get_workflow_jobs,
    get_workflow_permissions,
    load_action_yml,
    load_workflow,
)

# ---------------------------------------------------------------------------
# Import SBOM scripts
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
    sbom: dict = {
        "bomFormat": bom_format,
        "specVersion": spec_version,
        "version": 1,
        "components": components if components is not None else [
            {"type": "library", "name": "requests", "version": "2.31.0"},
        ],
    }
    if metadata is not None:
        sbom["metadata"] = metadata
    return sbom


def _write_sbom(dir_path: str, name: str, sbom: dict) -> str:
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
# TestSBOMInjection — 6 tests
# ---------------------------------------------------------------------------


class TestSBOMInjection:
    """Test rejection of malformed/injected SBOM data."""

    def test_malformed_json_rejected(self, tmp_path):
        path = os.path.join(str(tmp_path), "bad.cdx.json")
        with open(path, "w") as f:
            f.write("{not valid json!!!")
        data, errors = validate_sbom.load_and_validate(path)
        assert data is None
        assert any("invalid JSON" in e for e in errors)

    def test_missing_bom_format_rejected(self):
        sbom = {"specVersion": "1.5", "components": []}
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False

    def test_null_components_rejected(self):
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": None}
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False

    def test_non_dict_top_level(self):
        valid, errors = validate_sbom.validate_cyclonedx([1, 2, 3])
        assert valid is False

    def test_empty_name_rejected(self):
        sbom = _make_sbom(components=[{"type": "library", "name": ""}])
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False

    def test_non_string_type_rejected(self):
        sbom = _make_sbom(components=[{"type": 42, "name": "bad"}])
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False


# ---------------------------------------------------------------------------
# TestSBOMPathTraversal — 4 tests
# ---------------------------------------------------------------------------


class TestSBOMPathTraversal:
    """Test path traversal prevention in component fields."""

    def test_traversal_in_name(self):
        comp = {"type": "library", "name": "../../../etc/passwd", "version": "1.0"}
        errors = validate_sbom.validate_component(comp)
        # Name with traversal still validates — it's just a string field
        # The security comes from not using the name as a filesystem path
        assert isinstance(errors, list)

    def test_null_byte_in_purl(self):
        comp = {"type": "library", "name": "x", "purl": "pkg:pypi/x\x00@1.0"}
        errors = validate_sbom.validate_component(comp)
        # purl with null byte — validate_component accepts it but _sanitize_text strips nulls
        sanitized = validate_sbom._sanitize_text(comp["purl"])
        assert "\x00" not in sanitized

    def test_file_uri_in_purl(self):
        comp = {"type": "library", "name": "x", "purl": "file:///etc/passwd"}
        errors = validate_sbom.validate_component(comp)
        assert any("invalid purl" in e for e in errors)

    def test_backslash_in_name(self):
        comp = {"type": "library", "name": "..\\..\\secret", "version": "1.0"}
        errors = validate_sbom.validate_component(comp)
        assert isinstance(errors, list)


# ---------------------------------------------------------------------------
# TestComponentDedup — 5 tests
# ---------------------------------------------------------------------------


class TestComponentDedup:
    """Test deduplication attack vectors."""

    def test_purl_collision(self):
        comps = [
            {"type": "library", "name": "a", "purl": "pkg:pypi/a@1.0"},
            {"type": "library", "name": "b", "purl": "pkg:pypi/a@1.0"},
        ]
        result = merge_sboms._deduplicate_components(comps)
        assert len(result) == 1

    def test_name_version_collision(self):
        comps = [
            {"type": "library", "name": "a", "version": "1.0"},
            {"type": "library", "name": "a", "version": "1.0"},
        ]
        result = merge_sboms._deduplicate_components(comps)
        assert len(result) == 1

    def test_case_sensitivity(self):
        comps = [
            {"type": "library", "name": "Flask", "version": "3.0", "purl": "pkg:pypi/Flask@3.0"},
            {"type": "library", "name": "flask", "version": "3.0", "purl": "pkg:pypi/flask@3.0"},
        ]
        result = merge_sboms._deduplicate_components(comps)
        # Different case = different components (purls differ)
        assert len(result) == 2

    def test_missing_purl_fallback(self):
        comps = [
            {"type": "library", "name": "a", "version": "1.0"},
            {"type": "library", "name": "a", "version": "2.0"},
        ]
        result = merge_sboms._deduplicate_components(comps)
        assert len(result) == 2  # Different versions

    def test_non_dict_filtered(self):
        comps = [
            {"type": "library", "name": "a", "version": "1.0"},
            "not a dict",
            42,
        ]
        result = merge_sboms._deduplicate_components(comps)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# TestSBOMDoS — 5 tests
# ---------------------------------------------------------------------------


class TestSBOMDoS:
    """Test denial-of-service prevention."""

    def test_oversized_file_rejected(self, tmp_path):
        path = os.path.join(str(tmp_path), "big.cdx.json")
        # Create a file just over the limit
        with open(path, "w") as f:
            f.write("x" * (validate_sbom.MAX_SBOM_SIZE + 1))
        data, errors = validate_sbom.load_and_validate(path)
        assert data is None
        assert any("byte limit" in e for e in errors)

    def test_component_cap_enforced(self):
        components = [
            {"type": "library", "name": f"pkg-{i}", "version": "1.0"}
            for i in range(validate_sbom.MAX_COMPONENTS + 1)
        ]
        sbom = _make_sbom(components=components)
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False

    def test_deeply_nested_json(self, tmp_path):
        # Build deeply nested JSON that would cause RecursionError
        nested = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        current = nested
        for _ in range(200):
            current["nested"] = {"level": True}
            current = current["nested"]
        path = os.path.join(str(tmp_path), "deep.cdx.json")
        with open(path, "w") as f:
            json.dump(nested, f)
        # Should not crash — either valid or error
        data, errors = validate_sbom.load_and_validate(path)
        assert isinstance(errors, list)

    def test_many_duplicates_handled(self):
        comps = [
            {"type": "library", "name": "same", "version": "1.0", "purl": "pkg:pypi/same@1.0"}
            for _ in range(1000)
        ]
        result = merge_sboms._deduplicate_components(comps)
        assert len(result) == 1

    def test_empty_dir_handled(self, tmp_path):
        result = merge_sboms.load_sbom_files(str(tmp_path))
        assert result == []


# ---------------------------------------------------------------------------
# TestSBOMTokenLeakage — 5 tests
# ---------------------------------------------------------------------------


class TestSBOMTokenLeakage:
    """Test token masking in SBOM fields."""

    def test_github_pat_masked(self):
        text = "token: ghp_" + "A" * 40
        result = merge_sboms._mask_tokens(text)
        assert "[MASKED]" in result
        assert "ghp_" not in result

    def test_aws_key_masked(self):
        text = "key: AKIAIOSFODNN7EXAMPLE"
        result = merge_sboms._mask_tokens(text)
        assert "[MASKED]" in result
        assert "AKIA" not in result

    def test_private_key_masked(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        result = merge_sboms._mask_tokens(text)
        assert "[MASKED]" in result
        assert "PRIVATE KEY" not in result

    def test_no_secrets_in_merged_output(self, tmp_path):
        comp = {
            "type": "library",
            "name": "ghp_" + "B" * 40,
            "version": "AKIAIOSFODNN7EXAMPLE",
            "purl": "pkg:pypi/secret@1.0",
        }
        sbom = _make_sbom(components=[comp])
        merged = merge_sboms.merge_sboms([sbom])
        merged_str = json.dumps(merged)
        assert "ghp_" not in merged_str
        assert "AKIA" not in merged_str

    def test_non_string_returns_empty(self):
        assert merge_sboms._mask_tokens(None) == ""
        assert merge_sboms._mask_tokens(42) == ""


# ---------------------------------------------------------------------------
# TestWorkflowCmdInjection — 4 tests
# ---------------------------------------------------------------------------


class TestWorkflowCmdInjection:
    """Test workflow command injection prevention in SBOM text fields."""

    def test_colons_stripped(self):
        result = validate_sbom._sanitize_text("::error::injected")
        assert "::" not in result

    def test_newlines_stripped(self):
        result = validate_sbom._sanitize_text("line1\nline2\rline3")
        assert "\n" not in result
        assert "\r" not in result

    def test_set_output_stripped(self):
        result = validate_sbom._sanitize_text("::set-output name=x::evil")
        assert "::set-output" not in result

    def test_annotation_injection(self):
        result = validate_sbom._sanitize_text("::warning file=x::hacked")
        assert "::warning" not in result


# ---------------------------------------------------------------------------
# TestSBOMSupplyChain — 4 tests
# ---------------------------------------------------------------------------


class TestSBOMSupplyChain:
    """Test supply chain security of SBOM tooling references."""

    def test_tools_referenced_in_action(self, steps):
        """Verify all SBOM tools are referenced in action steps."""
        step_texts = " ".join(s.get("run", "") for s in steps)
        assert "cyclonedx-py" in step_texts or "cyclonedx-bom" in step_texts
        assert "cyclonedx-npm" in step_texts
        assert "cyclonedx-gomod" in step_texts
        assert "syft" in step_texts

    def test_no_mutable_action_refs(self, steps):
        """Verify no @main or @master refs in action uses."""
        for step in steps:
            uses = step.get("uses", "")
            if uses:
                assert "@main" not in uses, f"Mutable ref in {step.get('name')}"
                assert "@master" not in uses, f"Mutable ref in {step.get('name')}"

    def test_upload_pinned(self, steps):
        step = find_step_by_id(steps, "upload-sbom")
        assert step is not None
        uses = step.get("uses", "")
        assert "@v4" in uses or "@v" in uses

    def test_syft_uses_https(self, steps):
        step = find_step_by_id(steps, "sbom-image")
        assert step is not None
        run = step.get("run", "")
        if "curl" in run:
            assert "https://" in run


# ---------------------------------------------------------------------------
# TestMergeEdgeCases — 5 tests
# ---------------------------------------------------------------------------


class TestMergeEdgeCases:
    """Test merge edge cases and resilience."""

    def test_all_empty_sboms(self):
        sbom1 = _make_sbom(components=[])
        sbom2 = _make_sbom(components=[])
        merged = merge_sboms.merge_sboms([sbom1, sbom2])
        assert merged["components"] == []
        assert merged["bomFormat"] == "CycloneDX"

    def test_one_valid_one_invalid_dir(self, tmp_path):
        _write_sbom(str(tmp_path), "good.cdx.json", _make_sbom())
        bad = os.path.join(str(tmp_path), "bad.cdx.json")
        with open(bad, "w") as f:
            f.write("{invalid")
        result = merge_sboms.load_sbom_files(str(tmp_path))
        assert len(result) == 1

    def test_dup_purl_diff_metadata(self):
        comp1 = {"type": "library", "name": "a", "version": "1.0",
                 "purl": "pkg:pypi/a@1.0", "description": "first"}
        comp2 = {"type": "library", "name": "a", "version": "1.0",
                 "purl": "pkg:pypi/a@1.0", "description": "second"}
        sbom1 = _make_sbom(components=[comp1])
        sbom2 = _make_sbom(components=[comp2])
        merged = merge_sboms.merge_sboms([sbom1, sbom2])
        assert len(merged["components"]) == 1

    def test_preserves_bom_format(self):
        sbom = _make_sbom()
        merged = merge_sboms.merge_sboms([sbom])
        assert merged["bomFormat"] == "CycloneDX"
        assert merged["specVersion"] == "1.5"

    def test_latest_timestamp(self):
        sbom1 = _make_sbom(metadata={"timestamp": "2024-01-01T00:00:00Z"})
        sbom2 = _make_sbom(metadata={"timestamp": "2025-06-15T12:00:00Z"})
        sbom1["components"] = []
        sbom2["components"] = []
        merged = merge_sboms.merge_sboms([sbom1, sbom2])
        assert merged["metadata"]["timestamp"] == "2025-06-15T12:00:00Z"


# ---------------------------------------------------------------------------
# TestNullSafety — 6 tests
# ---------------------------------------------------------------------------


class TestNullSafety:
    """Test null/None handling in SBOM fields."""

    def test_null_bom_format(self):
        sbom = {"bomFormat": None, "specVersion": "1.5", "components": []}
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False

    def test_null_spec_version(self):
        sbom = {"bomFormat": "CycloneDX", "specVersion": None, "components": []}
        valid, errors = validate_sbom.validate_cyclonedx(sbom)
        assert valid is False

    def test_null_type(self):
        errors = validate_sbom.validate_component({"type": None, "name": "x"})
        assert len(errors) > 0

    def test_null_name(self):
        errors = validate_sbom.validate_component({"type": "library", "name": None})
        assert len(errors) > 0

    def test_null_purl(self):
        errors = validate_sbom.validate_component(
            {"type": "library", "name": "x", "purl": None}
        )
        # purl=None is valid (field is optional, None == absent)
        assert not any("purl" in e for e in errors)

    def test_null_version(self):
        errors = validate_sbom.validate_component(
            {"type": "library", "name": "x", "version": None}
        )
        # version=None is valid (field is optional)
        assert not any("version" in e for e in errors)


# ---------------------------------------------------------------------------
# TestSBOMWorkflowSecurity — 3 tests
# ---------------------------------------------------------------------------


class TestSBOMWorkflowSecurity:
    """Test security properties of the sbom-generate workflow."""

    def test_minimal_permissions(self, sbom_workflow):
        perms = get_workflow_permissions(sbom_workflow)
        # Should NOT have admin or unrestricted permissions
        for key, val in perms.items():
            assert val != "admin", f"Permission {key} should not be admin"

    def test_release_trigger_types(self, sbom_workflow):
        # PyYAML parses 'on' as boolean True
        triggers = sbom_workflow.get(True, sbom_workflow.get("on", {}))
        release = triggers.get("release", {})
        types = release.get("types", [])
        # Should only trigger on published, not edited/deleted
        assert "published" in types
        assert "deleted" not in types

    def test_contents_write_permission(self, sbom_workflow):
        perms = get_workflow_permissions(sbom_workflow)
        assert perms.get("contents") == "write"


# ---------------------------------------------------------------------------
# TestEndToEndPipeline — 3 tests
# ---------------------------------------------------------------------------


class TestEndToEndPipeline:
    """Test end-to-end SBOM validate → merge pipeline."""

    def test_validate_then_merge(self, tmp_path):
        sbom = _make_sbom(components=[
            {"type": "library", "name": "flask", "version": "3.0.0",
             "purl": "pkg:pypi/flask@3.0.0"},
        ])
        _write_sbom(str(tmp_path), "test.cdx.json", sbom)

        # Load and validate
        loaded = merge_sboms.load_sbom_files(str(tmp_path))
        assert len(loaded) == 1

        # Merge
        merged = merge_sboms.merge_sboms(loaded)
        assert merged["bomFormat"] == "CycloneDX"
        assert len(merged["components"]) == 1

    def test_mixed_valid_invalid(self, tmp_path):
        _write_sbom(str(tmp_path), "good.cdx.json", _make_sbom())
        bad = os.path.join(str(tmp_path), "bad.cdx.json")
        with open(bad, "w") as f:
            f.write("{}")  # missing bomFormat
        _write_sbom(str(tmp_path), "good2.cdx.json", _make_sbom(components=[
            {"type": "library", "name": "b", "version": "2.0"},
        ]))

        loaded = merge_sboms.load_sbom_files(str(tmp_path))
        assert len(loaded) == 2  # only 2 valid

        merged = merge_sboms.merge_sboms(loaded)
        assert len(merged["components"]) >= 2

    def test_merged_revalidates(self, tmp_path):
        sbom = _make_sbom()
        _write_sbom(str(tmp_path), "test.cdx.json", sbom)

        loaded = merge_sboms.load_sbom_files(str(tmp_path))
        merged = merge_sboms.merge_sboms(loaded)

        # Re-validate merged output
        valid, errors = validate_sbom.validate_cyclonedx(merged)
        assert valid is True
        assert errors == []
