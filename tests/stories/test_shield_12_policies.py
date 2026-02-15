"""Story acceptance tests for SHIELD-12: Security Policy Templates.

Story 12.1 (SHIELD-32): 9 SOC 2/ISO 27001 security policy templates
Story 12.2 (SHIELD-33): RFC 9116 security.txt + vulnerability disclosure

Each test class maps to an acceptance criterion (AC) from the stories.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"
POLICIES_DIR = TEMPLATES_DIR / "policies"

POLICY_FILES = [
    "information-security-policy.md",
    "access-control-policy.md",
    "incident-response-plan.md",
    "data-classification-policy.md",
    "acceptable-use-policy.md",
    "change-management-policy.md",
    "vendor-management-policy.md",
    "bcdr-plan.md",
    "data-retention-schedule.md",
]

REQUIRED_PLACEHOLDERS = [
    "{{COMPANY_NAME}}",
    "{{EFFECTIVE_DATE}}",
    "{{REVIEW_DATE}}",
    "{{POLICY_OWNER}}",
    "{{SECURITY_CONTACT}}",
]


# ---------------------------------------------------------------------------
# AC1: 9 SOC 2/ISO 27001 policy templates exist
# ---------------------------------------------------------------------------


class TestAC1_PolicyTemplatesExist:
    """AC1: All 9 required policy templates must be present."""

    def test_nine_policy_templates_present(self):
        existing = [f for f in POLICY_FILES if (POLICIES_DIR / f).is_file()]
        assert len(existing) == 9, f"Expected 9 policies, found {len(existing)}"

    def test_all_are_markdown(self):
        for f in POLICY_FILES:
            assert f.endswith(".md"), f"Policy {f} is not markdown"


# ---------------------------------------------------------------------------
# AC2: Templates use {{PLACEHOLDER}} variables
# ---------------------------------------------------------------------------


class TestAC2_PlaceholderVariables:
    """AC2: Templates must use substitutable placeholder variables."""

    @pytest.mark.parametrize("filename", POLICY_FILES)
    def test_contains_all_required_placeholders(self, filename: str):
        content = (POLICIES_DIR / filename).read_text(encoding="utf-8")
        for placeholder in REQUIRED_PLACEHOLDERS:
            assert placeholder in content, f"{filename} missing {placeholder}"

    def test_placeholders_use_double_braces(self):
        """Placeholders must use {{VAR}} format (not Jinja2 or other)."""
        for filename in POLICY_FILES:
            content = (POLICIES_DIR / filename).read_text(encoding="utf-8")
            matches = re.findall(r"\{\{[A-Z_]+\}\}", content)
            assert len(matches) >= 3, f"{filename} has too few {{{{PLACEHOLDER}}}} vars"


# ---------------------------------------------------------------------------
# AC3: Templates cover SOC 2 / ISO 27001 domains
# ---------------------------------------------------------------------------


class TestAC3_ComplianceCoverage:
    """AC3: Templates must cover key compliance domains."""

    def test_information_security_policy_covers_isms(self):
        content = (POLICIES_DIR / "information-security-policy.md").read_text()
        assert "confidentiality" in content.lower()
        assert "integrity" in content.lower()
        assert "availability" in content.lower()

    def test_access_control_covers_mfa(self):
        content = (POLICIES_DIR / "access-control-policy.md").read_text()
        assert "MFA" in content or "multi-factor" in content.lower()

    def test_incident_response_covers_72h(self):
        content = (POLICIES_DIR / "incident-response-plan.md").read_text()
        assert "72" in content  # GDPR 72-hour notification

    def test_change_management_covers_code_review(self):
        content = (POLICIES_DIR / "change-management-policy.md").read_text()
        assert "code review" in content.lower() or "pull request" in content.lower()

    def test_bcdr_covers_rto_rpo(self):
        content = (POLICIES_DIR / "bcdr-plan.md").read_text()
        assert "RTO" in content
        assert "RPO" in content


# ---------------------------------------------------------------------------
# AC4: RFC 9116 security.txt template
# ---------------------------------------------------------------------------


class TestAC4_SecurityTxtRFC9116:
    """AC4: security.txt template must comply with RFC 9116."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = (TEMPLATES_DIR / "security.txt").read_text(encoding="utf-8")

    def test_contact_field_present(self):
        assert "Contact:" in self.content

    def test_expires_field_present(self):
        assert "Expires:" in self.content

    def test_policy_field_present(self):
        assert "Policy:" in self.content

    def test_is_plain_text_format(self):
        """RFC 9116 requires plain text, not HTML or JSON."""
        assert not self.content.strip().startswith("<")
        assert not self.content.strip().startswith("{")


# ---------------------------------------------------------------------------
# AC5: Vulnerability disclosure policy
# ---------------------------------------------------------------------------


class TestAC5_VulnerabilityDisclosure:
    """AC5: VDP must include scope, safe harbor, and reporting instructions."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = (POLICIES_DIR / "vulnerability-disclosure.md").read_text()

    def test_defines_scope(self):
        assert "Scope" in self.content

    def test_safe_harbor_commitment(self):
        assert "Safe Harbor" in self.content
        assert "legal action" in self.content.lower() or "legal" in self.content.lower()

    def test_reporting_instructions(self):
        assert "{{SECURITY_CONTACT}}" in self.content

    def test_response_timeline_sla(self):
        # Must define response timelines
        assert "business day" in self.content.lower() or "days" in self.content.lower()


# ---------------------------------------------------------------------------
# AC6: security.txt served at /.well-known/security.txt
# ---------------------------------------------------------------------------


class TestAC6_WellKnownEndpoint:
    """AC6: security.txt must be served at the well-known URL path."""

    def _make_client(self, enabled: bool = True, values: dict | None = None):
        from proxy.api.well_known_routes import invalidate_template_cache
        invalidate_template_cache()

        import proxy.main as main_module
        main_module._pipeline = None
        main_module._http_client = None

        from proxy.main import app

        config = {
            "enabled_features": {"security_txt": enabled},
            "settings": {"security_txt": values or {}},
        }
        mock_service = MagicMock()
        mock_service.get_config.return_value = config

        return app, mock_service

    def test_endpoint_path(self):
        app, mock_svc = self._make_client(enabled=True)
        with patch("proxy.api.well_known_routes.get_config_service", return_value=mock_svc):
            with TestClient(app, raise_server_exceptions=False) as c:
                resp = c.get("/.well-known/security.txt")
                assert resp.status_code == 200

    def test_no_auth_required(self):
        """Well-known endpoint must be public (no API key)."""
        app, mock_svc = self._make_client(enabled=True)
        with patch("proxy.api.well_known_routes.get_config_service", return_value=mock_svc):
            with TestClient(app, raise_server_exceptions=False) as c:
                # No Authorization header
                resp = c.get("/.well-known/security.txt")
                assert resp.status_code == 200


# ---------------------------------------------------------------------------
# AC7: Feature-flag gated
# ---------------------------------------------------------------------------


class TestAC7_FeatureFlag:
    """AC7: security.txt endpoint must respect feature flag."""

    def _make_client(self, enabled: bool):
        from proxy.api.well_known_routes import invalidate_template_cache
        invalidate_template_cache()

        import proxy.main as main_module
        main_module._pipeline = None
        main_module._http_client = None

        from proxy.main import app

        config = {
            "enabled_features": {"security_txt": enabled},
            "settings": {"security_txt": {}},
        }
        mock_service = MagicMock()
        mock_service.get_config.return_value = config

        return app, mock_service

    def test_enabled_returns_200(self):
        app, mock_svc = self._make_client(enabled=True)
        with patch("proxy.api.well_known_routes.get_config_service", return_value=mock_svc):
            with TestClient(app, raise_server_exceptions=False) as c:
                resp = c.get("/.well-known/security.txt")
                assert resp.status_code == 200

    def test_disabled_returns_404(self):
        app, mock_svc = self._make_client(enabled=False)
        with patch("proxy.api.well_known_routes.get_config_service", return_value=mock_svc):
            with TestClient(app, raise_server_exceptions=False) as c:
                resp = c.get("/.well-known/security.txt")
                assert resp.status_code == 404
