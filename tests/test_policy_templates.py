"""Unit tests for SHIELD-12: Security Policy Templates.

Tests template file existence, placeholder variables, security.txt RFC 9116
compliance, VDP template structure, well-known route handler, sanitization,
and markdown structure.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
POLICIES_DIR = TEMPLATES_DIR / "policies"

# All 9 SOC 2/ISO 27001 policy templates
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


# ---------------------------------------------------------------------------
# TestTemplateFilesExist — 11 tests
# ---------------------------------------------------------------------------


class TestTemplateFilesExist:
    """Verify all required template files exist on disk."""

    @pytest.mark.parametrize("filename", POLICY_FILES)
    def test_policy_file_exists(self, filename: str):
        path = POLICIES_DIR / filename
        assert path.is_file(), f"Policy template missing: {path}"

    def test_security_txt_exists(self):
        path = TEMPLATES_DIR / "security.txt"
        assert path.is_file(), "security.txt template missing"

    def test_vulnerability_disclosure_exists(self):
        path = POLICIES_DIR / "vulnerability-disclosure.md"
        assert path.is_file(), "vulnerability-disclosure.md template missing"


# ---------------------------------------------------------------------------
# TestTemplatePlaceholders — 9 tests
# ---------------------------------------------------------------------------


class TestTemplatePlaceholders:
    """Each policy template must contain required placeholders."""

    @pytest.mark.parametrize("filename", POLICY_FILES)
    def test_has_company_name_and_effective_date(self, filename: str):
        content = (POLICIES_DIR / filename).read_text(encoding="utf-8")
        assert "{{COMPANY_NAME}}" in content, f"{filename} missing {{{{COMPANY_NAME}}}}"
        assert "{{EFFECTIVE_DATE}}" in content, f"{filename} missing {{{{EFFECTIVE_DATE}}}}"


# ---------------------------------------------------------------------------
# TestSecurityTxtTemplate — 5 tests
# ---------------------------------------------------------------------------


class TestSecurityTxtTemplate:
    """RFC 9116 security.txt template must contain required fields."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = (TEMPLATES_DIR / "security.txt").read_text(encoding="utf-8")

    def test_has_contact_field(self):
        assert "Contact:" in self.content

    def test_has_expires_field(self):
        assert "Expires:" in self.content

    def test_has_encryption_field(self):
        assert "Encryption:" in self.content

    def test_has_preferred_languages_field(self):
        assert "Preferred-Languages:" in self.content

    def test_has_canonical_field(self):
        assert "Canonical:" in self.content


# ---------------------------------------------------------------------------
# TestVDPTemplate — 4 tests
# ---------------------------------------------------------------------------


class TestVDPTemplate:
    """Vulnerability disclosure template must have required sections."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = (POLICIES_DIR / "vulnerability-disclosure.md").read_text(encoding="utf-8")

    def test_has_scope_section(self):
        assert "## 2. Scope" in self.content or "Scope" in self.content

    def test_has_safe_harbor_section(self):
        assert "Safe Harbor" in self.content

    def test_has_reporting_section(self):
        assert "Reporting" in self.content or "How to Report" in self.content

    def test_has_response_timeline(self):
        assert "Timeline" in self.content or "Response" in self.content


# ---------------------------------------------------------------------------
# TestWellKnownRoute — 8 tests
# ---------------------------------------------------------------------------


def _make_client_with_config(config: dict | None = None):
    """Create a test client with a mocked customer config service."""
    from proxy.api.well_known_routes import invalidate_template_cache
    invalidate_template_cache()

    import proxy.main as main_module
    main_module._pipeline = None
    main_module._http_client = None

    from proxy.main import app

    mock_service = MagicMock()
    if config is not None:
        mock_service.get_config.return_value = config
    else:
        # Default: feature disabled
        mock_service.get_config.return_value = {
            "enabled_features": {"security_txt": False},
            "settings": {},
        }

    with patch("proxy.api.well_known_routes.get_config_service", return_value=mock_service):
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c, mock_service


class TestWellKnownRoute:
    """Test GET /.well-known/security.txt route handler."""

    def test_returns_200_when_enabled(self):
        config = {
            "enabled_features": {"security_txt": True},
            "settings": {"security_txt": {"SECURITY_CONTACT": "security@example.com"}},
        }
        gen = _make_client_with_config(config)
        client, _ = next(gen)
        resp = client.get("/.well-known/security.txt", headers={"Host": "app.example.com"})
        assert resp.status_code == 200
        try:
            next(gen)
        except StopIteration:
            pass

    def test_returns_404_when_disabled(self):
        config = {
            "enabled_features": {"security_txt": False},
            "settings": {},
        }
        gen = _make_client_with_config(config)
        client, _ = next(gen)
        resp = client.get("/.well-known/security.txt", headers={"Host": "app.example.com"})
        assert resp.status_code == 404
        try:
            next(gen)
        except StopIteration:
            pass

    def test_content_type_is_plain_text(self):
        config = {
            "enabled_features": {"security_txt": True},
            "settings": {"security_txt": {}},
        }
        gen = _make_client_with_config(config)
        client, _ = next(gen)
        resp = client.get("/.well-known/security.txt", headers={"Host": "app.example.com"})
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("content-type", "")
        try:
            next(gen)
        except StopIteration:
            pass

    def test_placeholder_replacement(self):
        config = {
            "enabled_features": {"security_txt": True},
            "settings": {
                "security_txt": {
                    "SECURITY_CONTACT": "mailto:sec@acme.com",
                    "SECURITY_TXT_EXPIRES": "2027-01-01T00:00:00Z",
                }
            },
        }
        gen = _make_client_with_config(config)
        client, _ = next(gen)
        resp = client.get("/.well-known/security.txt", headers={"Host": "app.example.com"})
        assert resp.status_code == 200
        body = resp.text
        assert "mailto:sec@acme.com" in body
        assert "2027-01-01T00:00:00Z" in body
        try:
            next(gen)
        except StopIteration:
            pass

    def test_host_lookup(self):
        """Route uses Host header to look up customer config."""
        config = {
            "enabled_features": {"security_txt": True},
            "settings": {"security_txt": {}},
        }
        gen = _make_client_with_config(config)
        client, mock_svc = next(gen)
        client.get("/.well-known/security.txt", headers={"Host": "tenant.example.com"})
        mock_svc.get_config.assert_called_with("tenant.example.com")
        try:
            next(gen)
        except StopIteration:
            pass

    def test_defaults_when_no_security_txt_settings(self):
        """If settings.security_txt is missing, template is served with unreplaced placeholders."""
        config = {
            "enabled_features": {"security_txt": True},
            "settings": {},
        }
        gen = _make_client_with_config(config)
        client, _ = next(gen)
        resp = client.get("/.well-known/security.txt", headers={"Host": "app.example.com"})
        assert resp.status_code == 200
        # Unreplaced placeholders remain
        assert "{{SECURITY_CONTACT}}" in resp.text
        try:
            next(gen)
        except StopIteration:
            pass

    def test_cache_control_header(self):
        config = {
            "enabled_features": {"security_txt": True},
            "settings": {"security_txt": {}},
        }
        gen = _make_client_with_config(config)
        client, _ = next(gen)
        resp = client.get("/.well-known/security.txt", headers={"Host": "app.example.com"})
        assert resp.status_code == 200
        assert resp.headers.get("cache-control") == "max-age=86400"
        try:
            next(gen)
        except StopIteration:
            pass

    def test_unknown_domain_returns_404(self):
        """Unknown domain falls back to default config where security_txt is disabled."""
        # The default config has security_txt disabled
        from proxy.config.customer_config import _DEFAULT_CONFIG
        gen = _make_client_with_config(dict(_DEFAULT_CONFIG))
        client, _ = next(gen)
        resp = client.get("/.well-known/security.txt", headers={"Host": "unknown.example.com"})
        assert resp.status_code == 404
        try:
            next(gen)
        except StopIteration:
            pass


# ---------------------------------------------------------------------------
# TestPlaceholderSanitization — 4 tests
# ---------------------------------------------------------------------------


class TestPlaceholderSanitization:
    """Test _sanitize_field function for injection prevention."""

    def test_strips_newlines(self):
        from proxy.api.well_known_routes import _sanitize_field
        assert _sanitize_field("line1\nline2\r\n") == "line1line2"

    def test_strips_null_bytes(self):
        from proxy.api.well_known_routes import _sanitize_field
        assert _sanitize_field("hello\x00world") == "helloworld"

    def test_caps_length(self):
        from proxy.api.well_known_routes import _sanitize_field
        long_value = "A" * 1000
        result = _sanitize_field(long_value)
        assert len(result) == 500

    def test_empty_for_non_string(self):
        from proxy.api.well_known_routes import _sanitize_field
        assert _sanitize_field(123) == ""  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestTemplateMarkdown — 4 tests
# ---------------------------------------------------------------------------


class TestTemplateMarkdown:
    """Verify markdown template structure."""

    @pytest.mark.parametrize("filename", POLICY_FILES)
    def test_has_h1_header(self, filename: str):
        content = (POLICIES_DIR / filename).read_text(encoding="utf-8")
        assert content.startswith("# "), f"{filename} missing H1 header"

    @pytest.mark.parametrize("filename", POLICY_FILES)
    def test_no_raw_html(self, filename: str):
        content = (POLICIES_DIR / filename).read_text(encoding="utf-8")
        # Allow markdown tables (|) but no HTML tags
        html_tags = re.findall(r"<(?!!)(?!/)\s*[a-zA-Z]+[^>]*>", content)
        assert len(html_tags) == 0, f"{filename} contains raw HTML: {html_tags}"

    @pytest.mark.parametrize("filename", POLICY_FILES)
    def test_has_numbered_sections(self, filename: str):
        content = (POLICIES_DIR / filename).read_text(encoding="utf-8")
        assert "## 1." in content, f"{filename} missing numbered sections"

    @pytest.mark.parametrize("filename", POLICY_FILES)
    def test_has_review_section(self, filename: str):
        content = (POLICIES_DIR / filename).read_text(encoding="utf-8")
        assert "Review" in content, f"{filename} missing review section"
