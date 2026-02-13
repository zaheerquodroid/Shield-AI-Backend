"""Tests for customer and app Pydantic models."""

from __future__ import annotations

from proxy.models.customer import (
    AppCreate,
    AppUpdate,
    CustomerCreate,
    CustomerUpdate,
    EnabledFeatures,
)


class TestEnabledFeaturesDefaults:
    """EnabledFeatures should have correct defaults."""

    def test_all_defaults(self):
        f = EnabledFeatures()
        assert f.waf is True
        assert f.error_sanitization is True
        assert f.session_validation is True
        assert f.audit_logging is True
        assert f.rate_limiting is True
        assert f.security_headers is True
        assert f.bot_protection is False

    def test_override_single_flag(self):
        f = EnabledFeatures(rate_limiting=False)
        assert f.rate_limiting is False
        assert f.waf is True  # others unchanged

    def test_override_multiple_flags(self):
        f = EnabledFeatures(waf=False, security_headers=False, bot_protection=True)
        assert f.waf is False
        assert f.security_headers is False
        assert f.bot_protection is True
        assert f.rate_limiting is True

    def test_model_dump(self):
        f = EnabledFeatures()
        d = f.model_dump()
        assert isinstance(d, dict)
        assert len(d) == 7
        assert d["rate_limiting"] is True
        assert d["bot_protection"] is False


class TestAppCreate:
    def test_defaults(self):
        app = AppCreate(name="My App", origin_url="https://example.com", domain="example.com")
        assert app.enabled_features.waf is True
        assert app.enabled_features.rate_limiting is True
        assert app.enabled_features.security_headers is True
        assert app.settings == {}

    def test_custom_features(self):
        app = AppCreate(
            name="My App",
            origin_url="https://example.com",
            domain="example.com",
            enabled_features=EnabledFeatures(rate_limiting=False),
        )
        assert app.enabled_features.rate_limiting is False
        assert app.enabled_features.waf is True


class TestAppUpdate:
    def test_all_none_by_default(self):
        update = AppUpdate()
        assert update.name is None
        assert update.origin_url is None
        assert update.domain is None
        assert update.enabled_features is None
        assert update.settings is None

    def test_partial_update(self):
        update = AppUpdate(name="New Name")
        assert update.name == "New Name"
        assert update.origin_url is None


class TestCustomerCreate:
    def test_defaults(self):
        c = CustomerCreate(name="Acme", api_key="secret")
        assert c.plan == "starter"
        assert c.settings == {}

    def test_custom_plan(self):
        c = CustomerCreate(name="Acme", api_key="secret", plan="enterprise")
        assert c.plan == "enterprise"


class TestCustomerUpdate:
    def test_all_none_by_default(self):
        update = CustomerUpdate()
        assert update.name is None
        assert update.plan is None
        assert update.settings is None
