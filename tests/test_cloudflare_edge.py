"""Unit tests for Cloudflare Edge Security Terraform module.

Tests HCL structure for WAF managed rulesets, rate limiting rules,
security header transform rules, zone settings, DNS records,
variables, and outputs for the cloudflare-edge Terraform module.
"""

from __future__ import annotations

import pytest

from tests.helpers.terraform import (
    find_outputs,
    find_resource,
    find_resources,
    find_variables,
    parse_cloudflare_edge_module,
    parse_root_module,
    find_modules,
    requires_hcl2,
)


# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    """Parse the cloudflare-edge module once for all tests."""
    return parse_cloudflare_edge_module()


@pytest.fixture(scope="module")
def variables(parsed):
    """All module variables."""
    return find_variables(parsed)


@pytest.fixture(scope="module")
def outputs(parsed):
    """All module outputs."""
    return find_outputs(parsed)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_ruleset_by_phase(parsed, phase: str) -> dict:
    """Find a cloudflare_ruleset resource by its phase attribute.

    Returns the resource attrs dict (the inner dict, not the {name: attrs}
    wrapper).  Raises AssertionError when no match is found.
    """
    rulesets = find_resources(parsed, "cloudflare_ruleset")
    for rs in rulesets:
        for _name, attrs in rs.items():
            if attrs.get("phase") == phase:
                return attrs
    raise AssertionError(f"No cloudflare_ruleset with phase={phase!r} found")


def _find_ruleset_by_name_key(parsed, resource_name: str) -> dict:
    """Find a cloudflare_ruleset by its Terraform resource name key."""
    return find_resource(parsed, "cloudflare_ruleset", resource_name)


def _get_all_waf_rule_descriptions(waf_attrs: dict) -> list[str]:
    """Collect rule descriptions from both static rules and dynamic blocks."""
    descriptions: list[str] = []

    # Static rules
    for rule in waf_attrs.get("rules", []):
        desc = rule.get("description", "")
        if desc:
            descriptions.append(desc)

    # Dynamic rules blocks
    for dyn in waf_attrs.get("dynamic", []):
        if "rules" in dyn:
            content = dyn["rules"].get("content", [])
            for entry in content:
                desc = entry.get("description", "")
                if desc:
                    descriptions.append(desc)

    return descriptions


def _get_all_waf_rules(waf_attrs: dict) -> list[dict]:
    """Collect all rule dicts from static and dynamic blocks."""
    rules: list[dict] = list(waf_attrs.get("rules", []))

    for dyn in waf_attrs.get("dynamic", []):
        if "rules" in dyn:
            content = dyn["rules"].get("content", [])
            rules.extend(content)

    return rules


def _get_headers_list(headers_attrs: dict) -> list[dict]:
    """Extract the list of header dicts from the security_headers ruleset."""
    rules = headers_attrs.get("rules", [])
    if not rules:
        return []
    action_params = rules[0].get("action_parameters", [])
    if not action_params:
        return []
    ap = action_params[0] if isinstance(action_params, list) else action_params
    return ap.get("headers", [])


def _find_header_by_name(headers: list[dict], name: str) -> dict | None:
    """Find a header dict by its name field."""
    for h in headers:
        if h.get("name") == name:
            return h
    return None


# =========================================================================
# TestWAFRulesets (~8 tests)
# =========================================================================
@requires_hcl2
class TestWAFRulesets:
    """Verify Cloudflare managed WAF ruleset resource structure."""

    def test_waf_ruleset_resource_exists(self, parsed):
        """At least one cloudflare_ruleset exists with the WAF phase."""
        rulesets = find_resources(parsed, "cloudflare_ruleset")
        waf_rulesets = []
        for rs in rulesets:
            for _name, attrs in rs.items():
                if attrs.get("phase") == "http_request_firewall_managed":
                    waf_rulesets.append(attrs)
        assert len(waf_rulesets) >= 1, (
            "Expected at least one cloudflare_ruleset with "
            "phase=http_request_firewall_managed"
        )

    def test_waf_phase_is_firewall_managed(self, parsed):
        """WAF ruleset phase must be http_request_firewall_managed."""
        waf = _find_ruleset_by_name_key(parsed, "waf")
        assert waf["phase"] == "http_request_firewall_managed"

    def test_waf_kind_is_zone(self, parsed):
        """WAF ruleset kind must be 'zone'."""
        waf = _find_ruleset_by_name_key(parsed, "waf")
        assert waf["kind"] == "zone"

    def test_waf_has_cf_managed_ruleset_rule(self, parsed):
        """WAF contains a rule for the Cloudflare Managed Ruleset."""
        waf = _find_ruleset_by_name_key(parsed, "waf")
        descriptions = _get_all_waf_rule_descriptions(waf)
        assert any(
            "Cloudflare Managed Ruleset" in d for d in descriptions
        ), f"Expected 'Cloudflare Managed Ruleset' rule, got descriptions: {descriptions}"

    def test_waf_has_owasp_ruleset_rule(self, parsed):
        """WAF contains a dynamic rule for the OWASP Core Ruleset."""
        waf = _find_ruleset_by_name_key(parsed, "waf")
        descriptions = _get_all_waf_rule_descriptions(waf)
        assert any(
            "OWASP" in d for d in descriptions
        ), f"Expected an OWASP rule, got descriptions: {descriptions}"

    def test_waf_has_credentials_check_rule(self, parsed):
        """WAF contains a dynamic rule for Exposed Credentials Check."""
        waf = _find_ruleset_by_name_key(parsed, "waf")
        descriptions = _get_all_waf_rule_descriptions(waf)
        assert any(
            "Credentials" in d or "credentials" in d.lower() for d in descriptions
        ), f"Expected a credentials check rule, got descriptions: {descriptions}"

    def test_waf_action_references_local(self, parsed):
        """All WAF rules use 'execute' action with action_parameters.id."""
        waf = _find_ruleset_by_name_key(parsed, "waf")
        all_rules = _get_all_waf_rules(waf)
        assert len(all_rules) >= 1, "WAF should have at least one rule"
        for rule in all_rules:
            assert rule.get("action") == "execute", (
                f"Expected action='execute', got {rule.get('action')!r}"
            )
            ap = rule.get("action_parameters", [])
            ap_dict = ap[0] if isinstance(ap, list) and ap else ap
            assert "id" in ap_dict, (
                "action_parameters should contain 'id' referencing a managed ruleset"
            )

    def test_waf_name_includes_environment(self, parsed):
        """WAF ruleset name includes the environment variable reference."""
        waf = _find_ruleset_by_name_key(parsed, "waf")
        name = waf.get("name", "")
        assert "var.environment" in name, (
            f"WAF name should contain var.environment, got: {name!r}"
        )


# =========================================================================
# TestRateLimiting (~7 tests)
# =========================================================================
@requires_hcl2
class TestRateLimiting:
    """Verify Cloudflare rate limiting ruleset resource structure."""

    def test_rate_limiting_ruleset_exists(self, parsed):
        """A cloudflare_ruleset named 'rate_limiting' exists."""
        rl = _find_ruleset_by_name_key(parsed, "rate_limiting")
        assert rl is not None

    def test_rate_limiting_phase(self, parsed):
        """Rate limiting phase must be http_ratelimit."""
        rl = _find_ruleset_by_name_key(parsed, "rate_limiting")
        assert rl["phase"] == "http_ratelimit"

    def test_rate_limiting_has_auth_rule(self, parsed):
        """Rate limiting contains an auth endpoint rule."""
        rl = _find_ruleset_by_name_key(parsed, "rate_limiting")
        rules = rl.get("rules", [])
        descriptions = [r.get("description", "") for r in rules]
        assert any(
            "auth" in d.lower() or "Auth" in d for d in descriptions
        ), f"Expected auth endpoint rule, got descriptions: {descriptions}"

    def test_rate_limiting_has_api_rule(self, parsed):
        """Rate limiting contains an API endpoint rule."""
        rl = _find_ruleset_by_name_key(parsed, "rate_limiting")
        rules = rl.get("rules", [])
        descriptions = [r.get("description", "") for r in rules]
        assert any(
            "api" in d.lower() or "API" in d for d in descriptions
        ), f"Expected API endpoint rule, got descriptions: {descriptions}"

    def test_rate_limiting_has_global_rule(self, parsed):
        """Rate limiting contains a global rate limit rule."""
        rl = _find_ruleset_by_name_key(parsed, "rate_limiting")
        rules = rl.get("rules", [])
        descriptions = [r.get("description", "") for r in rules]
        assert any(
            "global" in d.lower() or "Global" in d for d in descriptions
        ), f"Expected global rate limit rule, got descriptions: {descriptions}"

    def test_rate_limiting_auth_expression(self, parsed):
        """Auth rule expression contains login_path_pattern and /login."""
        rl = _find_ruleset_by_name_key(parsed, "rate_limiting")
        rules = rl.get("rules", [])
        auth_rule = None
        for rule in rules:
            desc = rule.get("description", "")
            if "auth" in desc.lower() or "Auth" in desc:
                auth_rule = rule
                break
        assert auth_rule is not None, "Auth rule not found"
        expr = auth_rule.get("expression", "")
        assert "login_path_pattern" in expr, (
            f"Auth expression should reference login_path_pattern, got: {expr!r}"
        )
        assert "/login" in expr, (
            f"Auth expression should contain /login, got: {expr!r}"
        )

    def test_rate_limiting_global_expression(self, parsed):
        """Global rate limit rule expression is 'true' (matches all)."""
        rl = _find_ruleset_by_name_key(parsed, "rate_limiting")
        rules = rl.get("rules", [])
        global_rule = None
        for rule in rules:
            desc = rule.get("description", "")
            if "global" in desc.lower() or "Global" in desc:
                global_rule = rule
                break
        assert global_rule is not None, "Global rule not found"
        assert global_rule.get("expression") == "true", (
            f"Global rule expression should be 'true', "
            f"got: {global_rule.get('expression')!r}"
        )


# =========================================================================
# TestSecurityHeaders (~8 tests)
# =========================================================================
@requires_hcl2
class TestSecurityHeaders:
    """Verify Cloudflare security header transform rules."""

    def test_headers_ruleset_exists(self, parsed):
        """A cloudflare_ruleset named 'security_headers' exists."""
        sh = _find_ruleset_by_name_key(parsed, "security_headers")
        assert sh is not None

    def test_headers_phase(self, parsed):
        """Security headers phase must be http_response_headers_transform."""
        sh = _find_ruleset_by_name_key(parsed, "security_headers")
        assert sh["phase"] == "http_response_headers_transform"

    def test_headers_has_hsts(self, parsed):
        """Security headers include Strict-Transport-Security."""
        sh = _find_ruleset_by_name_key(parsed, "security_headers")
        headers = _get_headers_list(sh)
        header = _find_header_by_name(headers, "Strict-Transport-Security")
        assert header is not None, (
            "Strict-Transport-Security header should be present"
        )
        assert header.get("operation") == "set"

    def test_headers_has_csp(self, parsed):
        """Security headers include Content-Security-Policy."""
        sh = _find_ruleset_by_name_key(parsed, "security_headers")
        headers = _get_headers_list(sh)
        header = _find_header_by_name(headers, "Content-Security-Policy")
        assert header is not None, (
            "Content-Security-Policy header should be present"
        )
        assert header.get("operation") == "set"

    def test_headers_has_x_frame_options(self, parsed):
        """Security headers include X-Frame-Options."""
        sh = _find_ruleset_by_name_key(parsed, "security_headers")
        headers = _get_headers_list(sh)
        header = _find_header_by_name(headers, "X-Frame-Options")
        assert header is not None, "X-Frame-Options header should be present"
        assert header.get("operation") == "set"

    def test_headers_has_x_content_type_options(self, parsed):
        """X-Content-Type-Options is set to 'nosniff'."""
        sh = _find_ruleset_by_name_key(parsed, "security_headers")
        headers = _get_headers_list(sh)
        header = _find_header_by_name(headers, "X-Content-Type-Options")
        assert header is not None, (
            "X-Content-Type-Options header should be present"
        )
        assert header.get("operation") == "set"
        assert header.get("value") == "nosniff", (
            f"X-Content-Type-Options value should be 'nosniff', "
            f"got: {header.get('value')!r}"
        )

    def test_headers_removes_server(self, parsed):
        """Server header has operation 'remove' to strip fingerprint."""
        sh = _find_ruleset_by_name_key(parsed, "security_headers")
        headers = _get_headers_list(sh)
        header = _find_header_by_name(headers, "Server")
        assert header is not None, "Server header should be present"
        assert header.get("operation") == "remove", (
            f"Server header operation should be 'remove', "
            f"got: {header.get('operation')!r}"
        )

    def test_headers_removes_x_powered_by(self, parsed):
        """X-Powered-By header has operation 'remove' to strip fingerprint."""
        sh = _find_ruleset_by_name_key(parsed, "security_headers")
        headers = _get_headers_list(sh)
        header = _find_header_by_name(headers, "X-Powered-By")
        assert header is not None, "X-Powered-By header should be present"
        assert header.get("operation") == "remove", (
            f"X-Powered-By header operation should be 'remove', "
            f"got: {header.get('operation')!r}"
        )


# =========================================================================
# TestZoneSettings (~6 tests)
# =========================================================================
@requires_hcl2
class TestZoneSettings:
    """Verify Cloudflare zone settings and bot management resources."""

    def test_zone_settings_resource_exists(self, parsed):
        """cloudflare_zone_settings_override resource exists."""
        resources = find_resources(parsed, "cloudflare_zone_settings_override")
        assert len(resources) >= 1, (
            "Expected at least one cloudflare_zone_settings_override resource"
        )

    def test_zone_ssl_mode_from_variable(self, parsed):
        """Zone SSL setting references var.ssl_mode."""
        zone = find_resource(
            parsed, "cloudflare_zone_settings_override", "security"
        )
        settings = zone.get("settings", [])
        settings_dict = settings[0] if isinstance(settings, list) else settings
        ssl_val = settings_dict.get("ssl", "")
        assert "var.ssl_mode" in ssl_val, (
            f"ssl should reference var.ssl_mode, got: {ssl_val!r}"
        )

    def test_zone_min_tls_from_variable(self, parsed):
        """Zone min_tls_version references var.min_tls_version."""
        zone = find_resource(
            parsed, "cloudflare_zone_settings_override", "security"
        )
        settings = zone.get("settings", [])
        settings_dict = settings[0] if isinstance(settings, list) else settings
        tls_val = settings_dict.get("min_tls_version", "")
        assert "var.min_tls_version" in tls_val, (
            f"min_tls_version should reference var.min_tls_version, "
            f"got: {tls_val!r}"
        )

    def test_zone_always_use_https(self, parsed):
        """Zone settings contain always_use_https configuration."""
        zone = find_resource(
            parsed, "cloudflare_zone_settings_override", "security"
        )
        settings = zone.get("settings", [])
        settings_dict = settings[0] if isinstance(settings, list) else settings
        assert "always_use_https" in settings_dict, (
            "Zone settings should contain always_use_https"
        )

    def test_zone_tls_13_enabled(self, parsed):
        """Zone settings enable TLS 1.3."""
        zone = find_resource(
            parsed, "cloudflare_zone_settings_override", "security"
        )
        settings = zone.get("settings", [])
        settings_dict = settings[0] if isinstance(settings, list) else settings
        assert settings_dict.get("tls_1_3") == "on", (
            f"tls_1_3 should be 'on', got: {settings_dict.get('tls_1_3')!r}"
        )

    def test_bot_fight_mode_resource_exists(self, parsed):
        """cloudflare_bot_management resource exists."""
        resources = find_resources(parsed, "cloudflare_bot_management")
        assert len(resources) >= 1, (
            "Expected at least one cloudflare_bot_management resource"
        )


# =========================================================================
# TestDNS (~5 tests)
# =========================================================================
@requires_hcl2
class TestDNS:
    """Verify Cloudflare DNS CNAME record configuration."""

    def test_dns_record_exists(self, parsed):
        """cloudflare_record resource exists."""
        resources = find_resources(parsed, "cloudflare_record")
        assert len(resources) >= 1, (
            "Expected at least one cloudflare_record resource"
        )

    def test_dns_record_type_cname(self, parsed):
        """DNS record type is CNAME."""
        dns = find_resource(parsed, "cloudflare_record", "proxy")
        assert dns["type"] == "CNAME", (
            f"DNS record type should be 'CNAME', got: {dns['type']!r}"
        )

    def test_dns_record_proxied_from_variable(self, parsed):
        """DNS record proxied field references var.dns_proxied."""
        dns = find_resource(parsed, "cloudflare_record", "proxy")
        proxied = dns.get("proxied", "")
        assert "var.dns_proxied" in str(proxied), (
            f"proxied should reference var.dns_proxied, got: {proxied!r}"
        )

    def test_dns_record_content_from_variable(self, parsed):
        """DNS record content references var.origin."""
        dns = find_resource(parsed, "cloudflare_record", "proxy")
        content = dns.get("content", "")
        assert "var.origin" in str(content), (
            f"content should reference var.origin, got: {content!r}"
        )

    def test_dns_record_name_from_variable(self, parsed):
        """DNS record name references var.domain."""
        dns = find_resource(parsed, "cloudflare_record", "proxy")
        name = dns.get("name", "")
        assert "var.domain" in str(name), (
            f"name should reference var.domain, got: {name!r}"
        )


# =========================================================================
# TestVariables (~6 tests)
# =========================================================================
@requires_hcl2
class TestVariables:
    """Verify module variable declarations and constraints."""

    def test_all_required_variables_declared(self, variables):
        """Required variables zone_id, environment, domain, origin exist."""
        required = ["zone_id", "environment", "domain", "origin"]
        for var_name in required:
            assert var_name in variables, (
                f"Variable '{var_name}' should be declared"
            )

    def test_waf_mode_has_validation(self, variables):
        """waf_mode variable has a validation block."""
        waf_mode = variables.get("waf_mode")
        assert waf_mode is not None, "waf_mode variable should be declared"
        assert "validation" in waf_mode, (
            "waf_mode should have a validation block"
        )

    def test_header_preset_has_validation(self, variables):
        """header_preset variable has a validation block."""
        header_preset = variables.get("header_preset")
        assert header_preset is not None, (
            "header_preset variable should be declared"
        )
        assert "validation" in header_preset, (
            "header_preset should have a validation block"
        )

    def test_ssl_mode_has_validation(self, variables):
        """ssl_mode variable has a validation block."""
        ssl_mode = variables.get("ssl_mode")
        assert ssl_mode is not None, "ssl_mode variable should be declared"
        assert "validation" in ssl_mode, (
            "ssl_mode should have a validation block"
        )

    def test_min_tls_version_has_validation(self, variables):
        """min_tls_version variable has a validation block."""
        min_tls = variables.get("min_tls_version")
        assert min_tls is not None, (
            "min_tls_version variable should be declared"
        )
        assert "validation" in min_tls, (
            "min_tls_version should have a validation block"
        )

    def test_rate_limit_variables_have_defaults(self, variables):
        """Rate limit variables have expected default values."""
        auth_rl = variables.get("auth_rate_limit", {})
        assert auth_rl.get("default") == 20, (
            f"auth_rate_limit default should be 20, got: {auth_rl.get('default')}"
        )

        api_rl = variables.get("api_rate_limit", {})
        assert api_rl.get("default") == 100, (
            f"api_rate_limit default should be 100, got: {api_rl.get('default')}"
        )

        global_rl = variables.get("global_rate_limit", {})
        assert global_rl.get("default") == 500, (
            f"global_rate_limit default should be 500, "
            f"got: {global_rl.get('default')}"
        )


# =========================================================================
# TestOutputs (~6 tests)
# =========================================================================
@requires_hcl2
class TestOutputs:
    """Verify module output declarations."""

    def test_waf_ruleset_id_output(self, outputs):
        """waf_ruleset_id output exists."""
        assert "waf_ruleset_id" in outputs, (
            "waf_ruleset_id output should be declared"
        )

    def test_rate_limiting_ruleset_id_output(self, outputs):
        """rate_limiting_ruleset_id output exists."""
        assert "rate_limiting_ruleset_id" in outputs, (
            "rate_limiting_ruleset_id output should be declared"
        )

    def test_security_headers_ruleset_id_output(self, outputs):
        """security_headers_ruleset_id output exists."""
        assert "security_headers_ruleset_id" in outputs, (
            "security_headers_ruleset_id output should be declared"
        )

    def test_dns_record_id_output(self, outputs):
        """dns_record_id output exists."""
        assert "dns_record_id" in outputs, (
            "dns_record_id output should be declared"
        )

    def test_dns_record_hostname_output(self, outputs):
        """dns_record_hostname output exists."""
        assert "dns_record_hostname" in outputs, (
            "dns_record_hostname output should be declared"
        )

    def test_zone_settings_id_output(self, outputs):
        """zone_settings_id output exists."""
        assert "zone_settings_id" in outputs, (
            "zone_settings_id output should be declared"
        )
