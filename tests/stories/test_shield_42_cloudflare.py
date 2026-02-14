"""Story/Acceptance Criteria tests for SHIELD-42: Cloudflare Edge Security.

Validates the 8 acceptance criteria for the Cloudflare edge security module:
  AC1: Terraform module deploys complete Cloudflare edge security (WAF, rate limiting, headers, zone settings).
  AC2: WAF managed rulesets enabled (CF Managed, OWASP Core, Exposed Credentials Check).
  AC3: Rate limiting rules with configurable thresholds (auth 20, API 100, global 500 req/min).
  AC4: Security headers via Transform Rules (7 set, 2 removed, 3 presets).
  AC5: Zone settings (SSL strict, TLS 1.2 min, Bot Fight Mode).
  AC6: DNS record created proxied through Cloudflare.
  AC7: Environment-based mode (log for test, block for production).
  AC8: Root module integration (module block, conditional, outputs).
"""

from __future__ import annotations

import pytest

from tests.helpers.terraform import (
    requires_hcl2,
    parse_cloudflare_edge_module,
    parse_root_module,
    find_resource,
    find_resources,
    find_variables,
    find_outputs,
    find_modules,
)


@pytest.fixture(scope="module")
def cf_parsed():
    return parse_cloudflare_edge_module()


@pytest.fixture(scope="module")
def root_parsed():
    return parse_root_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_all_rulesets(parsed):
    """Return all cloudflare_ruleset resources as a flat list of (name, body) tuples."""
    results = []
    for resource_block in parsed.get("resource", []):
        if "cloudflare_ruleset" in resource_block:
            for name, body in resource_block["cloudflare_ruleset"].items():
                results.append((name, body))
    return results


def _get_rules_from_ruleset(ruleset_body):
    """Extract the rules list from a cloudflare_ruleset resource body.

    HCL2 parser may represent repeated blocks as a list of dicts.
    Dynamic "rules" blocks are stored under the "dynamic" key and their
    content is extracted and merged with static rules.
    """
    rules = ruleset_body.get("rules", [])
    if isinstance(rules, dict):
        rules = [rules]

    # Also extract rules from dynamic blocks (HCL2 puts these under "dynamic")
    for dyn_block in ruleset_body.get("dynamic", []):
        if "rules" in dyn_block:
            content = dyn_block["rules"].get("content", [])
            if isinstance(content, list):
                rules.extend(content)
            elif isinstance(content, dict):
                rules.append(content)

    return rules


def _get_headers_from_ruleset(ruleset_body):
    """Extract all header blocks from a security_headers ruleset.

    Path: rules[0].action_parameters[0].headers — may be list of dicts.
    """
    rules = _get_rules_from_ruleset(ruleset_body)
    if not rules:
        return []

    rule = rules[0]
    action_params = rule.get("action_parameters", [])
    if isinstance(action_params, list) and action_params:
        action_params = action_params[0]
    elif not isinstance(action_params, dict):
        return []

    headers = action_params.get("headers", [])
    if isinstance(headers, dict):
        return [headers]
    return headers


def _get_locals(parsed):
    """Extract all locals blocks merged into a single dict."""
    merged = {}
    for locals_block in parsed.get("locals", []):
        if isinstance(locals_block, dict):
            merged.update(locals_block)
    return merged


# =========================================================================
# AC1: Complete Edge Security (~4 tests)
# =========================================================================
@requires_hcl2
class TestAC1_CompleteEdgeSecurity:
    """AC1: Terraform module deploys complete Cloudflare edge security."""

    def test_waf_ruleset_resource_exists(self, cf_parsed):
        """WAF managed ruleset resource (cloudflare_ruleset.waf) exists."""
        resource = find_resource(cf_parsed, "cloudflare_ruleset", "waf")
        assert resource is not None, (
            "AC1: cloudflare_ruleset.waf must exist for WAF managed rulesets"
        )

    def test_rate_limiting_ruleset_resource_exists(self, cf_parsed):
        """Rate limiting ruleset resource (cloudflare_ruleset.rate_limiting) exists."""
        resource = find_resource(cf_parsed, "cloudflare_ruleset", "rate_limiting")
        assert resource is not None, (
            "AC1: cloudflare_ruleset.rate_limiting must exist for rate limiting"
        )

    def test_security_headers_ruleset_resource_exists(self, cf_parsed):
        """Security headers ruleset resource (cloudflare_ruleset.security_headers) exists."""
        resource = find_resource(cf_parsed, "cloudflare_ruleset", "security_headers")
        assert resource is not None, (
            "AC1: cloudflare_ruleset.security_headers must exist for header transform rules"
        )

    def test_zone_settings_resource_exists(self, cf_parsed):
        """Zone settings override resource exists."""
        resource = find_resource(
            cf_parsed, "cloudflare_zone_settings_override", "security"
        )
        assert resource is not None, (
            "AC1: cloudflare_zone_settings_override.security must exist for zone settings"
        )


# =========================================================================
# AC2: WAF Managed Rulesets (~3 tests)
# =========================================================================
@requires_hcl2
class TestAC2_WAFManagedRulesets:
    """AC2: WAF managed rulesets enabled (CF Managed, OWASP, Credentials Check)."""

    def test_cf_managed_ruleset_present(self, cf_parsed):
        """Cloudflare Managed Ruleset rule present in http_request_firewall_managed phase."""
        waf = find_resource(cf_parsed, "cloudflare_ruleset", "waf")
        # Verify the WAF ruleset is in the correct phase
        phase = waf.get("phase")
        # HCL2 wraps single values in lists
        if isinstance(phase, list):
            phase = phase[0]
        assert phase == "http_request_firewall_managed", (
            "AC2: WAF ruleset must use phase http_request_firewall_managed"
        )

        # Check that the Cloudflare Managed Ruleset rule is present via description
        rules = _get_rules_from_ruleset(waf)
        descriptions = [
            r.get("description", [""])[0] if isinstance(r.get("description"), list)
            else r.get("description", "")
            for r in rules
        ]
        assert any("Cloudflare Managed Ruleset" in d for d in descriptions), (
            "AC2: Cloudflare Managed Ruleset rule must be present in WAF"
        )

    def test_owasp_core_ruleset_present(self, cf_parsed):
        """OWASP Core Ruleset rule present in WAF ruleset."""
        waf = find_resource(cf_parsed, "cloudflare_ruleset", "waf")
        rules = _get_rules_from_ruleset(waf)
        descriptions = [
            r.get("description", [""])[0] if isinstance(r.get("description"), list)
            else r.get("description", "")
            for r in rules
        ]
        assert any("OWASP" in d for d in descriptions), (
            "AC2: OWASP Core Ruleset rule must be present in WAF"
        )

    def test_exposed_credentials_check_present(self, cf_parsed):
        """Exposed Credentials Check rule present in WAF ruleset."""
        waf = find_resource(cf_parsed, "cloudflare_ruleset", "waf")
        rules = _get_rules_from_ruleset(waf)
        descriptions = [
            r.get("description", [""])[0] if isinstance(r.get("description"), list)
            else r.get("description", "")
            for r in rules
        ]
        assert any("Exposed Credentials" in d for d in descriptions), (
            "AC2: Exposed Credentials Check rule must be present in WAF"
        )


# =========================================================================
# AC3: Rate Limiting (~4 tests)
# =========================================================================
@requires_hcl2
class TestAC3_RateLimiting:
    """AC3: Rate limiting rules with configurable thresholds."""

    def test_auth_rate_limit_default_20(self, cf_parsed):
        """Auth endpoint rate limit defaults to 20 req/min."""
        variables = find_variables(cf_parsed)
        auth_var = variables.get("auth_rate_limit", {})
        default = auth_var.get("default")
        # HCL2 may wrap in list
        if isinstance(default, list):
            default = default[0]
        assert default == 20, (
            "AC3: auth_rate_limit must default to 20 req/min"
        )

    def test_api_rate_limit_default_100(self, cf_parsed):
        """API endpoint rate limit defaults to 100 req/min."""
        variables = find_variables(cf_parsed)
        api_var = variables.get("api_rate_limit", {})
        default = api_var.get("default")
        if isinstance(default, list):
            default = default[0]
        assert default == 100, (
            "AC3: api_rate_limit must default to 100 req/min"
        )

    def test_global_rate_limit_default_500(self, cf_parsed):
        """Global rate limit defaults to 500 req/min."""
        variables = find_variables(cf_parsed)
        global_var = variables.get("global_rate_limit", {})
        default = global_var.get("default")
        if isinstance(default, list):
            default = default[0]
        assert default == 500, (
            "AC3: global_rate_limit must default to 500 req/min"
        )

    def test_all_rate_limits_configurable_via_variables(self, cf_parsed):
        """All three rate limit thresholds are configurable via Terraform variables."""
        variables = find_variables(cf_parsed)
        rate_limit_vars = {"auth_rate_limit", "api_rate_limit", "global_rate_limit"}
        for var_name in rate_limit_vars:
            assert var_name in variables, (
                f"AC3: variable '{var_name}' must exist for configurable rate limits"
            )
            # Each must have a type of number
            var_type = variables[var_name].get("type")
            type_str = str(var_type)
            assert "number" in type_str, (
                f"AC3: variable '{var_name}' must be of type number"
            )


# =========================================================================
# AC4: Security Headers (~4 tests)
# =========================================================================
@requires_hcl2
class TestAC4_SecurityHeaders:
    """AC4: Security headers injected via Transform Rules."""

    def test_all_seven_set_headers_present(self, cf_parsed):
        """All 7 security headers are set via Transform Rules."""
        ruleset = find_resource(cf_parsed, "cloudflare_ruleset", "security_headers")
        headers = _get_headers_from_ruleset(ruleset)

        set_headers = []
        for h in headers:
            op = h.get("operation")
            if isinstance(op, list):
                op = op[0]
            if op == "set":
                name = h.get("name")
                if isinstance(name, list):
                    name = name[0]
                set_headers.append(name)

        expected_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection",
        ]
        for header in expected_headers:
            assert header in set_headers, (
                f"AC4: Security header '{header}' must be set via Transform Rules"
            )

    def test_server_header_removed(self, cf_parsed):
        """Server header removed via Transform Rules."""
        ruleset = find_resource(cf_parsed, "cloudflare_ruleset", "security_headers")
        headers = _get_headers_from_ruleset(ruleset)

        removed_headers = []
        for h in headers:
            op = h.get("operation")
            if isinstance(op, list):
                op = op[0]
            if op == "remove":
                name = h.get("name")
                if isinstance(name, list):
                    name = name[0]
                removed_headers.append(name)

        assert "Server" in removed_headers, (
            "AC4: Server header must be removed to prevent server fingerprinting"
        )

    def test_x_powered_by_header_removed(self, cf_parsed):
        """X-Powered-By header removed via Transform Rules."""
        ruleset = find_resource(cf_parsed, "cloudflare_ruleset", "security_headers")
        headers = _get_headers_from_ruleset(ruleset)

        removed_headers = []
        for h in headers:
            op = h.get("operation")
            if isinstance(op, list):
                op = op[0]
            if op == "remove":
                name = h.get("name")
                if isinstance(name, list):
                    name = name[0]
                removed_headers.append(name)

        assert "X-Powered-By" in removed_headers, (
            "AC4: X-Powered-By header must be removed to prevent technology fingerprinting"
        )

    def test_three_header_presets_available(self, cf_parsed):
        """Three header presets (strict, balanced, permissive) available via locals."""
        all_locals = _get_locals(cf_parsed)
        presets = all_locals.get("presets", {})
        # HCL2 may wrap the presets value in a list
        if isinstance(presets, list) and presets:
            presets = presets[0]

        expected_presets = {"strict", "balanced", "permissive"}
        actual_presets = set(presets.keys()) if isinstance(presets, dict) else set()
        assert expected_presets.issubset(actual_presets), (
            f"AC4: Presets must include strict, balanced, permissive. "
            f"Found: {actual_presets}"
        )


# =========================================================================
# AC5: Zone Settings (~3 tests)
# =========================================================================
@requires_hcl2
class TestAC5_ZoneSettings:
    """AC5: Zone settings (SSL strict, TLS 1.2 min, Bot Fight Mode)."""

    def test_ssl_mode_strict_by_default(self, cf_parsed):
        """SSL mode defaults to 'strict'."""
        variables = find_variables(cf_parsed)
        ssl_var = variables.get("ssl_mode", {})
        default = ssl_var.get("default")
        if isinstance(default, list):
            default = default[0]
        assert default == "strict", (
            "AC5: ssl_mode must default to 'strict' for full origin certificate validation"
        )

    def test_minimum_tls_12_by_default(self, cf_parsed):
        """Minimum TLS version defaults to 1.2."""
        variables = find_variables(cf_parsed)
        tls_var = variables.get("min_tls_version", {})
        default = tls_var.get("default")
        if isinstance(default, list):
            default = default[0]
        assert default == "1.2", (
            "AC5: min_tls_version must default to '1.2' to disable legacy TLS"
        )

    def test_bot_fight_mode_resource_exists(self, cf_parsed):
        """Bot Fight Mode resource (cloudflare_bot_management) exists."""
        resources = find_resources(cf_parsed, "cloudflare_bot_management")
        assert len(resources) >= 1, (
            "AC5: cloudflare_bot_management resource must exist for Bot Fight Mode"
        )


# =========================================================================
# AC6: DNS Record (~2 tests)
# =========================================================================
@requires_hcl2
class TestAC6_DNSRecord:
    """AC6: DNS record created proxied through Cloudflare."""

    def test_cname_record_exists(self, cf_parsed):
        """CNAME DNS record resource exists."""
        resource = find_resource(cf_parsed, "cloudflare_record", "proxy")
        rec_type = resource.get("type")
        if isinstance(rec_type, list):
            rec_type = rec_type[0]
        assert rec_type == "CNAME", (
            "AC6: DNS record must be of type CNAME"
        )

    def test_record_proxied_by_default(self, cf_parsed):
        """DNS record is proxied through Cloudflare (orange cloud) by default."""
        variables = find_variables(cf_parsed)
        dns_var = variables.get("dns_proxied", {})
        default = dns_var.get("default")
        if isinstance(default, list):
            default = default[0]
        assert default is True, (
            "AC6: dns_proxied must default to true for Cloudflare proxy (orange cloud)"
        )


# =========================================================================
# AC7: Environment Mode (~2 tests)
# =========================================================================
@requires_hcl2
class TestAC7_EnvironmentMode:
    """AC7: Environment-based mode (log for test, block for production)."""

    def test_waf_mode_accepts_block_and_log(self, cf_parsed):
        """waf_mode variable accepts 'block' and 'log' values."""
        variables = find_variables(cf_parsed)
        waf_mode = variables.get("waf_mode", {})

        # Check validation constraint references both values
        validation = waf_mode.get("validation", [])
        if isinstance(validation, list) and validation:
            validation = validation[0]
        condition_str = str(validation.get("condition", ""))
        assert "block" in condition_str and "log" in condition_str, (
            "AC7: waf_mode validation must accept both 'block' and 'log'"
        )

    def test_waf_mode_defaults_to_log(self, cf_parsed):
        """waf_mode defaults to 'log' as a safe default for testing."""
        variables = find_variables(cf_parsed)
        waf_mode = variables.get("waf_mode", {})
        default = waf_mode.get("default")
        if isinstance(default, list):
            default = default[0]
        assert default == "log", (
            "AC7: waf_mode must default to 'log' for safe testing"
        )


# =========================================================================
# AC8: Root Module Integration (~3 tests)
# =========================================================================
@requires_hcl2
class TestAC8_RootModuleIntegration:
    """AC8: Module usable standalone or alongside security proxy."""

    def test_root_has_cloudflare_edge_module_block(self, root_parsed):
        """Root main.tf has a cloudflare_edge module block."""
        modules = find_modules(root_parsed)
        assert "cloudflare_edge" in modules, (
            "AC8: Root module must contain a module 'cloudflare_edge' block"
        )

    def test_module_conditional_on_enable_cloudflare(self, root_parsed):
        """Cloudflare edge module is conditional on enable_cloudflare variable."""
        modules = find_modules(root_parsed)
        cf_module = modules["cloudflare_edge"]
        count_expr = cf_module.get("count", "")
        count_str = str(count_expr)
        assert "enable_cloudflare" in count_str, (
            "AC8: cloudflare_edge module must be conditional on enable_cloudflare via count"
        )

    def test_root_outputs_include_cloudflare_outputs(self, root_parsed):
        """Root outputs include at least one Cloudflare-related output."""
        outputs = find_outputs(root_parsed)
        cf_outputs = [name for name in outputs if "cloudflare" in name.lower()]
        assert len(cf_outputs) >= 1, (
            "AC8: Root outputs must include at least one Cloudflare output "
            f"(found: {list(outputs.keys())})"
        )
