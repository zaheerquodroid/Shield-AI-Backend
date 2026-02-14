"""Attack simulation tests for Cloudflare edge security Terraform module.

Validates security properties against WAF bypass, rate limit bypass,
header bypass, TLS downgrade, DNS hijacking, bot protection,
credential stuffing, security misconfiguration, and root module
integration attacks.

Module under test: terraform/modules/cloudflare-edge/
"""

from __future__ import annotations

import re

import pytest

from tests.helpers.terraform import (
    find_modules,
    find_outputs,
    find_resource,
    find_resources,
    find_variables,
    parse_cloudflare_edge_module,
    parse_root_module,
    requires_hcl2,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed():
    return parse_cloudflare_edge_module()


@pytest.fixture(scope="module")
def root_parsed():
    return parse_root_module()


@pytest.fixture(scope="module")
def waf(parsed):
    return find_resource(parsed, "cloudflare_ruleset", "waf")


@pytest.fixture(scope="module")
def rate_limiting(parsed):
    return find_resource(parsed, "cloudflare_ruleset", "rate_limiting")


@pytest.fixture(scope="module")
def security_headers(parsed):
    return find_resource(parsed, "cloudflare_ruleset", "security_headers")


@pytest.fixture(scope="module")
def zone_settings(parsed):
    return find_resource(parsed, "cloudflare_zone_settings_override", "security")


@pytest.fixture(scope="module")
def bot_management(parsed):
    return find_resource(parsed, "cloudflare_bot_management", "bot_fight")


@pytest.fixture(scope="module")
def dns_record(parsed):
    return find_resource(parsed, "cloudflare_record", "proxy")


@pytest.fixture(scope="module")
def variables(parsed):
    return find_variables(parsed)


@pytest.fixture(scope="module")
def presets(parsed):
    """Extract the header presets from locals."""
    for local_block in parsed.get("locals", []):
        if "presets" in local_block:
            return local_block["presets"]
    pytest.fail("presets local not found in cloudflare-edge module")


@pytest.fixture(scope="module")
def locals_all(parsed):
    """Merge all locals blocks into a single dict."""
    merged = {}
    for local_block in parsed.get("locals", []):
        merged.update(local_block)
    return merged


# ---------------------------------------------------------------------------
# Helper: collect all WAF rules (static + dynamic)
# ---------------------------------------------------------------------------


def _all_waf_rules(waf_resource):
    """Return all rules including those inside dynamic blocks."""
    rules = list(waf_resource.get("rules", []))
    for dyn in waf_resource.get("dynamic", []):
        if "rules" in dyn:
            content = dyn["rules"].get("content", [])
            if isinstance(content, list):
                rules.extend(content)
            else:
                rules.append(content)
    return rules


# =========================================================================
# TestWAFBypass (~8 tests)
# =========================================================================
@requires_hcl2
class TestWAFBypass:
    """Prevent attackers from bypassing WAF inspection at the Cloudflare edge."""

    def test_waf_uses_managed_rulesets(self, waf):
        """WAF should deploy managed rulesets (maintained by Cloudflare), not
        custom rules that could become stale."""
        all_rules = _all_waf_rules(waf)
        for rule in all_rules:
            assert rule["action"] == "execute", (
                "WAF rules should use action='execute' to deploy managed rulesets, "
                "not custom match-and-block rules"
            )

    def test_waf_cf_managed_ruleset_id_correct(self, locals_all):
        """Cloudflare Managed Ruleset ID must be the well-known stable value
        published by Cloudflare. An incorrect ID silently deploys no protection."""
        assert locals_all["cf_managed_ruleset_id"] == "efb7b8c949ac4650a09736fc376e9aee", (
            "Cloudflare Managed Ruleset ID is incorrect -- WAF will not protect "
            "against SQLi, XSS, RCE, LFI attacks"
        )

    def test_waf_owasp_ruleset_id_correct(self, locals_all):
        """OWASP Core Ruleset ID must match Cloudflare's published value."""
        assert locals_all["owasp_core_ruleset_id"] == "4814384a9e5d4991b9815dcfc25d2f1f", (
            "OWASP Core Ruleset ID is incorrect -- OWASP CRS rules will not be deployed"
        )

    def test_waf_credentials_check_id_correct(self, locals_all):
        """Exposed Credentials Check ruleset ID must be correct to detect
        credential stuffing attacks."""
        assert locals_all["credentials_check_id"] == "c2e184081120413c86c3ab7e14069605", (
            "Exposed Credentials Check ruleset ID is incorrect -- credential "
            "stuffing detection will not work"
        )

    def test_waf_all_rules_enabled(self, waf):
        """Every WAF rule (static and dynamic) must have enabled=true.
        A disabled rule creates a silent gap in protection."""
        all_rules = _all_waf_rules(waf)
        for rule in all_rules:
            assert rule.get("enabled") is True, (
                f"WAF rule '{rule.get('description', 'unknown')}' is not enabled -- "
                "attackers can bypass this protection layer"
            )

    def test_waf_mode_overrides_action(self, waf):
        """All rules must reference the waf_action local in their overrides so
        that switching waf_mode from 'log' to 'block' takes effect everywhere."""
        all_rules = _all_waf_rules(waf)
        for rule in all_rules:
            ap = rule.get("action_parameters", [{}])
            if isinstance(ap, list):
                ap = ap[0]
            overrides = ap.get("overrides", [{}])
            if isinstance(overrides, list):
                overrides = overrides[0]
            action = overrides.get("action", "")
            assert "waf_action" in action, (
                f"WAF rule '{rule.get('description', 'unknown')}' does not reference "
                "local.waf_action -- mode switch will not affect this rule"
            )

    def test_waf_default_mode_is_log(self, variables):
        """Default WAF mode should be 'log' (safe for new deployments).
        Deploying in block mode by default risks breaking legitimate traffic."""
        assert variables["waf_mode"]["default"] == "log", (
            "waf_mode default should be 'log' to prevent blocking legitimate "
            "traffic in new deployments before tuning"
        )

    def test_waf_owasp_and_credentials_conditional(self, waf):
        """OWASP and Credentials Check rulesets should use dynamic blocks so
        operators can disable them if needed (e.g., false-positive tuning)."""
        dynamic_blocks = waf.get("dynamic", [])
        dynamic_names = set()
        for dyn in dynamic_blocks:
            dynamic_names.update(dyn.keys())
        assert "rules" in dynamic_names, (
            "OWASP/Credentials Check should use dynamic 'rules' blocks for "
            "conditional deployment"
        )
        # Verify both OWASP and credentials check are in dynamic blocks
        for_each_values = []
        for dyn in dynamic_blocks:
            if "rules" in dyn:
                for_each_values.append(dyn["rules"].get("for_each", ""))
        combined = " ".join(for_each_values)
        assert "enable_owasp_ruleset" in combined, (
            "OWASP ruleset should be conditional on enable_owasp_ruleset variable"
        )
        assert "enable_credentials_check" in combined, (
            "Credentials check should be conditional on enable_credentials_check variable"
        )


# =========================================================================
# TestRateLimitBypass (~8 tests)
# =========================================================================
@requires_hcl2
class TestRateLimitBypass:
    """Prevent attackers from bypassing rate limiting rules."""

    def test_auth_rate_limit_covers_login_path(self, rate_limiting):
        """Auth rate limit expression must cover /auth/ and /login paths.
        Missing path coverage allows brute-force credential attacks."""
        auth_rule = rate_limiting["rules"][0]
        expr = auth_rule["expression"]
        assert "/login" in expr, (
            "Auth rate limit must cover /login path to prevent brute-force attacks"
        )
        assert "login_path_pattern" in expr or "/auth/" in expr, (
            "Auth rate limit must cover /auth/ path or use login_path_pattern variable"
        )

    def test_api_rate_limit_covers_api_path(self, rate_limiting):
        """API rate limit expression must cover /api/ path."""
        api_rule = rate_limiting["rules"][1]
        expr = api_rule["expression"]
        assert "/api/" in expr, (
            "API rate limit must cover /api/ path to prevent API abuse"
        )

    def test_global_rate_limit_catches_all(self, rate_limiting):
        """Global rate limit expression must be 'true' (catches all requests).
        A narrower expression leaves unprotected paths open to DDoS."""
        global_rule = rate_limiting["rules"][2]
        expr = global_rule["expression"]
        assert expr.strip('"') == "true", (
            "Global rate limit expression must be 'true' to catch all requests -- "
            "any narrower expression leaves gaps for DDoS"
        )

    def test_rate_limits_use_ip_src(self, rate_limiting):
        """All rate limit rules must use ip.src characteristics for per-IP
        throttling. Without this, a single attacker can exhaust the global quota."""
        for rule in rate_limiting["rules"]:
            rl = rule.get("ratelimit", [{}])
            if isinstance(rl, list):
                rl = rl[0]
            chars = rl.get("characteristics", [])
            assert "ip.src" in chars, (
                f"Rate limit rule '{rule.get('description', 'unknown')}' must use "
                "ip.src characteristics for per-IP throttling"
            )

    def test_rate_limits_have_mitigation_timeout(self, rate_limiting):
        """All rules must have mitigation_timeout > 0 to actually block
        offending IPs. A zero timeout means the block expires immediately."""
        for rule in rate_limiting["rules"]:
            rl = rule.get("ratelimit", [{}])
            if isinstance(rl, list):
                rl = rl[0]
            timeout = rl.get("mitigation_timeout", 0)
            assert timeout > 0, (
                f"Rate limit rule '{rule.get('description', 'unknown')}' has "
                "mitigation_timeout=0 -- blocked IPs are unblocked immediately"
            )

    def test_auth_rate_limit_strictest(self, variables):
        """Auth rate limit (20) must be stricter than API (100) which must be
        stricter than global (500). Auth endpoints are the most sensitive target
        for brute-force attacks and need the tightest limit."""
        auth = variables["auth_rate_limit"]["default"]
        api = variables["api_rate_limit"]["default"]
        glob = variables["global_rate_limit"]["default"]
        assert auth < api < glob, (
            f"Rate limit hierarchy violated: auth({auth}) < api({api}) < global({glob}) "
            "-- auth endpoints must have the strictest limit"
        )

    def test_rate_limit_period_is_60s(self, rate_limiting):
        """All rate limit rules should use a 60-second period. Longer periods
        allow burst attacks; shorter periods can cause false positives."""
        for rule in rate_limiting["rules"]:
            rl = rule.get("ratelimit", [{}])
            if isinstance(rl, list):
                rl = rl[0]
            period = rl.get("period")
            assert period == 60, (
                f"Rate limit rule '{rule.get('description', 'unknown')}' uses "
                f"period={period} instead of 60s"
            )

    def test_rate_limit_action_respects_mode(self, rate_limiting):
        """Rate limit action must reference the rate_action local so that
        switching waf_mode toggles between block and log."""
        for rule in rate_limiting["rules"]:
            action = rule.get("action", "")
            assert "rate_action" in action, (
                f"Rate limit rule '{rule.get('description', 'unknown')}' action does "
                "not reference local.rate_action -- mode switch will not take effect"
            )


# =========================================================================
# TestHeaderBypass (~8 tests)
# =========================================================================
@requires_hcl2
class TestHeaderBypass:
    """Prevent attackers from bypassing security header injection."""

    def test_all_security_headers_set(self, security_headers):
        """All 7 security headers must use operation='set'. A missing header
        leaves the browser vulnerable to the corresponding attack class."""
        ap = security_headers["rules"][0]["action_parameters"]
        if isinstance(ap, list):
            ap = ap[0]
        headers = ap["headers"]
        set_headers = [h for h in headers if h.get("operation") == "set"]
        expected_set_headers = {
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection",
        }
        actual_set_names = {h["name"] for h in set_headers}
        assert expected_set_headers == actual_set_names, (
            f"Missing security headers with 'set' operation: "
            f"{expected_set_headers - actual_set_names}"
        )

    def test_server_header_removed(self, security_headers):
        """Server header must be removed to prevent server fingerprinting.
        Exposing the server software version helps attackers target known CVEs."""
        ap = security_headers["rules"][0]["action_parameters"]
        if isinstance(ap, list):
            ap = ap[0]
        headers = ap["headers"]
        server_headers = [
            h for h in headers if h["name"] == "Server"
        ]
        assert len(server_headers) == 1, "Server header entry must exist"
        assert server_headers[0]["operation"] == "remove", (
            "Server header must have operation='remove' to prevent fingerprinting"
        )

    def test_x_powered_by_removed(self, security_headers):
        """X-Powered-By header must be removed to prevent technology stack
        fingerprinting that aids targeted attacks."""
        ap = security_headers["rules"][0]["action_parameters"]
        if isinstance(ap, list):
            ap = ap[0]
        headers = ap["headers"]
        xpb_headers = [
            h for h in headers if h["name"] == "X-Powered-By"
        ]
        assert len(xpb_headers) == 1, "X-Powered-By header entry must exist"
        assert xpb_headers[0]["operation"] == "remove", (
            "X-Powered-By must have operation='remove' to prevent tech stack fingerprinting"
        )

    def test_hsts_includes_subdomains(self, presets):
        """Strict preset HSTS must include includeSubDomains directive.
        Without it, attackers can MITM subdomain traffic."""
        hsts = presets["strict"]["hsts"]
        assert "includeSubDomains" in hsts, (
            "Strict HSTS must include includeSubDomains to protect all subdomains "
            "from TLS stripping attacks"
        )

    def test_hsts_includes_preload_in_strict(self, presets):
        """Strict preset HSTS must include the preload directive for browser
        HSTS preload list inclusion."""
        hsts = presets["strict"]["hsts"]
        assert "preload" in hsts, (
            "Strict HSTS must include 'preload' to qualify for browser HSTS preload "
            "lists, preventing first-visit TLS stripping"
        )

    def test_csp_blocks_unsafe_eval_in_strict(self, presets):
        """Strict preset CSP must NOT contain 'unsafe-eval'. Allowing eval()
        in strict mode defeats the purpose of CSP and enables XSS via eval."""
        csp = presets["strict"]["csp"]
        assert "unsafe-eval" not in csp, (
            "Strict CSP must not contain 'unsafe-eval' -- it allows arbitrary "
            "JavaScript execution via eval(), defeating XSS protection"
        )

    def test_x_frame_options_deny_in_strict(self, presets):
        """Strict preset must set X-Frame-Options to DENY to prevent all
        clickjacking attacks. SAMEORIGIN still allows same-origin framing."""
        x_frame = presets["strict"]["x_frame_options"]
        assert x_frame == "DENY", (
            "Strict X-Frame-Options must be 'DENY' to prevent all clickjacking "
            f"attacks, got '{x_frame}'"
        )

    def test_headers_applied_to_all_requests(self, security_headers):
        """Security headers rule expression must be 'true' so headers are
        injected on every response. A narrower expression leaves some
        responses unprotected."""
        rule = security_headers["rules"][0]
        expr = rule["expression"]
        assert expr.strip('"') == "true", (
            "Security headers expression must be 'true' to apply to all responses -- "
            "any narrower expression creates bypass opportunities"
        )


# =========================================================================
# TestTLSDowngrade (~7 tests)
# =========================================================================
@requires_hcl2
class TestTLSDowngrade:
    """Prevent TLS downgrade attacks via Cloudflare zone settings."""

    def test_ssl_mode_defaults_to_strict(self, variables):
        """SSL mode must default to 'strict' (validates origin certificate).
        'full' accepts any cert; 'flexible' allows unencrypted origin traffic."""
        assert variables["ssl_mode"]["default"] == "strict", (
            "ssl_mode must default to 'strict' to validate origin certificates -- "
            "'full' or 'flexible' allows MITM between Cloudflare and origin"
        )

    def test_min_tls_defaults_to_1_2(self, variables):
        """Minimum TLS version must default to 1.2. TLS 1.0 and 1.1 have
        known vulnerabilities (BEAST, POODLE, etc.)."""
        assert variables["min_tls_version"]["default"] == "1.2", (
            "min_tls_version must default to '1.2' -- TLS 1.0/1.1 have known "
            "vulnerabilities (BEAST, POODLE, Lucky13)"
        )

    def test_tls_13_enabled(self, zone_settings):
        """TLS 1.3 must be enabled for the best available encryption and
        performance (0-RTT handshake)."""
        settings = zone_settings["settings"]
        if isinstance(settings, list):
            settings = settings[0]
        assert settings["tls_1_3"] == "on", (
            "TLS 1.3 must be enabled for strongest encryption and 0-RTT performance"
        )

    def test_always_use_https_default_true(self, variables):
        """always_use_https must default to true to redirect all HTTP to HTTPS.
        Without this, users can be MITMed on their first HTTP request."""
        assert variables["always_use_https"]["default"] is True, (
            "always_use_https must default to true to prevent HTTP plaintext "
            "exposure on first request"
        )

    def test_automatic_https_rewrites_on(self, zone_settings):
        """Automatic HTTPS rewrites must be on to fix mixed-content issues
        that could leak data over HTTP."""
        settings = zone_settings["settings"]
        if isinstance(settings, list):
            settings = settings[0]
        assert settings["automatic_https_rewrites"] == "on", (
            "automatic_https_rewrites must be 'on' to fix mixed-content issues "
            "that leak data over HTTP"
        )

    def test_ssl_mode_validation_rejects_invalid(self, variables):
        """ssl_mode must have a validation block to reject invalid values.
        Typos like 'strit' silently deploy with no SSL validation."""
        assert "validation" in variables["ssl_mode"], (
            "ssl_mode must have a validation block to reject typos that silently "
            "disable SSL certificate verification"
        )

    def test_min_tls_validation_rejects_invalid(self, variables):
        """min_tls_version must have a validation block to reject invalid values.
        An invalid TLS version string may silently default to TLS 1.0."""
        assert "validation" in variables["min_tls_version"], (
            "min_tls_version must have a validation block to prevent accidental "
            "TLS downgrade via invalid version strings"
        )


# =========================================================================
# TestDNSHijacking (~6 tests)
# =========================================================================
@requires_hcl2
class TestDNSHijacking:
    """Prevent DNS hijacking and origin exposure via DNS misconfiguration."""

    def test_dns_record_proxied_by_default(self, variables):
        """DNS record must be proxied (orange cloud) by default to hide the
        origin IP. Unproxied records expose the origin to direct attacks."""
        assert variables["dns_proxied"]["default"] is True, (
            "dns_proxied must default to true -- unproxied DNS records expose "
            "the origin IP, allowing attackers to bypass Cloudflare entirely"
        )

    def test_dns_uses_cname_not_a_record(self, dns_record):
        """DNS record must use CNAME type, not A record. CNAME allows the
        origin to be a hostname (e.g., ALB DNS), enabling dynamic resolution."""
        assert dns_record["type"] == "CNAME", (
            "DNS record must be CNAME to allow dynamic origin resolution -- "
            "A records hardcode an IP that can become stale"
        )

    def test_dns_content_from_variable(self, dns_record):
        """DNS record content must reference var.origin, not a hardcoded value.
        Hardcoded origins cannot be updated per-deployment."""
        content = dns_record["content"]
        assert "var.origin" in content, (
            "DNS record content must reference var.origin -- hardcoded origins "
            "cannot be updated per-deployment and leak infrastructure details"
        )

    def test_dns_name_from_variable(self, dns_record):
        """DNS record name must reference var.domain, not a hardcoded value."""
        name = dns_record["name"]
        assert "var.domain" in name, (
            "DNS record name must reference var.domain -- hardcoded domain names "
            "prevent multi-tenant deployment"
        )

    def test_dns_ttl_automatic_when_proxied(self, dns_record):
        """When proxied, TTL must be 1 (automatic) per Cloudflare requirements.
        A custom TTL on a proxied record is ignored and indicates misconfiguration."""
        assert dns_record["ttl"] == 1, (
            "Proxied DNS record TTL must be 1 (automatic) -- custom TTL values "
            "are ignored by Cloudflare and indicate configuration drift"
        )

    def test_dns_zone_id_from_variable(self, dns_record):
        """DNS record zone_id must reference var.zone_id, not a hardcoded value.
        Hardcoded zone IDs leak Cloudflare account structure."""
        zone_id = dns_record["zone_id"]
        assert "var.zone_id" in zone_id, (
            "DNS record zone_id must reference var.zone_id -- hardcoded zone IDs "
            "leak account structure and cannot be reused across zones"
        )


# =========================================================================
# TestBotProtection (~4 tests)
# =========================================================================
@requires_hcl2
class TestBotProtection:
    """Verify bot protection configuration to prevent automated attacks."""

    def test_bot_fight_mode_resource_exists(self, parsed):
        """cloudflare_bot_management resource must exist to enable bot
        protection. Without it, automated scanners and bots are unrestricted."""
        resources = find_resources(parsed, "cloudflare_bot_management")
        assert len(resources) >= 1, (
            "cloudflare_bot_management resource must exist to enable bot protection"
        )

    def test_bot_fight_mode_conditional(self, bot_management):
        """Bot fight mode must use count based on enable_bot_fight_mode variable
        so it can be disabled for test environments."""
        count = bot_management.get("count", "")
        assert "enable_bot_fight_mode" in str(count), (
            "Bot fight mode must be conditional on enable_bot_fight_mode variable "
            "for environment-specific control"
        )

    def test_bot_fight_mode_enabled_by_default(self, variables):
        """enable_bot_fight_mode must default to true. Bot protection should be
        opt-out, not opt-in, to prevent accidental exposure."""
        assert variables["enable_bot_fight_mode"]["default"] is True, (
            "enable_bot_fight_mode must default to true -- bot protection should "
            "be on by default to prevent automated attacks"
        )

    def test_bot_fight_mode_fight_true(self, bot_management):
        """fight_mode must be set to true to actually enable bot detection.
        The resource existing with fight_mode=false provides no protection."""
        assert bot_management["fight_mode"] is True, (
            "fight_mode must be true on the cloudflare_bot_management resource -- "
            "false means the resource exists but provides no bot protection"
        )


# =========================================================================
# TestCredentialStuffing (~4 tests)
# =========================================================================
@requires_hcl2
class TestCredentialStuffing:
    """Verify credential stuffing protection configuration."""

    def test_credentials_check_enabled_by_default(self, variables):
        """enable_credentials_check must default to true. Credential stuffing
        is a top attack vector and should be blocked by default."""
        assert variables["enable_credentials_check"]["default"] is True, (
            "enable_credentials_check must default to true -- credential stuffing "
            "is a top attack vector (OWASP A7: Identification and Authentication Failures)"
        )

    def test_credentials_check_uses_correct_ruleset(self, locals_all):
        """The credentials check ruleset ID must match Cloudflare's published
        Exposed Credentials Check ID."""
        assert locals_all["credentials_check_id"] == "c2e184081120413c86c3ab7e14069605", (
            "Credentials check ruleset ID must be c2e184081120413c86c3ab7e14069605 -- "
            "wrong ID means no credential stuffing detection"
        )

    def test_credentials_check_conditional(self, waf):
        """Credentials check must use a dynamic block with conditional for_each
        so it can be disabled when not needed."""
        dynamic_blocks = waf.get("dynamic", [])
        cred_check_found = False
        for dyn in dynamic_blocks:
            if "rules" in dyn:
                for_each = dyn["rules"].get("for_each", "")
                if "enable_credentials_check" in for_each:
                    cred_check_found = True
                    break
        assert cred_check_found, (
            "Credentials check must use a dynamic block conditional on "
            "enable_credentials_check variable"
        )

    def test_auth_rate_limit_low_threshold(self, variables):
        """Auth rate limit default (20 req/min) must be appropriately strict to
        limit brute-force attempts. Higher thresholds allow faster password
        enumeration."""
        auth_limit = variables["auth_rate_limit"]["default"]
        assert auth_limit <= 30, (
            f"Auth rate limit default ({auth_limit}) is too high -- allows "
            f"{auth_limit} login attempts per minute per IP, enabling brute-force attacks"
        )


# =========================================================================
# TestSecurityMisconfiguration (~6 tests)
# =========================================================================
@requires_hcl2
class TestSecurityMisconfiguration:
    """Detect security misconfigurations in variables and hardcoded secrets."""

    def test_no_hardcoded_zone_ids(self, variables):
        """Variable defaults must not contain Cloudflare zone ID patterns
        (32-char hex). Hardcoded zone IDs leak account structure and prevent
        multi-tenant reuse."""
        zone_id_pattern = re.compile(r"^[0-9a-f]{32}$")
        for name, attrs in variables.items():
            default = str(attrs.get("default", ""))
            assert not zone_id_pattern.match(default), (
                f"Variable '{name}' has hardcoded zone ID: {default} -- "
                "zone IDs must come from external configuration"
            )

    def test_no_hardcoded_api_tokens(self, parsed):
        """No .tf file in the module should contain hardcoded Cloudflare API
        tokens. Leaked tokens grant full zone access."""
        # Cloudflare API tokens are 40-char alphanumeric strings
        # Check all string values recursively in the parsed dict
        import json
        serialized = json.dumps(parsed)
        # Cloudflare API tokens typically look like: [a-zA-Z0-9_-]{40}
        # But we check for common prefixes that indicate tokens
        assert "Bearer " not in serialized, (
            "Module contains hardcoded Bearer token -- API tokens must be "
            "passed as variables, never committed to source control"
        )

    def test_waf_mode_validation_exists(self, variables):
        """waf_mode must have a validation block to reject invalid values like
        'blcok' (typo) which silently defaults to log mode."""
        assert "validation" in variables["waf_mode"], (
            "waf_mode must have a validation block to reject typos that "
            "silently leave the WAF in log-only mode"
        )

    def test_security_level_validation_exists(self, variables):
        """security_level must have a validation block. Invalid values could
        silently set the threat score threshold to the lowest level."""
        assert "validation" in variables["security_level"], (
            "security_level must have a validation block to prevent accidental "
            "weakening of the Cloudflare threat score threshold"
        )

    def test_header_preset_validation_exists(self, variables):
        """header_preset must have a validation block. An invalid preset name
        would cause a Terraform apply failure or silently apply no headers."""
        assert "validation" in variables["header_preset"], (
            "header_preset must have a validation block to reject invalid preset "
            "names that could cause apply failures or missing headers"
        )

    def test_rate_limit_validation_exists(self, variables):
        """Rate limit variables must have validation blocks to prevent negative
        or excessively high values that disable effective rate limiting."""
        for var_name in ["auth_rate_limit", "api_rate_limit", "global_rate_limit"]:
            assert "validation" in variables[var_name], (
                f"Variable '{var_name}' must have a validation block to prevent "
                "invalid rate limit values (zero, negative, or excessively high)"
            )


# =========================================================================
# TestRootModuleIntegration (~5 tests)
# =========================================================================
@requires_hcl2
class TestRootModuleIntegration:
    """Verify cloudflare-edge module is properly wired into root Terraform module."""

    def test_root_has_cloudflare_module(self, root_parsed):
        """Root main.tf must contain the cloudflare_edge module block."""
        modules = find_modules(root_parsed)
        assert "cloudflare_edge" in modules, (
            "Root module must contain cloudflare_edge module block -- "
            "module exists but is not wired into the root configuration"
        )

    def test_module_conditional_on_flag(self, root_parsed):
        """cloudflare_edge module must use count conditional on enable_cloudflare
        variable so it is not deployed by default."""
        modules = find_modules(root_parsed)
        cf = modules["cloudflare_edge"]
        count = str(cf.get("count", ""))
        assert "enable_cloudflare" in count, (
            "cloudflare_edge module must be conditional on enable_cloudflare -- "
            "deploying unconditionally wastes resources and may conflict with CloudFront"
        )

    def test_root_variables_include_cloudflare(self, root_parsed):
        """Root variables.tf must declare Cloudflare-specific variables."""
        variables = find_variables(root_parsed)
        assert "enable_cloudflare" in variables, (
            "Root module must have enable_cloudflare variable"
        )
        assert "cloudflare_zone_id" in variables, (
            "Root module must have cloudflare_zone_id variable"
        )
        assert "cloudflare_domain" in variables, (
            "Root module must have cloudflare_domain variable"
        )

    def test_root_outputs_include_cloudflare(self, root_parsed):
        """Root outputs.tf must export Cloudflare resource IDs for downstream use."""
        outputs = find_outputs(root_parsed)
        assert "cloudflare_waf_ruleset_id" in outputs, (
            "Root module must export cloudflare_waf_ruleset_id output"
        )
        assert "cloudflare_rate_limiting_ruleset_id" in outputs, (
            "Root module must export cloudflare_rate_limiting_ruleset_id output"
        )
        assert "cloudflare_dns_record_hostname" in outputs, (
            "Root module must export cloudflare_dns_record_hostname output"
        )

    def test_module_reuses_shared_variables(self, root_parsed):
        """cloudflare_edge module must wire header_preset and login_path_pattern
        from root variables to ensure consistency with other modules (e.g.,
        security-headers, WAF)."""
        modules = find_modules(root_parsed)
        cf = modules["cloudflare_edge"]
        header_preset = str(cf.get("header_preset", ""))
        assert "header_preset" in header_preset, (
            "cloudflare_edge must receive header_preset from root to stay "
            "consistent with the security-headers module"
        )
        login_path = str(cf.get("login_path_pattern", ""))
        assert "login_path_pattern" in login_path, (
            "cloudflare_edge must receive login_path_pattern from root to stay "
            "consistent with the WAF module's auth rate limiting"
        )


# =========================================================================
# TestSecurityHardening (~20 tests)
# =========================================================================
@requires_hcl2
class TestSecurityHardening:
    """Security hardening round 1 — fixes for audit findings."""

    # ----- CRITICAL-1: login_path_pattern expression injection prevention -----

    def test_login_path_pattern_has_validation(self, variables):
        """login_path_pattern must have validation to prevent Cloudflare
        expression injection via crafted URI patterns."""
        assert "validation" in variables["login_path_pattern"], (
            "login_path_pattern must have a validation block -- without it, "
            "an attacker-controlled value like ') or true #' can inject into "
            "Cloudflare WAF expressions"
        )

    def test_login_path_pattern_rejects_special_chars(self, variables):
        """login_path_pattern validation must enforce simple path format,
        rejecting parentheses, quotes, and other expression-injection chars."""
        validation = variables["login_path_pattern"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        # The regex should restrict to alphanumeric + slashes + hyphens + underscores
        assert "regex" in condition or "can(" in condition, (
            "login_path_pattern validation must use a regex to enforce simple "
            "path format (letters, digits, slashes, hyphens, underscores only)"
        )

    # ----- CRITICAL-2: SSL mode restricted to secure values -----

    def test_ssl_mode_rejects_flexible(self, variables):
        """ssl_mode must reject 'flexible' — sends plaintext to origin,
        allowing MITM between Cloudflare and the backend."""
        validation = variables["ssl_mode"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        # Condition should contain only "strict" and "full"
        assert "flexible" not in condition, (
            "ssl_mode validation must not allow 'flexible' -- it sends plaintext "
            "traffic to the origin, enabling MITM attacks"
        )

    def test_ssl_mode_rejects_off(self, variables):
        """ssl_mode must reject 'off' — disables SSL entirely, exposing all
        traffic in plaintext."""
        validation = variables["ssl_mode"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        # The allowed list should only contain "strict" and "full"
        allowed_values = re.findall(r'"([^"]+)"', condition)
        assert "off" not in allowed_values, (
            "ssl_mode validation must not allow 'off' -- it disables SSL entirely"
        )

    def test_ssl_mode_only_allows_strict_and_full(self, variables):
        """ssl_mode validation must only allow 'strict' and 'full'."""
        validation = variables["ssl_mode"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        # hcl2 parser may strip quotes: contains([strict, full], var.ssl_mode)
        assert "strict" in condition and "full" in condition, (
            "ssl_mode validation must allow both 'strict' and 'full'"
        )
        # Ensure insecure modes are not in the allowed list
        for insecure in ["flexible", "off"]:
            assert insecure not in condition, (
                f"ssl_mode validation must not allow '{insecure}'"
            )

    # ----- CRITICAL-3: TLS version restricted -----

    def test_min_tls_rejects_1_0(self, variables):
        """min_tls_version must reject '1.0' — deprecated per RFC 8996,
        vulnerable to BEAST and POODLE attacks."""
        validation = variables["min_tls_version"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        assert '"1.0"' not in condition, (
            "min_tls_version must not allow '1.0' -- deprecated per RFC 8996, "
            "vulnerable to BEAST, POODLE, and Lucky13 attacks"
        )

    def test_min_tls_rejects_1_1(self, variables):
        """min_tls_version must reject '1.1' — deprecated per RFC 8996,
        does not support modern cipher suites."""
        validation = variables["min_tls_version"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        assert '"1.1"' not in condition, (
            "min_tls_version must not allow '1.1' -- deprecated per RFC 8996, "
            "no support for AEAD cipher suites"
        )

    # ----- HIGH-1: Root module rate limit variable validation -----

    def test_root_cloudflare_auth_rate_limit_has_validation(self, root_parsed):
        """Root cloudflare_auth_rate_limit must have validation to prevent
        zero or excessively high values that disable rate limiting."""
        root_vars = find_variables(root_parsed)
        assert "validation" in root_vars.get("cloudflare_auth_rate_limit", {}), (
            "Root cloudflare_auth_rate_limit must have a validation block -- "
            "a value of 0 or negative disables rate limiting entirely"
        )

    def test_root_cloudflare_api_rate_limit_has_validation(self, root_parsed):
        """Root cloudflare_api_rate_limit must have validation."""
        root_vars = find_variables(root_parsed)
        assert "validation" in root_vars.get("cloudflare_api_rate_limit", {}), (
            "Root cloudflare_api_rate_limit must have a validation block"
        )

    def test_root_cloudflare_global_rate_limit_has_validation(self, root_parsed):
        """Root cloudflare_global_rate_limit must have validation."""
        root_vars = find_variables(root_parsed)
        assert "validation" in root_vars.get("cloudflare_global_rate_limit", {}), (
            "Root cloudflare_global_rate_limit must have a validation block"
        )

    # ----- HIGH-2: environment validation -----

    def test_environment_has_validation(self, variables):
        """environment must have validation to restrict to known deployment
        environments (test, demo, staging, prod)."""
        assert "validation" in variables["environment"], (
            "environment must have a validation block -- an unknown environment "
            "like 'production' (instead of 'prod') can cause misconfiguration"
        )

    def test_environment_allows_only_known_values(self, variables):
        """environment validation must restrict to test, demo, staging, prod."""
        validation = variables["environment"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        for env in ["test", "demo", "staging", "prod"]:
            assert env in condition, (
                f"environment validation must allow '{env}'"
            )

    # ----- HIGH-3: zone_id format validation -----

    def test_zone_id_has_validation(self, variables):
        """zone_id must validate 32-char hex format to catch typos and
        prevent invalid API calls to Cloudflare."""
        assert "validation" in variables["zone_id"], (
            "zone_id must have a validation block -- an invalid zone ID causes "
            "silent API failures or applies rules to the wrong zone"
        )

    # ----- HIGH-4: domain and origin non-empty validation -----

    def test_domain_has_validation(self, variables):
        """domain must have validation to reject empty strings."""
        assert "validation" in variables["domain"], (
            "domain must have a validation block -- an empty domain causes "
            "DNS record creation failures"
        )

    def test_origin_has_validation(self, variables):
        """origin must have validation to reject empty strings."""
        assert "validation" in variables["origin"], (
            "origin must have a validation block -- an empty origin causes "
            "Cloudflare to proxy to an undefined backend"
        )

    # ----- MEDIUM-1: X-XSS-Protection set to "0" -----

    def test_x_xss_protection_is_zero(self, security_headers):
        """X-XSS-Protection should be '0' per OWASP recommendation.
        The legacy XSS auditor in older browsers can be exploited to CREATE
        XSS vulnerabilities via response splitting attacks."""
        ap = security_headers["rules"][0]["action_parameters"]
        if isinstance(ap, list):
            ap = ap[0]
        headers = ap["headers"]
        xss_headers = [h for h in headers if h["name"] == "X-XSS-Protection"]
        assert len(xss_headers) == 1, "X-XSS-Protection header must exist"
        assert xss_headers[0]["value"] == "0", (
            "X-XSS-Protection must be '0' per OWASP recommendation -- "
            "'1; mode=block' enables the legacy XSS auditor which can be "
            "exploited to create XSS via response splitting"
        )

    # ----- MEDIUM-3: security_level rejects insecure values -----

    def test_security_level_rejects_off(self, variables):
        """security_level must reject 'off' — completely disables Cloudflare
        threat score checking, allowing known-malicious IPs through."""
        validation = variables["security_level"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        allowed_values = re.findall(r'"([^"]+)"', condition)
        assert "off" not in allowed_values, (
            "security_level must not allow 'off' -- it disables all threat "
            "score checking, allowing known-malicious IPs through"
        )

    def test_security_level_rejects_essentially_off(self, variables):
        """security_level must reject 'essentially_off' — sets threat score
        threshold so high that almost no traffic is challenged."""
        validation = variables["security_level"]["validation"]
        if isinstance(validation, list):
            validation = validation[0]
        condition = str(validation.get("condition", ""))
        assert "essentially_off" not in condition, (
            "security_level must not allow 'essentially_off' -- it sets the "
            "threat score threshold so high that virtually no traffic is challenged"
        )

    # ----- MEDIUM-4: CloudFront/Cloudflare mutual exclusion -----

    def test_mutual_exclusion_check_exists(self, root_parsed):
        """Root module must have a check block preventing both CloudFront
        and Cloudflare from being enabled simultaneously. Both create
        conflicting DNS/CDN infrastructure."""
        checks = root_parsed.get("check", [])
        assert len(checks) >= 2, (
            "Root module should have at least 2 check blocks (region check + "
            "mutual exclusion check)"
        )
        check_str = str(checks)
        assert "enable_cloudfront" in check_str and "enable_cloudflare" in check_str, (
            "Root module must have a check block that references both "
            "enable_cloudfront and enable_cloudflare for mutual exclusion"
        )

    # ----- Root module pass-through validation -----

    def test_root_cloudflare_ssl_mode_has_validation(self, root_parsed):
        """Root cloudflare_ssl_mode must have validation mirroring the module
        variable to prevent insecure values at the root level."""
        root_vars = find_variables(root_parsed)
        assert "validation" in root_vars.get("cloudflare_ssl_mode", {}), (
            "Root cloudflare_ssl_mode must have a validation block -- without it, "
            "insecure values like 'flexible' can bypass module-level validation "
            "via Terraform's variable precedence"
        )

    def test_root_cloudflare_min_tls_has_validation(self, root_parsed):
        """Root cloudflare_min_tls_version must have validation mirroring the
        module variable to prevent deprecated TLS versions."""
        root_vars = find_variables(root_parsed)
        assert "validation" in root_vars.get("cloudflare_min_tls_version", {}), (
            "Root cloudflare_min_tls_version must have a validation block -- "
            "without it, deprecated TLS 1.0/1.1 can bypass module validation"
        )

    def test_root_cloudflare_security_level_has_validation(self, root_parsed):
        """Root cloudflare_security_level must have validation to prevent
        insecure values like 'off' or 'essentially_off'."""
        root_vars = find_variables(root_parsed)
        assert "validation" in root_vars.get("cloudflare_security_level", {}), (
            "Root cloudflare_security_level must have a validation block -- "
            "without it, insecure values bypass module-level restrictions"
        )
