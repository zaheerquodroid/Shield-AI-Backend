"""Attack simulation tests for CloudFront SaaS distribution.

Validates security properties against origin bypass, WAF bypass,
cache poisoning, TLS downgrade, DNS hijacking, geo restriction,
logging, resource naming, and root module integration attacks.
"""

from __future__ import annotations

import pytest

from tests.helpers.terraform import (
    find_data_sources,
    find_modules,
    find_outputs,
    find_resource,
    find_resources,
    find_rule_by_name,
    find_rules_in_waf,
    find_variables,
    get_tags,
    parse_cloudfront_module,
    parse_proxy_ecs_module,
    parse_root_module,
    requires_hcl2,
)


@pytest.fixture(scope="module")
def cf_parsed():
    return parse_cloudfront_module()


@pytest.fixture(scope="module")
def root_parsed():
    return parse_root_module()


@pytest.fixture(scope="module")
def ecs_parsed():
    return parse_proxy_ecs_module()


@pytest.fixture(scope="module")
def distribution(cf_parsed):
    return find_resource(cf_parsed, "aws_cloudfront_distribution", "proxy")


@pytest.fixture(scope="module")
def waf(cf_parsed):
    return find_resource(cf_parsed, "aws_wafv2_web_acl", "cloudfront")


# =========================================================================
# TestOriginBypass (~8 tests)
# =========================================================================
@requires_hcl2
class TestOriginBypass:
    """Prevent attackers from bypassing CloudFront to hit ALB directly."""

    def test_custom_origin_header_configured(self, distribution):
        origin = distribution["origin"][0]
        headers = origin.get("custom_header", [])
        assert len(headers) > 0
        assert headers[0]["name"] == "X-ShieldAI-Origin-Verify"

    def test_origin_verify_secret_from_variable(self, distribution):
        origin = distribution["origin"][0]
        headers = origin.get("custom_header", [])
        value = headers[0]["value"]
        assert "var.origin_verify_secret" in value, "Secret should come from variable, not hardcoded"

    def test_origin_verify_secret_is_sensitive(self, cf_parsed):
        variables = find_variables(cf_parsed)
        assert variables["origin_verify_secret"].get("sensitive") is True

    def test_origin_protocol_https_only(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        assert cfg["origin_protocol_policy"] == "https-only"

    def test_origin_ssl_excludes_legacy(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        protocols = cfg["origin_ssl_protocols"]
        for bad in ["SSLv3", "TLSv1", "TLSv1.1"]:
            assert bad not in protocols

    def test_cloudfront_prefix_list_data_source_exists(self, cf_parsed):
        ds = find_data_sources(cf_parsed, "aws_ec2_managed_prefix_list")
        assert len(ds) >= 1

    def test_prefix_list_output_exported(self, cf_parsed):
        outputs = find_outputs(cf_parsed)
        assert "cloudfront_prefix_list_id" in outputs

    def test_origin_timeouts_reasonable(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        assert cfg["origin_keepalive_timeout"] <= 60
        assert cfg["origin_read_timeout"] <= 60


# =========================================================================
# TestWAFBypass (~10 tests)
# =========================================================================
@requires_hcl2
class TestWAFBypass:
    """Prevent attackers from bypassing WAF inspection at edge."""

    def test_body_size_limit_rule_exists(self, waf):
        rule = find_rule_by_name(waf, "body-size-limit")
        assert rule is not None

    def test_body_size_limit_threshold(self, waf):
        rule = find_rule_by_name(waf, "body-size-limit")
        stmt = rule["statement"][0]["size_constraint_statement"][0]
        assert stmt["size"] <= 8192, "Body limit should be <= 8KB"

    def test_body_size_limit_highest_priority(self, waf):
        rule = find_rule_by_name(waf, "body-size-limit")
        all_rules = find_rules_in_waf(waf)
        for other in all_rules:
            if other["name"] != "body-size-limit":
                assert rule["priority"] < other["priority"], (
                    f"body-size-limit priority ({rule['priority']}) should be "
                    f"lower than {other['name']} ({other['priority']})"
                )

    def test_body_size_limit_uses_action_block(self, waf):
        """In block mode, body-size-limit should use action (not override_action)."""
        rule = find_rule_by_name(waf, "body-size-limit")
        assert "action" in rule
        assert "override_action" not in rule

    def test_managed_rules_use_override_action(self, waf):
        for name in ["aws-common-rules", "aws-sqli-rules", "aws-known-bad-inputs"]:
            rule = find_rule_by_name(waf, name)
            assert "override_action" in rule, f"{name} should use override_action"

    def test_waf_scope_explicitly_cloudfront(self, waf):
        assert waf["scope"] == "CLOUDFRONT"

    def test_waf_default_action_allow(self, waf):
        default = waf.get("default_action")
        if isinstance(default, list):
            default = default[0]
        assert "allow" in default

    def test_visibility_config_sampled_on_all_rules(self, waf):
        for rule in find_rules_in_waf(waf):
            vis = rule.get("visibility_config")
            if isinstance(vis, list):
                vis = vis[0]
            assert vis["sampled_requests_enabled"] is True, (
                f"Rule {rule['name']} should have sampled_requests_enabled"
            )

    def test_cloudwatch_metrics_on_all_rules(self, waf):
        for rule in find_rules_in_waf(waf):
            vis = rule.get("visibility_config")
            if isinstance(vis, list):
                vis = vis[0]
            assert vis["cloudwatch_metrics_enabled"] is True

    def test_metric_names_include_environment(self, waf):
        for rule in find_rules_in_waf(waf):
            vis = rule.get("visibility_config")
            if isinstance(vis, list):
                vis = vis[0]
            metric = vis.get("metric_name", "")
            assert "var.environment" in metric or "${var.environment}" in metric, (
                f"Metric for {rule['name']} should include environment"
            )


# =========================================================================
# TestCachePoisoning (~6 tests)
# =========================================================================
@requires_hcl2
class TestCachePoisoning:
    """Prevent cache poisoning by ensuring no caching."""

    def test_caching_disabled_policy(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        # CachingDisabled managed policy ID
        assert behavior["cache_policy_id"] == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

    def test_no_forwarded_values_block(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert "forwarded_values" not in behavior

    def test_no_custom_cache_policies(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        # The only cache_policy_id should be CachingDisabled
        policy_id = behavior["cache_policy_id"]
        assert policy_id == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

    def test_compress_enabled(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert behavior["compress"] is True

    def test_no_additional_cache_behaviors(self, distribution):
        assert "ordered_cache_behavior" not in distribution

    def test_origin_request_policy_forwards_all(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        # AllViewer managed policy ID
        assert behavior["origin_request_policy_id"] == "216adef6-5c7f-47e4-b989-5492eafa07d3"


# =========================================================================
# TestTLSDowngrade (~6 tests)
# =========================================================================
@requires_hcl2
class TestTLSDowngrade:
    """Prevent TLS downgrade attacks."""

    def test_viewer_minimum_tls_high(self, distribution):
        cert = distribution["viewer_certificate"][0]
        mpv = cert.get("minimum_protocol_version", "")
        assert "TLSv1.2_2021" in mpv

    def test_origin_ssl_tls12_only(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        assert cfg["origin_ssl_protocols"] == ["TLSv1.2"]

    def test_ssl_support_sni_only(self, distribution):
        cert = distribution["viewer_certificate"][0]
        method = cert.get("ssl_support_method", "")
        assert "sni-only" in method

    def test_no_sslv3_in_origin(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        assert "SSLv3" not in cfg["origin_ssl_protocols"]

    def test_no_tlsv1_in_origin(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        # TLSv1.2 contains "TLSv1" as a substring — check exact match
        assert cfg["origin_ssl_protocols"] == ["TLSv1.2"]

    def test_no_tlsv11_in_origin(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        assert "TLSv1.1" not in cfg["origin_ssl_protocols"]


# =========================================================================
# TestDNSHijacking (~4 tests)
# =========================================================================
@requires_hcl2
class TestDNSHijacking:
    """Prevent DNS hijacking by exporting required DNS integration values."""

    def test_aliases_from_variable(self, distribution):
        aliases = distribution.get("aliases", "")
        assert "var.customer_domains" in str(aliases)

    def test_hosted_zone_id_exported(self, cf_parsed):
        outputs = find_outputs(cf_parsed)
        assert "distribution_hosted_zone_id" in outputs

    def test_domain_name_exported(self, cf_parsed):
        outputs = find_outputs(cf_parsed)
        assert "distribution_domain_name" in outputs

    def test_distribution_arn_exported(self, cf_parsed):
        outputs = find_outputs(cf_parsed)
        assert "distribution_arn" in outputs


# =========================================================================
# TestGeoRestriction (~4 tests)
# =========================================================================
@requires_hcl2
class TestGeoRestriction:
    """Verify geo restriction configuration."""

    def test_geo_restriction_block_present(self, distribution):
        restrictions = distribution.get("restrictions")
        assert restrictions is not None

    def test_restriction_type_from_variable(self, distribution):
        restrictions = distribution["restrictions"][0]
        geo = restrictions["geo_restriction"][0]
        assert "var.geo_restriction_type" in geo["restriction_type"]

    def test_locations_from_variable(self, distribution):
        restrictions = distribution["restrictions"][0]
        geo = restrictions["geo_restriction"][0]
        assert "var.geo_restriction_locations" in str(geo["locations"])

    def test_default_is_none(self, cf_parsed):
        variables = find_variables(cf_parsed)
        assert variables["geo_restriction_type"]["default"] == "none"


# =========================================================================
# TestLogging (~5 tests)
# =========================================================================
@requires_hcl2
class TestLogging:
    """Verify CloudFront access logging configuration."""

    def test_logging_conditional_on_variable(self, distribution):
        dynamic = distribution.get("dynamic", [])
        assert len(dynamic) > 0
        logging = dynamic[0].get("logging_config", {})
        for_each = logging.get("for_each", "")
        assert "var.enable_logging" in for_each

    def test_log_bucket_from_variable(self, distribution):
        dynamic = distribution.get("dynamic", [])
        logging = dynamic[0].get("logging_config", {})
        content = logging.get("content", [{}])[0]
        assert "var.log_bucket_domain_name" in content.get("bucket", "")

    def test_log_prefix_includes_environment(self, distribution):
        dynamic = distribution.get("dynamic", [])
        logging = dynamic[0].get("logging_config", {})
        content = logging.get("content", [{}])[0]
        prefix = content.get("prefix", "")
        assert "var.environment" in prefix or "${var.environment}" in prefix

    def test_cookies_disabled(self, distribution):
        dynamic = distribution.get("dynamic", [])
        logging = dynamic[0].get("logging_config", {})
        content = logging.get("content", [{}])[0]
        assert content.get("include_cookies") is False

    def test_no_stdout_logging(self, distribution):
        # CloudFront should only log to S3, not stdout
        assert "provisioner" not in distribution


# =========================================================================
# TestResourceNaming (~6 tests)
# =========================================================================
@requires_hcl2
class TestResourceNaming:
    """Verify resource naming and tagging conventions."""

    def test_distribution_comment_includes_environment(self, distribution):
        comment = distribution.get("comment", "")
        assert "var.environment" in comment or "${var.environment}" in comment

    def test_waf_name_includes_environment(self, waf):
        name = waf.get("name", "")
        assert "var.environment" in name or "${var.environment}" in name

    def test_all_resources_tagged_environment(self, distribution, waf):
        for resource in [distribution, waf]:
            tags = get_tags(resource)
            assert "Environment" in tags

    def test_all_resources_tagged_project(self, distribution, waf):
        for resource in [distribution, waf]:
            tags = get_tags(resource)
            assert tags.get("Project") == "shieldai"

    def test_all_resources_tagged_module(self, distribution, waf):
        for resource in [distribution, waf]:
            tags = get_tags(resource)
            assert tags.get("Module") == "cloudfront-saas"

    def test_no_hardcoded_account_ids(self, cf_parsed):
        """Scan all variable defaults for hardcoded AWS account IDs."""
        variables = find_variables(cf_parsed)
        for name, attrs in variables.items():
            default = str(attrs.get("default", ""))
            # AWS account IDs are 12 digits
            assert not (default.isdigit() and len(default) == 12), (
                f"Variable {name} has hardcoded account ID: {default}"
            )


# =========================================================================
# TestRootModuleIntegration (~6 tests)
# =========================================================================
@requires_hcl2
class TestRootModuleIntegration:
    """Verify CloudFront module is wired into root Terraform module."""

    def test_root_has_cloudfront_module(self, root_parsed):
        modules = find_modules(root_parsed)
        assert "cloudfront_saas" in modules

    def test_module_conditional_on_enable_cloudfront(self, root_parsed):
        modules = find_modules(root_parsed)
        cf = modules["cloudfront_saas"]
        count = cf.get("count", "")
        assert "enable_cloudfront" in str(count)

    def test_module_receives_alb_dns_name(self, root_parsed):
        modules = find_modules(root_parsed)
        cf = modules["cloudfront_saas"]
        assert "module.proxy_ecs.alb_dns_name" in str(cf.get("alb_dns_name", ""))

    def test_module_receives_response_headers_policy(self, root_parsed):
        modules = find_modules(root_parsed)
        cf = modules["cloudfront_saas"]
        assert "module.security_headers.response_headers_policy_id" in str(
            cf.get("response_headers_policy_id", "")
        )

    def test_root_has_cloudfront_variables(self, root_parsed):
        variables = find_variables(root_parsed)
        assert "enable_cloudfront" in variables
        assert "cloudfront_origin_verify_secret" in variables
        assert "cloudfront_price_class" in variables

    def test_root_exports_cloudfront_outputs(self, root_parsed):
        outputs = find_outputs(root_parsed)
        assert "cloudfront_distribution_id" in outputs
        assert "cloudfront_distribution_domain_name" in outputs
        assert "cloudfront_waf_arn" in outputs


# =========================================================================
# TestALBOriginProtection (~6 tests)
# =========================================================================
@requires_hcl2
class TestALBOriginProtection:
    """Verify ALB security group restricts to CloudFront when enabled."""

    def test_restrict_to_cloudfront_variable_exists(self, ecs_parsed):
        variables = find_variables(ecs_parsed)
        assert "restrict_to_cloudfront" in variables

    def test_restrict_defaults_to_false(self, ecs_parsed):
        variables = find_variables(ecs_parsed)
        assert variables["restrict_to_cloudfront"]["default"] is False

    def test_origin_verify_secret_variable_exists(self, ecs_parsed):
        variables = find_variables(ecs_parsed)
        assert "origin_verify_secret" in variables

    def test_origin_verify_secret_is_sensitive(self, ecs_parsed):
        variables = find_variables(ecs_parsed)
        assert variables["origin_verify_secret"].get("sensitive") is True

    def test_cloudfront_prefix_list_variable_exists(self, ecs_parsed):
        variables = find_variables(ecs_parsed)
        assert "cloudfront_prefix_list_id" in variables

    def test_alb_security_group_id_output_exists(self, ecs_parsed):
        outputs = find_outputs(ecs_parsed)
        assert "alb_security_group_id" in outputs


# =========================================================================
# TestTLSDowngradePrevention (~4 tests) — Security Hardening Round 1
# =========================================================================
@requires_hcl2
class TestTLSDowngradePrevention:
    """Prevent silent TLS downgrade when using CloudFront default certificate.

    AWS limitation: CloudFront default cert (*.cloudfront.net) only supports
    TLS 1.0 minimum. Custom ACM certs enforce TLSv1.2_2021.
    The precondition on the distribution resource prevents deployment with
    customer_domains but no ACM cert — avoiding a silent TLS 1.0 fallback.
    """

    def test_lifecycle_precondition_exists(self, distribution):
        lifecycle = distribution.get("lifecycle")
        assert lifecycle is not None, "Distribution should have lifecycle block"
        assert isinstance(lifecycle, list) and len(lifecycle) > 0

    def test_precondition_checks_cert_and_domains(self, distribution):
        lifecycle = distribution["lifecycle"][0]
        preconditions = lifecycle.get("precondition", [])
        assert len(preconditions) > 0, "Should have at least one precondition"
        condition = preconditions[0].get("condition", "")
        assert "customer_domains" in condition
        assert "cloudfront_certificate_arn" in condition

    def test_precondition_error_mentions_tls_downgrade(self, distribution):
        lifecycle = distribution["lifecycle"][0]
        preconditions = lifecycle.get("precondition", [])
        error_msg = preconditions[0].get("error_message", "")
        assert "TLS" in error_msg.upper() or "tls" in error_msg.lower()

    def test_require_custom_cert_variable_defaults_true(self, cf_parsed):
        variables = find_variables(cf_parsed)
        var = variables.get("require_custom_cert_for_domains")
        assert var is not None, "require_custom_cert_for_domains variable should exist"
        assert var.get("default") is True, "Should default to true (safe-by-default)"

    def test_default_cert_fallback_documented(self, distribution):
        """The minimum_protocol_version ternary explicitly shows TLSv1 fallback."""
        cert = distribution["viewer_certificate"][0]
        mpv = cert.get("minimum_protocol_version", "")
        # Both branches must be visible in the ternary
        assert "TLSv1.2_2021" in mpv, "Custom cert path must use TLSv1.2_2021"
        assert "TLSv1" in mpv, "Default cert path shows TLSv1 (AWS limitation)"


# =========================================================================
# TestOriginHeaderVerification (~5 tests) — Security Hardening Round 1
# =========================================================================
@requires_hcl2
class TestOriginHeaderVerification:
    """Verify that the ALB enforces X-ShieldAI-Origin-Verify header check.

    Defense-in-depth: SG prefix list is the primary control, ALB listener
    rules provide application-layer header verification as a secondary control.
    """

    def test_allow_verified_origin_rule_exists(self, ecs_parsed):
        rules = find_resources(ecs_parsed, "aws_lb_listener_rule")
        names = []
        for r in rules:
            names.extend(r.keys())
        assert "allow_verified_origin" in names

    def test_deny_unverified_origin_rule_exists(self, ecs_parsed):
        rules = find_resources(ecs_parsed, "aws_lb_listener_rule")
        names = []
        for r in rules:
            names.extend(r.keys())
        assert "deny_unverified_origin" in names

    def test_allow_rule_checks_header(self, ecs_parsed):
        rule = find_resource(ecs_parsed, "aws_lb_listener_rule", "allow_verified_origin")
        conditions = rule.get("condition", [])
        assert len(conditions) > 0
        header_cond = conditions[0].get("http_header", [{}])[0]
        assert header_cond.get("http_header_name") == "X-ShieldAI-Origin-Verify"

    def test_deny_rule_returns_403(self, ecs_parsed):
        rule = find_resource(ecs_parsed, "aws_lb_listener_rule", "deny_unverified_origin")
        action = rule.get("action", [{}])[0]
        assert action.get("type") == "fixed-response"
        resp = action.get("fixed_response", [{}])[0]
        assert resp.get("status_code") == "403"

    def test_rules_conditional_on_restrict_to_cloudfront(self, ecs_parsed):
        for name in ["allow_verified_origin", "deny_unverified_origin"]:
            rule = find_resource(ecs_parsed, "aws_lb_listener_rule", name)
            count = rule.get("count", "")
            assert "restrict_to_cloudfront" in str(count), (
                f"{name} should be conditional on restrict_to_cloudfront"
            )

    def test_allow_rule_higher_priority_than_deny(self, ecs_parsed):
        allow = find_resource(ecs_parsed, "aws_lb_listener_rule", "allow_verified_origin")
        deny = find_resource(ecs_parsed, "aws_lb_listener_rule", "deny_unverified_origin")
        assert allow["priority"] < deny["priority"], (
            "Allow rule must have higher priority (lower number) than deny rule"
        )


# =========================================================================
# TestRegionConstraint (~3 tests) — Security Hardening Round 1
# =========================================================================
@requires_hcl2
class TestRegionConstraint:
    """Verify CloudFront module requires us-east-1 for WAF and ACM certs."""

    def test_region_check_block_exists(self, root_parsed):
        checks = root_parsed.get("check", [])
        assert len(checks) > 0, "Root module should have check blocks"
        check_names = []
        for c in checks:
            check_names.extend(c.keys())
        assert "cloudfront_region_check" in check_names

    def test_region_check_references_us_east_1(self, root_parsed):
        checks = root_parsed.get("check", [])
        for c in checks:
            if "cloudfront_region_check" in c:
                asserts = c["cloudfront_region_check"].get("assert", [])
                assert len(asserts) > 0
                condition = asserts[0].get("condition", "")
                assert "us-east-1" in condition

    def test_region_check_references_enable_cloudfront(self, root_parsed):
        checks = root_parsed.get("check", [])
        for c in checks:
            if "cloudfront_region_check" in c:
                asserts = c["cloudfront_region_check"].get("assert", [])
                condition = asserts[0].get("condition", "")
                assert "enable_cloudfront" in condition


# =========================================================================
# TestNoDeadCode (~2 tests) — Security Hardening Round 1
# =========================================================================
@requires_hcl2
class TestNoDeadCode:
    """Ensure no dead code or unused locals in the CloudFront module."""

    def test_no_unused_waf_action_local(self, cf_parsed):
        """The waf_action local was removed — only use_custom_cert should remain."""
        locals_list = cf_parsed.get("locals", [])
        all_local_keys = set()
        for local_block in locals_list:
            all_local_keys.update(local_block.keys())
        assert "waf_action" not in all_local_keys, "Dead waf_action local should be removed"

    def test_use_custom_cert_local_exists(self, cf_parsed):
        locals_list = cf_parsed.get("locals", [])
        all_local_keys = set()
        for local_block in locals_list:
            all_local_keys.update(local_block.keys())
        assert "use_custom_cert" in all_local_keys
