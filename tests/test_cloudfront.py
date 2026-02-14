"""Unit tests for CloudFront SaaS multi-tenant distribution module.

Tests HCL structure, TLS security, WAF integration, cache behavior,
variables, and outputs for the cloudfront-saas Terraform module.
"""

from __future__ import annotations

import pytest

from tests.helpers.terraform import (
    find_data_sources,
    find_outputs,
    find_resource,
    find_resources,
    find_rule_by_name,
    find_rules_in_waf,
    find_variables,
    get_resource_attr,
    get_tags,
    parse_cloudfront_module,
    requires_hcl2,
)


@pytest.fixture(scope="module")
def parsed():
    """Parse the cloudfront-saas module once for all tests."""
    return parse_cloudfront_module()


@pytest.fixture(scope="module")
def distribution(parsed):
    """CloudFront distribution resource."""
    return find_resource(parsed, "aws_cloudfront_distribution", "proxy")


@pytest.fixture(scope="module")
def waf(parsed):
    """CloudFront WAF WebACL resource."""
    return find_resource(parsed, "aws_wafv2_web_acl", "cloudfront")


@pytest.fixture(scope="module")
def variables(parsed):
    """All module variables."""
    return find_variables(parsed)


@pytest.fixture(scope="module")
def outputs(parsed):
    """All module outputs."""
    return find_outputs(parsed)


# =========================================================================
# TestDistributionStructure (~10 tests)
# =========================================================================
@requires_hcl2
class TestDistributionStructure:
    """Verify the CloudFront distribution resource structure."""

    def test_distribution_resource_exists(self, parsed):
        resources = find_resources(parsed, "aws_cloudfront_distribution")
        assert len(resources) >= 1, "CloudFront distribution resource should exist"

    def test_origin_points_to_alb(self, distribution):
        origin = distribution.get("origin")
        assert origin is not None, "Origin block should exist"
        assert isinstance(origin, list) and len(origin) > 0
        origin_cfg = origin[0]
        assert origin_cfg.get("domain_name") == "${var.alb_dns_name}"
        assert "custom_origin_config" in origin_cfg

    def test_origin_protocol_https_only(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        assert cfg["origin_protocol_policy"] == "https-only"

    def test_origin_ssl_protocols_tls12_only(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        protocols = cfg["origin_ssl_protocols"]
        assert protocols == ["TLSv1.2"], f"Expected [TLSv1.2], got {protocols}"

    def test_custom_origin_header_present(self, distribution):
        origin = distribution["origin"][0]
        headers = origin.get("custom_header", [])
        assert len(headers) > 0, "Custom origin header should exist"
        header = headers[0]
        assert header["name"] == "X-ShieldAI-Origin-Verify"

    def test_caching_disabled_policy(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert behavior["cache_policy_id"] == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

    def test_allviewer_origin_request_policy(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert behavior["origin_request_policy_id"] == "216adef6-5c7f-47e4-b989-5492eafa07d3"

    def test_response_headers_policy_wired(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert "response_headers_policy_id" in behavior
        assert "var.response_headers_policy_id" in behavior["response_headers_policy_id"]

    def test_ipv6_enabled(self, distribution):
        assert distribution["is_ipv6_enabled"] is True

    def test_tags_present(self, distribution):
        tags = get_tags(distribution)
        assert tags.get("Project") == "shieldai"
        assert tags.get("Module") == "cloudfront-saas"
        assert tags.get("ManagedBy") == "terraform"
        assert "Environment" in tags


# =========================================================================
# TestTLSSecurity (~5 tests)
# =========================================================================
@requires_hcl2
class TestTLSSecurity:
    """Verify TLS 1.2+ enforcement on viewer and origin sides."""

    def test_viewer_certificate_sni_only(self, distribution):
        cert = distribution["viewer_certificate"][0]
        # When custom cert is used, ssl_support_method should be sni-only
        ssl_method = cert.get("ssl_support_method", "")
        assert "sni-only" in ssl_method

    def test_minimum_protocol_tls12_2021(self, distribution):
        cert = distribution["viewer_certificate"][0]
        mpv = cert.get("minimum_protocol_version", "")
        assert "TLSv1.2_2021" in mpv

    def test_acm_certificate_wired(self, distribution):
        cert = distribution["viewer_certificate"][0]
        arn = cert.get("acm_certificate_arn", "")
        assert "var.cloudfront_certificate_arn" in arn

    def test_default_cert_fallback(self, distribution):
        cert = distribution["viewer_certificate"][0]
        default = cert.get("cloudfront_default_certificate", "")
        # Should use default cert when no custom cert provided
        assert "local.use_custom_cert" in str(default)

    def test_origin_keepalive_and_read_timeout(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        assert cfg["origin_keepalive_timeout"] == 60
        assert cfg["origin_read_timeout"] == 60


# =========================================================================
# TestWAFIntegration (~8 tests)
# =========================================================================
@requires_hcl2
class TestWAFIntegration:
    """Verify CloudFront WAF WebACL structure and rules."""

    def test_waf_resource_exists(self, parsed):
        resources = find_resources(parsed, "aws_wafv2_web_acl")
        assert len(resources) >= 1

    def test_waf_scope_cloudfront(self, waf):
        assert waf["scope"] == "CLOUDFRONT"

    def test_web_acl_wired_to_distribution(self, distribution):
        acl_id = distribution.get("web_acl_id", "")
        assert "aws_wafv2_web_acl.cloudfront.arn" in acl_id

    def test_body_size_limit_rule_exists(self, waf):
        rule = find_rule_by_name(waf, "body-size-limit")
        assert rule is not None, "body-size-limit rule should exist"
        assert rule["priority"] == 5

    def test_common_rules_present(self, waf):
        rule = find_rule_by_name(waf, "aws-common-rules")
        assert rule is not None
        assert rule["priority"] == 10

    def test_sqli_rules_present(self, waf):
        rule = find_rule_by_name(waf, "aws-sqli-rules")
        assert rule is not None
        assert rule["priority"] == 20

    def test_known_bad_inputs_present(self, waf):
        rule = find_rule_by_name(waf, "aws-known-bad-inputs")
        assert rule is not None
        assert rule["priority"] == 30

    def test_auth_rate_limit_present(self, waf):
        rule = find_rule_by_name(waf, "auth-rate-limit")
        assert rule is not None
        assert rule["priority"] == 40

    def test_global_rate_limit_present(self, waf):
        rule = find_rule_by_name(waf, "global-rate-limit")
        assert rule is not None
        assert rule["priority"] == 50

    def test_bot_control_conditional(self, waf):
        # Bot control is in the dynamic block, not in static rules
        dynamic = waf.get("dynamic", [])
        assert len(dynamic) > 0
        bot_rule = dynamic[0].get("rule", {})
        assert "enable_bot_control" in bot_rule.get("for_each", "")

    def test_waf_visibility_config(self, waf):
        vis = waf.get("visibility_config")
        if isinstance(vis, list):
            vis = vis[0]
        assert vis["sampled_requests_enabled"] is True
        assert vis["cloudwatch_metrics_enabled"] is True


# =========================================================================
# TestCacheBehavior (~5 tests)
# =========================================================================
@requires_hcl2
class TestCacheBehavior:
    """Verify cache behavior is configured for no-caching proxy."""

    def test_all_http_methods_allowed(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        methods = behavior["allowed_methods"]
        assert len(methods) == 7
        assert set(methods) == {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}

    def test_cached_methods_get_head_only(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        cached = behavior["cached_methods"]
        assert set(cached) == {"GET", "HEAD"}

    def test_compress_enabled(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert behavior["compress"] is True

    def test_viewer_protocol_redirect_to_https(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert behavior["viewer_protocol_policy"] == "redirect-to-https"

    def test_no_additional_cache_behaviors(self, distribution):
        # Only default_cache_behavior, no ordered_cache_behavior
        assert "ordered_cache_behavior" not in distribution


# =========================================================================
# TestVariables (~6 tests)
# =========================================================================
@requires_hcl2
class TestVariables:
    """Verify module variable declarations."""

    def test_required_variables_declared(self, variables):
        required = ["environment", "alb_dns_name", "response_headers_policy_id", "origin_verify_secret"]
        for var_name in required:
            assert var_name in variables, f"Variable {var_name} should be declared"

    def test_price_class_has_validation(self, variables):
        pc = variables["price_class"]
        assert "validation" in pc, "price_class should have validation"

    def test_geo_restriction_type_has_validation(self, variables):
        grt = variables["geo_restriction_type"]
        assert "validation" in grt, "geo_restriction_type should have validation"

    def test_origin_verify_secret_is_sensitive(self, variables):
        secret = variables["origin_verify_secret"]
        assert secret.get("sensitive") is True

    def test_secure_defaults(self, variables):
        assert variables["price_class"].get("default") == "PriceClass_100"
        assert variables["geo_restriction_type"].get("default") == "none"
        assert variables["waf_block_mode"].get("default") is False

    def test_customer_domains_defaults_empty(self, variables):
        cd = variables["customer_domains"]
        assert cd.get("default") == []


# =========================================================================
# TestOutputs (~6 tests)
# =========================================================================
@requires_hcl2
class TestOutputs:
    """Verify module output declarations."""

    def test_distribution_id_output(self, outputs):
        assert "distribution_id" in outputs

    def test_distribution_domain_name_output(self, outputs):
        assert "distribution_domain_name" in outputs

    def test_distribution_arn_output(self, outputs):
        assert "distribution_arn" in outputs

    def test_distribution_hosted_zone_id_output(self, outputs):
        assert "distribution_hosted_zone_id" in outputs

    def test_waf_web_acl_arn_output(self, outputs):
        assert "waf_web_acl_arn" in outputs

    def test_cloudfront_prefix_list_id_output(self, outputs):
        assert "cloudfront_prefix_list_id" in outputs
