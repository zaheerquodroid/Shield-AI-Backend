"""Story/Acceptance Criteria tests for SHIELD-40: CloudFront SaaS Manager.

Validates the 5 acceptance criteria for the multi-tenant CloudFront distribution.
"""

from __future__ import annotations

import pytest

from tests.helpers.terraform import (
    find_modules,
    find_outputs,
    find_resource,
    find_resources,
    find_rule_by_name,
    find_rules_in_waf,
    find_variables,
    get_tags,
    parse_cloudfront_module,
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
def distribution(cf_parsed):
    return find_resource(cf_parsed, "aws_cloudfront_distribution", "proxy")


@pytest.fixture(scope="module")
def waf(cf_parsed):
    return find_resource(cf_parsed, "aws_wafv2_web_acl", "cloudfront")


# =========================================================================
# AC1: Multi-Tenant Distribution (~5 tests)
# =========================================================================
@requires_hcl2
class TestAC1_MultiTenantDistribution:
    """A single CloudFront distribution serves all tenant domains."""

    def test_distribution_resource_exists(self, cf_parsed):
        resources = find_resources(cf_parsed, "aws_cloudfront_distribution")
        assert len(resources) == 1, "Exactly one distribution for multi-tenant"

    def test_customer_domains_wired_to_aliases(self, distribution):
        aliases = distribution.get("aliases", "")
        assert "var.customer_domains" in str(aliases)

    def test_origin_points_to_security_proxy_alb(self, distribution):
        origin = distribution["origin"][0]
        assert "var.alb_dns_name" in origin["domain_name"]

    def test_single_distribution_serves_all_tenants(self, cf_parsed):
        """Only one distribution — no per-tenant distributions."""
        dists = find_resources(cf_parsed, "aws_cloudfront_distribution")
        assert len(dists) == 1

    def test_environment_tag_matches(self, distribution):
        tags = get_tags(distribution)
        assert "Environment" in tags
        assert "var.environment" in tags["Environment"]


# =========================================================================
# AC2: WAF Inheritance (~4 tests)
# =========================================================================
@requires_hcl2
class TestAC2_WAFInheritance:
    """All tenants inherit edge WAF protection (defense-in-depth)."""

    def test_waf_attached_to_distribution(self, distribution):
        acl_id = distribution.get("web_acl_id", "")
        assert "aws_wafv2_web_acl.cloudfront" in acl_id

    def test_all_managed_rule_groups_present(self, waf):
        rules = find_rules_in_waf(waf)
        rule_names = {r["name"] for r in rules}
        assert "aws-common-rules" in rule_names
        assert "aws-sqli-rules" in rule_names
        assert "aws-known-bad-inputs" in rule_names

    def test_rate_limiting_rules_present(self, waf):
        rules = find_rules_in_waf(waf)
        rule_names = {r["name"] for r in rules}
        assert "auth-rate-limit" in rule_names
        assert "global-rate-limit" in rule_names

    def test_all_tenants_inherit_waf(self, cf_parsed):
        """Only one WAF — all tenants share it via the single distribution."""
        wafs = find_resources(cf_parsed, "aws_wafv2_web_acl")
        assert len(wafs) == 1


# =========================================================================
# AC3: Security Headers (~4 tests)
# =========================================================================
@requires_hcl2
class TestAC3_SecurityHeaders:
    """Security headers applied via CloudFront response headers policy."""

    def test_response_headers_policy_wired(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        rhp = behavior.get("response_headers_policy_id", "")
        assert "var.response_headers_policy_id" in rhp

    def test_no_lambda_edge_needed(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert "lambda_function_association" not in behavior

    def test_no_cloudfront_function_needed(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert "function_association" not in behavior

    def test_headers_applied_to_default_behavior(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert "response_headers_policy_id" in behavior


# =========================================================================
# AC4: Tenant Template (~3 tests)
# =========================================================================
@requires_hcl2
class TestAC4_TenantTemplate:
    """Tenant onboarding via customer_domains variable."""

    def test_customer_domains_variable_accepts_list(self, cf_parsed):
        variables = find_variables(cf_parsed)
        cd = variables["customer_domains"]
        assert "list" in str(cd.get("type", ""))

    def test_aliases_populated_from_variable(self, distribution):
        aliases = distribution.get("aliases", "")
        assert "var.customer_domains" in str(aliases)

    def test_certificate_arn_wired(self, distribution):
        cert = distribution["viewer_certificate"][0]
        arn = cert.get("acm_certificate_arn", "")
        assert "var.cloudfront_certificate_arn" in arn


# =========================================================================
# AC5: TLS Enforcement (~4 tests)
# =========================================================================
@requires_hcl2
class TestAC5_TLSEnforcement:
    """TLS 1.2+ enforced on viewer and origin sides."""

    def test_tls12_plus_viewer_side(self, distribution):
        cert = distribution["viewer_certificate"][0]
        mpv = cert.get("minimum_protocol_version", "")
        assert "TLSv1.2_2021" in mpv

    def test_https_only_origin(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        assert cfg["origin_protocol_policy"] == "https-only"

    def test_redirect_http_to_https(self, distribution):
        behavior = distribution["default_cache_behavior"][0]
        assert behavior["viewer_protocol_policy"] == "redirect-to-https"

    def test_no_legacy_tls_in_origin(self, distribution):
        origin = distribution["origin"][0]
        cfg = origin["custom_origin_config"][0]
        protocols = cfg["origin_ssl_protocols"]
        for bad in ["SSLv3", "TLSv1", "TLSv1.1"]:
            assert bad not in protocols, f"{bad} should not be in origin_ssl_protocols"
