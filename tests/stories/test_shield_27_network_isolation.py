"""Story-level acceptance tests for SHIELD-27: Network Isolation via Kubernetes NetworkPolicy.

AC1: Helm chart shieldai-security-policies created with NetworkPolicy resources
AC2: Default deny all ingress to customer workload namespaces
AC3: Egress allowed only to: DNS (kube-dns, port 53), HTTPS (port 443), callback API
AC4: Egress blocked to: internal cluster IPs, cloud metadata, other customer namespaces
AC5: NetworkPolicy applied per customer namespace via Helm values
AC6: Compromised test code cannot make lateral movements within the cluster
"""

from __future__ import annotations

import ipaddress
import os

import pytest
import yaml

from tests.helpers.helm import (
    CHART_DIR,
    default_callback_values,
    find_policy,
    get_egress_ports,
    get_egress_rules,
    get_except_cidrs,
    get_ingress_rules,
    get_pod_selector,
    get_policy_types,
    render_chart,
    render_default,
    requires_helm,
)


# ---------------------------------------------------------------------------
# AC1: Helm Chart Structure
# ---------------------------------------------------------------------------


@requires_helm
class TestAC1_HelmChartStructure:
    """AC1: Helm chart created with NetworkPolicy resources."""

    def test_chart_yaml_valid(self):
        chart_path = os.path.join(CHART_DIR, "Chart.yaml")
        assert os.path.exists(chart_path)
        with open(chart_path) as f:
            chart = yaml.safe_load(f)
        assert chart["apiVersion"] == "v2"
        assert chart["name"] == "shieldai-security-policies"
        assert "version" in chart

    def test_values_yaml_valid(self):
        values_path = os.path.join(CHART_DIR, "values.yaml")
        assert os.path.exists(values_path)
        with open(values_path) as f:
            values = yaml.safe_load(f)
        assert "policies" in values
        assert "blockedCIDRs" in values
        assert "dns" in values
        assert "https" in values
        assert "callback" in values

    def test_renders_networkpolicy_resources(self):
        docs = render_default()
        assert len(docs) == 5
        for doc in docs:
            assert doc["kind"] == "NetworkPolicy"
            assert doc["apiVersion"] == "networking.k8s.io/v1"


# ---------------------------------------------------------------------------
# AC2: Default Deny Ingress
# ---------------------------------------------------------------------------


@requires_helm
class TestAC2_DefaultDenyIngress:
    """AC2: Default deny all ingress to customer workload namespaces."""

    def test_deny_ingress_exists(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        assert policy is not None
        assert get_policy_types(policy) == ["Ingress"]
        # No ingress rules = deny all
        assert get_ingress_rules(policy) == []

    def test_applies_to_all_pods(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        selector = get_pod_selector(policy)
        assert selector.get("matchLabels", {}) == {}


# ---------------------------------------------------------------------------
# AC3: Egress Allowed
# ---------------------------------------------------------------------------


@requires_helm
class TestAC3_EgressAllowed:
    """AC3: Egress allowed only to DNS, HTTPS, and callback API."""

    def test_dns_to_kube_system(self):
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        assert len(rules) == 1
        ns_label = rules[0]["to"][0]["namespaceSelector"]["matchLabels"]
        assert ns_label["kubernetes.io/metadata.name"] == "kube-system"
        ports = get_egress_ports(policy)
        protocols = {p["protocol"] for p in ports}
        assert protocols == {"UDP", "TCP"}
        assert all(p["port"] == 53 for p in ports)

    def test_https_on_443(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        ports = get_egress_ports(policy)
        assert len(ports) == 1
        assert ports[0]["protocol"] == "TCP"
        assert ports[0]["port"] == 443

    def test_callback_with_specific_cidr(self):
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        cidr = rules[0]["to"][0]["ipBlock"]["cidr"]
        assert cidr == "203.0.113.10/32"
        ports = get_egress_ports(policy)
        assert ports[0]["port"] == 443


# ---------------------------------------------------------------------------
# AC4: Egress Blocked
# ---------------------------------------------------------------------------


@requires_helm
class TestAC4_EgressBlocked:
    """AC4: Egress blocked to internal cluster IPs, cloud metadata, other namespaces."""

    def test_rfc1918_and_metadata_in_except(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        required = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ]
        for cidr in required:
            assert cidr in cidrs, f"Missing {cidr} in except list"

    def test_metadata_ip_blocked(self):
        """169.254.169.254 (AWS/GCP/Azure IMDS) must be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        metadata_ip = ipaddress.ip_address("169.254.169.254")
        blocked = any(
            metadata_ip in ipaddress.ip_network(c) for c in cidrs
        )
        assert blocked


# ---------------------------------------------------------------------------
# AC5: Per Namespace
# ---------------------------------------------------------------------------


@requires_helm
class TestAC5_PerNamespace:
    """AC5: NetworkPolicy applied per customer namespace via Helm values."""

    def test_custom_namespace_applied(self):
        values = default_callback_values()
        values["namespace"] = "tenant-beta"
        docs = render_chart(values)
        assert len(docs) == 5
        for doc in docs:
            assert doc["metadata"]["namespace"] == "tenant-beta"


# ---------------------------------------------------------------------------
# AC6: Lateral Movement
# ---------------------------------------------------------------------------


@requires_helm
class TestAC6_LateralMovement:
    """AC6: Compromised test code cannot make lateral movements."""

    def test_no_cross_namespace_egress_except_dns(self):
        """Only DNS egress targets a specific namespace (kube-system).
        No other policy allows cross-namespace traffic.
        HTTPS and callback use ipBlock (not namespaceSelector).
        Default deny blocks everything else.
        """
        docs = render_default()
        for doc in docs:
            name = doc["metadata"]["name"]
            rules = get_egress_rules(doc)
            for rule in rules:
                for to in rule.get("to", []):
                    if "namespaceSelector" in to:
                        # Only DNS should have namespaceSelector
                        assert "dns" in name, (
                            f"Non-DNS policy {name} has namespaceSelector"
                        )
                        # And it must be scoped to kube-system
                        labels = to["namespaceSelector"]["matchLabels"]
                        assert labels["kubernetes.io/metadata.name"] == "kube-system"
