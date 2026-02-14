"""Unit tests for ShieldAI NetworkPolicy Helm chart.

Tests cover rendering, default-deny policies, DNS/HTTPS/callback egress,
explicit policyTypes, and values defaults.
"""

from __future__ import annotations

import pytest

from tests.helpers.helm import (
    default_callback_values,
    find_policies,
    find_policy,
    get_egress_ports,
    get_egress_rules,
    get_except_cidrs,
    get_ingress_rules,
    get_pod_selector,
    get_policy_types,
    render_chart,
    render_chart_error,
    render_default,
    requires_helm,
)


# ---------------------------------------------------------------------------
# TestHelmRendering — basic chart rendering
# ---------------------------------------------------------------------------


@requires_helm
class TestHelmRendering:
    """Verify basic Helm chart rendering and structure."""

    def test_renders_without_error(self):
        docs = render_default()
        assert len(docs) > 0

    def test_renders_five_policies(self):
        docs = render_default()
        policies = find_policies(docs)
        assert len(policies) == 5

    def test_all_networkpolicies_have_correct_kind(self):
        docs = render_default()
        policies = find_policies(docs)
        for doc in policies:
            assert doc["kind"] == "NetworkPolicy"

    def test_api_version(self):
        docs = render_default()
        policies = find_policies(docs)
        for doc in policies:
            assert doc["apiVersion"] == "networking.k8s.io/v1"

    def test_default_namespace(self):
        docs = render_default()
        for doc in docs:
            assert doc["metadata"]["namespace"] == "default"

    def test_custom_namespace(self):
        values = default_callback_values()
        values["namespace"] = "tenant-alpha"
        docs = render_chart(values)
        for doc in docs:
            assert doc["metadata"]["namespace"] == "tenant-alpha"

    def test_labels_present(self):
        docs = render_default()
        for doc in docs:
            labels = doc["metadata"]["labels"]
            assert "app.kubernetes.io/name" in labels
            assert "app.kubernetes.io/instance" in labels
            assert "helm.sh/chart" in labels
            assert "app.kubernetes.io/managed-by" in labels

    def test_shieldai_policy_label(self):
        docs = render_default()
        for doc in docs:
            labels = doc["metadata"]["labels"]
            assert "shieldai.io/policy" in labels


# ---------------------------------------------------------------------------
# TestDefaultDenyIngress
# ---------------------------------------------------------------------------


@requires_helm
class TestDefaultDenyIngress:
    """Verify default-deny-ingress policy."""

    def test_exists(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        assert policy is not None

    def test_policy_types_ingress(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        assert get_policy_types(policy) == ["Ingress"]

    def test_pod_selector_empty(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        selector = get_pod_selector(policy)
        assert selector.get("matchLabels", {}) == {}

    def test_no_ingress_rules(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        assert get_ingress_rules(policy) == []

    def test_no_egress_rules(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        assert get_egress_rules(policy) == []

    def test_disable_flag(self):
        values = default_callback_values()
        values["policies"] = {"defaultDenyIngress": False}
        docs = render_chart(values)
        names = [d["metadata"]["name"] for d in docs]
        assert not any("default-deny-ingress" in n for n in names)


# ---------------------------------------------------------------------------
# TestDefaultDenyEgress
# ---------------------------------------------------------------------------


@requires_helm
class TestDefaultDenyEgress:
    """Verify default-deny-egress policy."""

    def test_exists(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-egress")
        assert policy is not None

    def test_policy_types_egress(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-egress")
        assert get_policy_types(policy) == ["Egress"]

    def test_pod_selector_empty(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-egress")
        selector = get_pod_selector(policy)
        assert selector.get("matchLabels", {}) == {}

    def test_no_egress_rules(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-egress")
        assert get_egress_rules(policy) == []

    def test_no_ingress_rules(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-egress")
        assert get_ingress_rules(policy) == []

    def test_disable_flag(self):
        values = default_callback_values()
        values["policies"] = {"defaultDenyEgress": False}
        docs = render_chart(values)
        names = [d["metadata"]["name"] for d in docs]
        assert not any("default-deny-egress" in n for n in names)


# ---------------------------------------------------------------------------
# TestDnsEgress
# ---------------------------------------------------------------------------


@requires_helm
class TestDnsEgress:
    """Verify allow-dns-egress policy."""

    def test_exists(self):
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        assert policy is not None

    def test_policy_types_egress(self):
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        assert get_policy_types(policy) == ["Egress"]

    def test_scoped_to_kube_system(self):
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        assert len(rules) == 1
        to = rules[0]["to"]
        ns_selector = to[0]["namespaceSelector"]["matchLabels"]
        assert ns_selector["kubernetes.io/metadata.name"] == "kube-system"

    def test_scoped_to_coredns_pods(self):
        """DNS egress should target CoreDNS pods, not all pods in kube-system."""
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        to = rules[0]["to"][0]
        assert "podSelector" in to
        pod_labels = to["podSelector"]["matchLabels"]
        assert pod_labels.get("k8s-app") == "kube-dns"

    def test_udp_port_53(self):
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        ports = get_egress_ports(policy)
        udp_ports = [p for p in ports if p["protocol"] == "UDP"]
        assert len(udp_ports) == 1
        assert udp_ports[0]["port"] == 53

    def test_tcp_port_53(self):
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        ports = get_egress_ports(policy)
        tcp_ports = [p for p in ports if p["protocol"] == "TCP"]
        assert len(tcp_ports) == 1
        assert tcp_ports[0]["port"] == 53

    def test_no_other_ports(self):
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        ports = get_egress_ports(policy)
        assert len(ports) == 2  # UDP 53 + TCP 53

    def test_no_global_dns(self):
        """DNS is NOT allowed to all namespaces — only kube-system."""
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        for rule in rules:
            for to in rule.get("to", []):
                if "namespaceSelector" in to:
                    labels = to["namespaceSelector"].get("matchLabels", {})
                    assert labels.get("kubernetes.io/metadata.name") == "kube-system"

    def test_custom_dns_namespace(self):
        values = default_callback_values()
        values["dns"] = {"namespace": "dns-system", "podLabels": {"k8s-app": "kube-dns"}}
        docs = render_chart(values)
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        ns_selector = rules[0]["to"][0]["namespaceSelector"]["matchLabels"]
        assert ns_selector["kubernetes.io/metadata.name"] == "dns-system"

    def test_custom_dns_port(self):
        values = default_callback_values()
        values["dns"] = {"port": 5353, "podLabels": {"k8s-app": "kube-dns"}}
        docs = render_chart(values)
        policy = find_policy(docs, "allow-dns-egress")
        ports = get_egress_ports(policy)
        for p in ports:
            assert p["port"] == 5353

    def test_disable_flag(self):
        values = default_callback_values()
        values["policies"] = {"allowDnsEgress": False}
        docs = render_chart(values)
        names = [d["metadata"]["name"] for d in docs]
        assert not any("allow-dns-egress" in n for n in names)


# ---------------------------------------------------------------------------
# TestHttpsEgress
# ---------------------------------------------------------------------------


@requires_helm
class TestHttpsEgress:
    """Verify allow-https-egress policy."""

    def test_exists(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        assert policy is not None

    def test_policy_types_egress(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        assert get_policy_types(policy) == ["Egress"]

    def test_cidr_0_0_0_0(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        rules = get_egress_rules(policy)
        ip_block = rules[0]["to"][0]["ipBlock"]
        assert ip_block["cidr"] == "0.0.0.0/0"

    def test_tcp_port_443(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        ports = get_egress_ports(policy)
        assert len(ports) == 1
        assert ports[0]["protocol"] == "TCP"
        assert ports[0]["port"] == 443

    def test_no_port_80(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        ports = get_egress_ports(policy)
        for p in ports:
            assert p["port"] != 80

    def test_blocks_rfc1918_10(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "10.0.0.0/8" in cidrs

    def test_blocks_rfc1918_172(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "172.16.0.0/12" in cidrs

    def test_blocks_rfc1918_192(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "192.168.0.0/16" in cidrs

    def test_blocks_metadata(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "169.254.0.0/16" in cidrs

    def test_except_list_complete(self):
        """All four required blocked CIDRs present in except list."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        required = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
        for cidr in required:
            assert cidr in cidrs, f"{cidr} missing from except list"

    def test_extra_blocked_cidrs(self):
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": ["44.0.0.0/8"],
        }
        docs = render_chart(values)
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "44.0.0.0/8" in cidrs

    def test_blocks_benchmarking_range(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "198.18.0.0/15" in cidrs

    def test_disable_flag(self):
        values = default_callback_values()
        values["policies"] = {"allowHttpsEgress": False}
        docs = render_chart(values)
        names = [d["metadata"]["name"] for d in docs]
        assert not any("allow-https-egress" in n for n in names)


# ---------------------------------------------------------------------------
# TestCallbackEgress
# ---------------------------------------------------------------------------


@requires_helm
class TestCallbackEgress:
    """Verify allow-callback-egress policy."""

    def test_exists(self):
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        assert policy is not None

    def test_policy_types_egress(self):
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        assert get_policy_types(policy) == ["Egress"]

    def test_specific_cidr(self):
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        ip_block = rules[0]["to"][0]["ipBlock"]
        assert ip_block["cidr"] == "203.0.113.10/32"

    def test_tcp_port_443(self):
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        ports = get_egress_ports(policy)
        assert len(ports) == 1
        assert ports[0]["protocol"] == "TCP"
        assert ports[0]["port"] == 443

    def test_fails_without_cidr(self):
        """Template must fail if callback.enabled but cidr is empty."""
        stderr = render_chart_error()
        assert "callback.cidr" in stderr
        assert "REQUIRED" in stderr

    def test_custom_cidr(self):
        values = {"callback": {"cidr": "198.51.100.0/24"}}
        docs = render_chart(values)
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        ip_block = rules[0]["to"][0]["ipBlock"]
        assert ip_block["cidr"] == "198.51.100.0/24"

    def test_slash_32_works(self):
        values = {"callback": {"cidr": "198.51.100.5/32"}}
        docs = render_chart(values)
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        assert rules[0]["to"][0]["ipBlock"]["cidr"] == "198.51.100.5/32"

    def test_custom_port(self):
        values = {"callback": {"cidr": "203.0.113.10/32", "port": 8443}}
        docs = render_chart(values)
        policy = find_policy(docs, "allow-callback-egress")
        ports = get_egress_ports(policy)
        assert ports[0]["port"] == 8443

    def test_disable_flag(self):
        values = {"policies": {"allowCallbackEgress": False}}
        docs = render_chart(values)
        names = [d["metadata"]["name"] for d in docs]
        assert not any("allow-callback-egress" in n for n in names)

    def test_no_except_list(self):
        """Callback policy should have no except list — it targets a specific CIDR."""
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        for rule in rules:
            for to in rule.get("to", []):
                ip_block = to.get("ipBlock", {})
                assert "except" not in ip_block


# ---------------------------------------------------------------------------
# TestPolicyTypesExplicit
# ---------------------------------------------------------------------------


@requires_helm
class TestPolicyTypesExplicit:
    """Every policy MUST have explicit policyTypes — missing policyTypes silently fails."""

    def test_all_policies_have_policy_types(self):
        docs = render_default()
        policies = find_policies(docs)
        for doc in policies:
            types = get_policy_types(doc)
            assert len(types) > 0, (
                f"Policy {doc['metadata']['name']} has no policyTypes"
            )

    def test_deny_ingress_type(self):
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        assert get_policy_types(policy) == ["Ingress"]

    def test_egress_policies_type(self):
        docs = render_default()
        egress_names = [
            "default-deny-egress",
            "allow-dns-egress",
            "allow-https-egress",
            "allow-callback-egress",
        ]
        for name in egress_names:
            policy = find_policy(docs, name)
            assert get_policy_types(policy) == ["Egress"], (
                f"Policy {name} should have policyTypes=[Egress]"
            )

    def test_no_mixed_types(self):
        """No NetworkPolicy should have both Ingress and Egress — separation of concerns."""
        docs = render_default()
        policies = find_policies(docs)
        for doc in policies:
            types = get_policy_types(doc)
            assert len(types) == 1, (
                f"Policy {doc['metadata']['name']} has mixed policyTypes: {types}"
            )


# ---------------------------------------------------------------------------
# TestValuesDefaults
# ---------------------------------------------------------------------------


@requires_helm
class TestValuesDefaults:
    """Verify default values are valid and complete."""

    def test_all_rfc1918_in_defaults(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "10.0.0.0/8" in cidrs
        assert "172.16.0.0/12" in cidrs
        assert "192.168.0.0/16" in cidrs

    def test_metadata_in_defaults(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "169.254.0.0/16" in cidrs

    def test_dns_defaults(self):
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        ns_label = rules[0]["to"][0]["namespaceSelector"]["matchLabels"]
        assert ns_label["kubernetes.io/metadata.name"] == "kube-system"
        ports = get_egress_ports(policy)
        port_numbers = {p["port"] for p in ports}
        assert port_numbers == {53}

    def test_all_policies_enabled_by_default(self):
        docs = render_default()
        policies = find_policies(docs)
        assert len(policies) == 5

    def test_loopback_in_defaults(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "127.0.0.0/8" in cidrs

    def test_this_network_in_defaults(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "0.0.0.0/8" in cidrs

    def test_cgnat_in_defaults(self):
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "100.64.0.0/10" in cidrs


# ---------------------------------------------------------------------------
# TestFailGuards — template fail-closed validations
# ---------------------------------------------------------------------------


@requires_helm
class TestFailGuards:
    """Verify template fail guards prevent silent fail-open configurations."""

    def test_empty_rfc1918_fails(self):
        """Removing RFC 1918 CIDRs must fail, not silently pass."""
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": [],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": [],
        }
        stderr = render_chart_error(values)
        assert "10.0.0.0/8" in stderr

    def test_missing_10_slash_8_fails(self):
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["172.16.0.0/12", "192.168.0.0/16"],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": [],
        }
        stderr = render_chart_error(values)
        assert "10.0.0.0/8" in stderr

    def test_missing_172_slash_12_fails(self):
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8", "192.168.0.0/16"],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": [],
        }
        stderr = render_chart_error(values)
        assert "172.16.0.0/12" in stderr

    def test_missing_192_slash_16_fails(self):
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8", "172.16.0.0/12"],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": [],
        }
        stderr = render_chart_error(values)
        assert "192.168.0.0/16" in stderr

    def test_missing_metadata_169_fails(self):
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "metadata": ["127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": [],
        }
        stderr = render_chart_error(values)
        assert "169.254.0.0/16" in stderr

    def test_too_few_total_cidrs_fails(self):
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8"],
            "metadata": ["169.254.0.0/16"],
            "extra": [],
        }
        stderr = render_chart_error(values)
        assert "at least 4" in stderr

    def test_callback_cidr_empty_fails(self):
        stderr = render_chart_error()
        assert "REQUIRED" in stderr
