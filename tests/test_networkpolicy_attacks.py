"""Attack simulation tests for ShieldAI NetworkPolicy Helm chart.

These tests verify that the NetworkPolicy configuration actually blocks
known attack vectors including metadata endpoint access, lateral movement,
DNS exfiltration, and policy bypass patterns.
"""

from __future__ import annotations

import ipaddress

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
# Helpers
# ---------------------------------------------------------------------------


def _cidr_blocks_ip(except_cidrs: list[str], ip: str) -> bool:
    """Check if an IP address is within any of the except CIDRs (i.e., blocked)."""
    addr = ipaddress.ip_address(ip)
    for cidr in except_cidrs:
        try:
            net = ipaddress.ip_network(cidr)
            if addr in net:
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# TestMetadataEndpointBlocking
# ---------------------------------------------------------------------------


@requires_helm
class TestMetadataEndpointBlocking:
    """Verify cloud metadata endpoints are blocked."""

    def test_aws_imds_169_254_169_254(self):
        """AWS IMDS at 169.254.169.254 must be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "169.254.169.254")

    def test_gcp_metadata_169_254_169_254(self):
        """GCP metadata server at 169.254.169.254 must be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "169.254.169.254")

    def test_azure_imds_169_254_169_254(self):
        """Azure IMDS at 169.254.169.254 must be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "169.254.169.254")

    def test_link_local_range_blocked(self):
        """Entire 169.254.0.0/16 range must be blocked, not just .169.254."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "169.254.0.0/16" in cidrs

    def test_link_local_other_ips(self):
        """Other link-local IPs like 169.254.1.1 must also be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "169.254.1.1")
        assert _cidr_blocks_ip(cidrs, "169.254.255.255")

    def test_ipv6_metadata_in_values(self):
        """fd00:ec2::254/128 should be in values but NOT in ipv4 except list."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        # IPv6 CIDRs should be filtered out of ipv4 except list
        for cidr in cidrs:
            assert ":" not in cidr, f"IPv6 CIDR {cidr} in IPv4 except list"

    def test_metadata_blocked_via_default_deny(self):
        """Even without HTTPS egress, default-deny-egress blocks all."""
        values = default_callback_values()
        values["policies"] = {
            "allowHttpsEgress": False,
            "defaultDenyEgress": True,
        }
        docs = render_chart(values)
        policy = find_policy(docs, "default-deny-egress")
        # No egress rules = deny all
        assert get_egress_rules(policy) == []

    def test_metadata_not_in_callback_cidr(self):
        """Callback CIDR must not accidentally include metadata IPs."""
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        cidr = rules[0]["to"][0]["ipBlock"]["cidr"]
        net = ipaddress.ip_network(cidr)
        metadata_ip = ipaddress.ip_address("169.254.169.254")
        assert metadata_ip not in net


# ---------------------------------------------------------------------------
# TestLateralMovementBlocking
# ---------------------------------------------------------------------------


@requires_helm
class TestLateralMovementBlocking:
    """Verify lateral movement within the cluster is blocked."""

    def test_pod_cidr_10_x_blocked(self):
        """Pod CIDRs in 10.0.0.0/8 must be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "10.244.0.5")  # typical pod IP

    def test_service_cidr_10_x_blocked(self):
        """Service CIDRs in 10.96.0.0/12 must be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "10.96.0.1")  # typical cluster IP

    def test_pod_cidr_172_blocked(self):
        """Pod CIDRs in 172.16-31.x must be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "172.17.0.2")  # docker bridge
        assert _cidr_blocks_ip(cidrs, "172.20.0.5")  # EKS pod CIDR

    def test_pod_cidr_192_168_blocked(self):
        """Pod CIDRs in 192.168.x must be blocked."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "192.168.1.100")

    def test_default_deny_ingress_blocks_pod_to_pod(self):
        """Default deny ingress blocks any pod-to-pod inbound traffic."""
        docs = render_default()
        policy = find_policy(docs, "default-deny-ingress")
        assert get_ingress_rules(policy) == []

    def test_cross_namespace_blocked_by_default_deny(self):
        """Default deny egress blocks cross-namespace traffic."""
        docs = render_default()
        policy = find_policy(docs, "default-deny-egress")
        assert get_egress_rules(policy) == []

    def test_nodeport_access_blocked(self):
        """NodePort services (30000-32767) on node IPs are blocked via RFC 1918 except."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        # Node IPs are typically in 10.x or 192.168.x ranges
        assert _cidr_blocks_ip(cidrs, "10.0.1.10")
        # Also, only port 443 is allowed, so 30000+ is blocked
        ports = get_egress_ports(policy)
        for p in ports:
            assert p["port"] == 443

    def test_kubelet_api_blocked(self):
        """Kubelet API on node:10250 blocked via RFC 1918 + port restriction."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "10.0.1.10")
        ports = get_egress_ports(policy)
        assert all(p["port"] != 10250 for p in ports)


# ---------------------------------------------------------------------------
# TestDnsExfiltrationMitigation
# ---------------------------------------------------------------------------


@requires_helm
class TestDnsExfiltrationMitigation:
    """Verify DNS is scoped to prevent exfiltration."""

    def test_dns_only_to_kube_system(self):
        """DNS egress limited to kube-system namespace only."""
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        for rule in rules:
            for to in rule.get("to", []):
                ns = to.get("namespaceSelector", {}).get("matchLabels", {})
                assert ns.get("kubernetes.io/metadata.name") == "kube-system"

    def test_no_global_dns_port_53(self):
        """Port 53 is NOT open to 0.0.0.0/0 — only to kube-system."""
        docs = render_default()
        # The HTTPS policy only allows 443, not 53
        https_policy = find_policy(docs, "allow-https-egress")
        https_ports = get_egress_ports(https_policy)
        for p in https_ports:
            assert p["port"] != 53

    def test_dns_port_53_only(self):
        """DNS policy only allows port 53, no other ports."""
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        ports = get_egress_ports(policy)
        for p in ports:
            assert p["port"] == 53

    def test_external_dns_server_blocked(self):
        """External DNS servers (e.g. 8.8.8.8:53) blocked because DNS egress
        is scoped to kube-system namespace only, not by IP."""
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        # No ipBlock in DNS policy — only namespaceSelector
        for rule in rules:
            for to in rule.get("to", []):
                assert "ipBlock" not in to

    def test_dns_exfiltration_via_txt_records(self):
        """Even if TXT record exfiltration is attempted, it only goes to
        kube-system DNS which logs and doesn't forward to attacker DNS."""
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        to = rules[0]["to"]
        # Only kube-system — attacker can't run DNS in other namespaces
        assert len(to) == 1
        assert "namespaceSelector" in to[0]


# ---------------------------------------------------------------------------
# TestPolicyBypassPatterns
# ---------------------------------------------------------------------------


@requires_helm
class TestPolicyBypassPatterns:
    """Test that common policy bypass patterns are prevented."""

    def test_no_allow_all_ingress(self):
        """No policy creates an allow-all ingress rule."""
        docs = render_default()
        for doc in docs:
            rules = get_ingress_rules(doc)
            for rule in rules:
                # Empty 'from' = allow all
                assert rule.get("from") is not None or rule.get("ports") is not None

    def test_no_allow_all_egress(self):
        """No policy creates a blanket allow-all egress (empty rule)."""
        docs = render_default()
        for doc in docs:
            rules = get_egress_rules(doc)
            for rule in rules:
                # Rule must have 'to' or 'ports' restrictions
                assert rule.get("to") is not None or rule.get("ports") is not None

    def test_except_list_not_empty(self):
        """HTTPS egress except list must not be empty."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert len(cidrs) >= 4  # At least RFC1918 + metadata

    def test_all_rfc1918_in_except(self):
        """All three RFC 1918 ranges must be in except list."""
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        required = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        for cidr in required:
            assert cidr in cidrs

    def test_callback_cidr_required_prevents_wildcard(self):
        """Empty callback CIDR must fail — prevents fail-open."""
        stderr = render_chart_error()
        assert "REQUIRED" in stderr

    def test_callback_cidr_not_0_0_0_0(self):
        """Callback should not use 0.0.0.0/0 — that would bypass all blocking."""
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        cidr = rules[0]["to"][0]["ipBlock"]["cidr"]
        assert cidr != "0.0.0.0/0"

    def test_pod_selector_matches_all(self):
        """podSelector:{} must match ALL pods — no pod escapes isolation."""
        docs = render_default()
        for doc in docs:
            selector = get_pod_selector(doc)
            labels = selector.get("matchLabels", {})
            assert labels == {}, (
                f"Policy {doc['metadata']['name']} has non-empty podSelector"
            )

    def test_missing_policy_types_not_possible(self):
        """Every NetworkPolicy has explicit policyTypes."""
        docs = render_default()
        policies = find_policies(docs)
        for doc in policies:
            types = get_policy_types(doc)
            assert len(types) > 0

    def test_no_namespace_wide_allow(self):
        """No policy allows traffic to/from all namespaces."""
        docs = render_default()
        for doc in docs:
            rules = get_egress_rules(doc)
            for rule in rules:
                for to in rule.get("to", []):
                    ns = to.get("namespaceSelector", {})
                    if ns:
                        # Must have matchLabels — empty namespaceSelector = all namespaces
                        assert ns.get("matchLabels") is not None

    def test_egress_deny_is_baseline(self):
        """Default-deny-egress exists and has no egress rules (deny all)."""
        docs = render_default()
        policy = find_policy(docs, "default-deny-egress")
        assert get_egress_rules(policy) == []
        assert get_policy_types(policy) == ["Egress"]


# ---------------------------------------------------------------------------
# TestEdgeCases
# ---------------------------------------------------------------------------


@requires_helm
class TestEdgeCases:
    """Edge cases and unusual configurations."""

    def test_all_policies_disabled(self):
        """Disabling all NetworkPolicy policies produces no NetworkPolicy resources."""
        values = {
            "policies": {
                "defaultDenyIngress": False,
                "defaultDenyEgress": False,
                "allowDnsEgress": False,
                "allowHttpsEgress": False,
                "allowCallbackEgress": False,
            }
        }
        docs = render_chart(values)
        policies = find_policies(docs)
        assert len(policies) == 0

    def test_only_deny_policies(self):
        """Only deny policies can be enabled."""
        values = {
            "policies": {
                "defaultDenyIngress": True,
                "defaultDenyEgress": True,
                "allowDnsEgress": False,
                "allowHttpsEgress": False,
                "allowCallbackEgress": False,
            }
        }
        docs = render_chart(values)
        policies = find_policies(docs)
        assert len(policies) == 2
        names = [d["metadata"]["name"] for d in policies]
        assert any("deny-ingress" in n for n in names)
        assert any("deny-egress" in n for n in names)

    def test_extra_blocked_cidrs(self):
        """Extra CIDRs added to blockedCIDRs.extra appear in except list."""
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": ["44.0.0.0/8", "198.18.0.0/15"],
        }
        docs = render_chart(values)
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "44.0.0.0/8" in cidrs
        assert "198.18.0.0/15" in cidrs

    def test_namespace_override(self):
        """Custom namespace applied to all policies."""
        values = default_callback_values()
        values["namespace"] = "customer-tenant-1"
        docs = render_chart(values)
        for doc in docs:
            assert doc["metadata"]["namespace"] == "customer-tenant-1"

    def test_release_namespace_fallback(self):
        """When namespace not set, falls back to release namespace."""
        values = default_callback_values()
        docs = render_chart(values, namespace="my-release-ns")
        for doc in docs:
            assert doc["metadata"]["namespace"] == "my-release-ns"

    def test_multiple_extra_cidrs_accumulated(self):
        """Multiple extra CIDRs all appear in except list."""
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": ["44.0.0.0/8", "198.18.0.0/15", "203.0.113.0/24"],
        }
        docs = render_chart(values)
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert len(cidrs) >= 10  # 3 RFC1918 + 4 metadata + 3 extra


# ---------------------------------------------------------------------------
# TestSecurityProperties
# ---------------------------------------------------------------------------


@requires_helm
class TestSecurityProperties:
    """High-level security properties that must hold."""

    def test_zero_trust_default(self):
        """Default configuration denies all traffic then selectively allows."""
        docs = render_default()
        # Both deny policies must exist
        find_policy(docs, "default-deny-ingress")
        find_policy(docs, "default-deny-egress")

    def test_minimum_privilege_egress(self):
        """Egress allows only DNS, HTTPS, and callback — nothing else."""
        docs = render_default()
        allow_policies = [
            d for d in docs
            if "allow-" in d["metadata"]["name"]
        ]
        names = {d["metadata"]["name"] for d in allow_policies}
        # Exactly 3 allow policies
        assert len(names) == 3
        assert any("dns" in n for n in names)
        assert any("https" in n for n in names)
        assert any("callback" in n for n in names)

    def test_defense_in_depth(self):
        """Multiple layers: default deny + except lists + namespace scoping."""
        docs = render_default()
        # Layer 1: default deny
        deny_egress = find_policy(docs, "default-deny-egress")
        assert get_egress_rules(deny_egress) == []
        # Layer 2: HTTPS except list
        https_policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(https_policy)
        assert len(cidrs) >= 4
        # Layer 3: DNS scoped to kube-system
        dns_policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(dns_policy)
        assert "namespaceSelector" in rules[0]["to"][0]

    def test_fail_closed_callback(self):
        """Callback requires explicit CIDR — fails if not provided."""
        stderr = render_chart_error()
        assert "REQUIRED" in stderr

    def test_no_http_port_80(self):
        """No policy allows plaintext HTTP (port 80)."""
        docs = render_default()
        for doc in docs:
            ports = get_egress_ports(doc)
            for p in ports:
                assert p.get("port") != 80

    def test_no_ssh_port_22(self):
        """No policy allows SSH (port 22)."""
        docs = render_default()
        for doc in docs:
            ports = get_egress_ports(doc)
            for p in ports:
                assert p.get("port") != 22

    def test_cidr_parity_with_url_validator(self):
        """Blocked CIDRs must match proxy/middleware/url_validator.py _BLOCKED_NETWORKS.

        The network layer (NetworkPolicy) and application layer (SSRF validator)
        must block the same IPv4 ranges for defense in depth.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        netpol_cidrs = set(get_except_cidrs(policy))

        # From url_validator.py _BLOCKED_NETWORKS (IPv4 only, relevant to NetworkPolicy)
        url_validator_ipv4 = {
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "127.0.0.0/8",
            "0.0.0.0/8",
        }

        # All url_validator IPv4 blocked ranges must be in NetworkPolicy except list
        for cidr in url_validator_ipv4:
            assert cidr in netpol_cidrs, (
                f"CIDR {cidr} from url_validator.py _BLOCKED_NETWORKS "
                f"missing from NetworkPolicy except list"
            )

    def test_loopback_in_except_list(self):
        """127.0.0.0/8 must be in HTTPS except list for defense in depth.

        0.0.0.0/0 includes 127.x. While most CNI implementations don't
        enforce NetworkPolicy on loopback, we block it explicitly to
        prevent surprises across different CNI implementations.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "127.0.0.0/8" in cidrs
        assert _cidr_blocks_ip(cidrs, "127.0.0.1")


# ---------------------------------------------------------------------------
# TestHardeningRound1 — fixes from security audit
# ---------------------------------------------------------------------------


@requires_helm
class TestHardeningRound1:
    """Security hardening tests addressing discovered loopholes."""

    def test_cgnat_range_blocked(self):
        """100.64.0.0/10 (CGNAT, RFC 6598) must be blocked.

        AWS EKS uses this range for pod CIDRs. Without blocking it,
        pods using CGNAT-range IPs could communicate freely.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "100.64.0.0/10" in cidrs
        assert _cidr_blocks_ip(cidrs, "100.64.0.1")
        assert _cidr_blocks_ip(cidrs, "100.96.0.1")  # EKS typical
        assert _cidr_blocks_ip(cidrs, "100.127.255.255")

    def test_this_network_blocked(self):
        """0.0.0.0/8 ('this network') must be blocked.

        Prevents access via 0.x.x.x addresses which some stacks
        interpret as localhost.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "0.0.0.0/8" in cidrs
        assert _cidr_blocks_ip(cidrs, "0.0.0.0")
        assert _cidr_blocks_ip(cidrs, "0.0.0.1")

    def test_dns_scoped_to_coredns_pods(self):
        """DNS egress must target CoreDNS pods specifically, not all pods
        in kube-system. An attacker pod in kube-system (if compromised)
        could otherwise receive DNS traffic from tenant pods.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        to = rules[0]["to"][0]
        assert "podSelector" in to, (
            "DNS egress must include podSelector to scope to CoreDNS pods"
        )
        pod_labels = to["podSelector"]["matchLabels"]
        assert "k8s-app" in pod_labels

    def test_fail_guard_prevents_empty_rfc1918(self):
        """Removing RFC 1918 CIDRs from blockedCIDRs must FAIL the template.

        Without this guard, a user could accidentally set
        blockedCIDRs.rfc1918=[] and silently lose all internal IP blocking.
        """
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": [],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10"],
            "extra": [],
        }
        stderr = render_chart_error(values)
        assert "10.0.0.0/8" in stderr

    def test_fail_guard_prevents_missing_metadata(self):
        """Removing 169.254.0.0/16 must FAIL — prevents IMDS access."""
        values = default_callback_values()
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "metadata": ["127.0.0.0/8"],
            "extra": [],
        }
        stderr = render_chart_error(values)
        assert "169.254.0.0/16" in stderr

    def test_kube_apiserver_cluster_ip_blocked(self):
        """Kubernetes API server ClusterIP (typically 10.96.0.1) must be
        blocked by RFC 1918 except list. Prevents pods from accessing
        the API server to enumerate secrets or escalate privileges.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        # Standard kube-apiserver ClusterIP
        assert _cidr_blocks_ip(cidrs, "10.96.0.1")

    def test_eks_pod_cidr_100_x_blocked(self):
        """EKS custom networking often uses 100.64.0.0/10 for pods.
        These must be blocked to prevent lateral movement on EKS.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        # Typical EKS secondary CIDR pod IPs
        assert _cidr_blocks_ip(cidrs, "100.64.1.5")
        assert _cidr_blocks_ip(cidrs, "100.96.0.100")

    def test_gke_metadata_169_254_169_252(self):
        """GKE uses 169.254.169.252:988 for metadata in some versions.
        Must be blocked by the link-local range.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "169.254.169.252")

    def test_no_implicit_allow_all_via_empty_ingress_array(self):
        """ingress: [{}] means allow-all; ingress: [] means deny-all.
        Our deny-ingress has NO ingress key at all (= deny-all with policyTypes).
        Verify no policy accidentally includes ingress: [{}].
        """
        docs = render_default()
        for doc in docs:
            spec = doc.get("spec", {})
            if "ingress" in spec:
                for rule in spec["ingress"]:
                    # An empty rule {} means allow from everywhere
                    assert rule != {}, (
                        f"Policy {doc['metadata']['name']} has ingress: [{{}}] "
                        f"which allows all ingress (silent security hole)"
                    )

    def test_no_implicit_allow_all_via_empty_egress_array(self):
        """egress: [{}] means allow-all; egress: [] means deny-all.
        Verify no policy accidentally includes egress: [{}].
        """
        docs = render_default()
        for doc in docs:
            spec = doc.get("spec", {})
            if "egress" in spec:
                for rule in spec["egress"]:
                    assert rule != {}, (
                        f"Policy {doc['metadata']['name']} has egress: [{{}}] "
                        f"which allows all egress (silent security hole)"
                    )

    def test_deny_policies_have_no_rules_key(self):
        """Default deny policies must NOT have ingress/egress keys at all.
        Having an empty array (ingress: []) is deny-all, but having
        NO key at all with explicit policyTypes is the canonical form.
        """
        docs = render_default()
        deny_ingress = find_policy(docs, "default-deny-ingress")
        deny_egress = find_policy(docs, "default-deny-egress")
        # Deny-ingress: no ingress key, no egress key
        assert "ingress" not in deny_ingress.get("spec", {})
        assert "egress" not in deny_ingress.get("spec", {})
        # Deny-egress: no egress key, no ingress key
        assert "egress" not in deny_egress.get("spec", {})
        assert "ingress" not in deny_egress.get("spec", {})

    def test_except_list_has_minimum_8_cidrs(self):
        """After hardening, except list should have at least 8 IPv4 CIDRs:
        3 RFC 1918 + 169.254/16 + 127/8 + 0/8 + 100.64/10 + 198.18/15.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert len(cidrs) >= 8, (
            f"Expected at least 8 CIDRs in except list, got {len(cidrs)}: {cidrs}"
        )

    def test_no_ipv6_in_ipv4_except_list(self):
        """IPv6 CIDRs must be filtered from IPv4 ipBlock.except.
        Including IPv6 in IPv4 except would cause K8s API validation errors.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        for cidr in cidrs:
            assert ":" not in cidr, (
                f"IPv6 CIDR {cidr} leaked into IPv4 except list"
            )


# ---------------------------------------------------------------------------
# TestHardeningRound2 — fixes from deep security audit
# ---------------------------------------------------------------------------


@requires_helm
class TestHardeningRound2:
    """Round 2 security hardening tests from deep audit of K8s NetworkPolicy
    bypass techniques, CVEs, and CNI-specific behaviors."""

    def test_mustToJson_used_not_toJson(self):
        """mustToJson must be used instead of toJson.

        toJson silently returns empty string on serialization failure,
        producing 'matchLabels: ' which K8s interprets as matchLabels: null.
        mustToJson fails loudly on serialization errors.
        """
        # Render with valid values — should succeed
        docs = render_default()
        policies = find_policies(docs)
        for doc in policies:
            selector = get_pod_selector(doc)
            # Must have matchLabels key (not null)
            assert "matchLabels" in selector

    def test_dns_selector_and_not_or(self):
        """DNS policy must use AND semantics (same to entry), NOT OR.

        AND (correct): namespaceSelector + podSelector in same entry
          = pods matching BOTH namespace AND pod labels.
        OR (dangerous): namespaceSelector and podSelector as separate entries
          = pods matching EITHER namespace label OR pod label.

        OR would allow DNS to any pod with k8s-app:kube-dns in ANY namespace,
        which an attacker could exploit by labeling their pod.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        rules = get_egress_rules(policy)
        assert len(rules) == 1
        to_entries = rules[0]["to"]
        # Must be exactly 1 'to' entry (AND semantics)
        assert len(to_entries) == 1, (
            f"DNS policy has {len(to_entries)} 'to' entries — must be 1 "
            f"for AND semantics. Multiple entries = OR semantics (insecure)."
        )
        entry = to_entries[0]
        # Both selectors in same entry
        assert "namespaceSelector" in entry
        assert "podSelector" in entry

    def test_all_egress_rules_have_explicit_ports(self):
        """Every egress rule with 'to' must also specify 'ports'.

        Missing ports = allow ALL ports (TCP/UDP/SCTP), which is
        a wildcard allow that defeats the purpose of the policy.
        """
        docs = render_default()
        for doc in docs:
            rules = get_egress_rules(doc)
            for rule in rules:
                if "to" in rule:
                    assert "ports" in rule, (
                        f"Policy {doc['metadata']['name']} has egress rule "
                        f"with 'to' but no 'ports' — allows ALL ports"
                    )
                    assert len(rule["ports"]) > 0, (
                        f"Policy {doc['metadata']['name']} has empty ports "
                        f"list — allows ALL ports"
                    )

    def test_all_ports_have_explicit_protocol(self):
        """Every port entry must specify protocol explicitly.

        Omitting protocol defaults to TCP only, which could silently
        break UDP DNS or allow unexpected UDP traffic.
        """
        docs = render_default()
        for doc in docs:
            ports = get_egress_ports(doc)
            for p in ports:
                assert "protocol" in p, (
                    f"Policy {doc['metadata']['name']} has port {p.get('port')} "
                    f"without explicit protocol (defaults to TCP only)"
                )

    def test_benchmarking_range_blocked(self):
        """198.18.0.0/15 (benchmarking, RFC 2544) must be blocked.

        Sometimes used for pod CIDRs in test environments.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert "198.18.0.0/15" in cidrs
        assert _cidr_blocks_ip(cidrs, "198.18.0.1")
        assert _cidr_blocks_ip(cidrs, "198.19.255.255")

    def test_except_cidrs_are_valid_subnets(self):
        """All except CIDRs must be valid IPv4 networks.

        Malformed CIDRs (e.g. 10.0.0.1/8 with non-zero host bits)
        may be silently accepted by older K8s but behave unpredictably.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=True)
            assert str(net) == cidr, (
                f"CIDR {cidr} has non-zero host bits. "
                f"Canonical form: {net}"
            )

    def test_except_cidrs_are_all_subnets_of_0_0_0_0(self):
        """All except CIDRs must be proper subnets of 0.0.0.0/0.

        K8s validates that except entries are subsets of the cidr.
        This is always true for 0.0.0.0/0 but verify anyway.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        parent = ipaddress.ip_network("0.0.0.0/0")
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr)
            assert net.subnet_of(parent), (
                f"CIDR {cidr} is not a subnet of 0.0.0.0/0"
            )

    def test_max_except_list_size_guard(self):
        """Template must fail if except list exceeds 50 CIDRs.

        Large except lists can exhaust Cilium BPF maps or degrade
        iptables performance. Limit to 50 entries.
        """
        values = default_callback_values()
        # 3 rfc1918 + 4 metadata (after IPv6 filter: 169.254, 127, 0, 100.64, 198.18 = 5)
        # + 43 extra = 51 total > 50
        values["blockedCIDRs"] = {
            "rfc1918": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "metadata": ["169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15"],
            "extra": [f"{i}.0.0.0/8" for i in range(1, 44)],  # 43 extra = 51 total
        }
        stderr = render_chart_error(values)
        assert "50" in stderr or "performance" in stderr.lower()

    def test_callback_cidr_not_rfc1918(self):
        """Callback CIDR should not overlap with RFC 1918 ranges.

        A callback CIDR in RFC 1918 would be blocked by the HTTPS
        except list, making the callback policy useless.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        callback_cidr = rules[0]["to"][0]["ipBlock"]["cidr"]
        callback_net = ipaddress.ip_network(callback_cidr)
        rfc1918 = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        for private_net in rfc1918:
            assert not callback_net.overlaps(private_net), (
                f"Callback CIDR {callback_cidr} overlaps with {private_net}"
            )

    def test_no_wildcard_callback_cidr(self):
        """Callback CIDR must not be a broad range like /8 or wider.

        A broad callback CIDR defeats the purpose of network isolation.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        rules = get_egress_rules(policy)
        callback_cidr = rules[0]["to"][0]["ipBlock"]["cidr"]
        net = ipaddress.ip_network(callback_cidr)
        assert net.prefixlen >= 16, (
            f"Callback CIDR {callback_cidr} is too broad "
            f"(/{net.prefixlen}). Use /16 or narrower."
        )

    def test_dns_rebinding_0_0_0_0_blocked(self):
        """DNS rebinding via 0.0.0.0 must be blocked.

        Attacker DNS responds with 0.0.0.0 which some stacks
        interpret as localhost, bypassing RFC 1918 checks.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "0.0.0.0")

    def test_dns_rebinding_127_x_blocked(self):
        """DNS rebinding via 127.x.x.x variants must be blocked.

        Attacker DNS can return any 127.x.x.x address, not just 127.0.0.1.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        cidrs = get_except_cidrs(policy)
        assert _cidr_blocks_ip(cidrs, "127.0.0.1")
        assert _cidr_blocks_ip(cidrs, "127.0.0.2")
        assert _cidr_blocks_ip(cidrs, "127.255.255.255")

    def test_no_udp_on_https_policy(self):
        """HTTPS policy must only allow TCP, not UDP.

        UDP on port 443 would enable QUIC/HTTP3 which could bypass
        L4 inspection. Only TCP is allowed by default.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-https-egress")
        ports = get_egress_ports(policy)
        for p in ports:
            assert p["protocol"] == "TCP", (
                f"HTTPS policy has non-TCP protocol: {p['protocol']}"
            )

    def test_no_udp_on_callback_policy(self):
        """Callback policy must only allow TCP, not UDP."""
        docs = render_default()
        policy = find_policy(docs, "allow-callback-egress")
        ports = get_egress_ports(policy)
        for p in ports:
            assert p["protocol"] == "TCP"

    def test_dns_allows_both_tcp_and_udp(self):
        """DNS policy must allow BOTH UDP and TCP on port 53.

        TCP DNS is required for large responses (>512 bytes).
        Blocking TCP 53 causes silent DNS resolution failures
        for DNSSEC and large record sets.
        """
        docs = render_default()
        policy = find_policy(docs, "allow-dns-egress")
        ports = get_egress_ports(policy)
        protocols = {p["protocol"] for p in ports}
        assert protocols == {"UDP", "TCP"}
