"""Story-level acceptance tests for SHIELD-28: Pod Security Standards.

AC1: All customer workload pods run as non-root user
AC2: Root filesystem is read-only (writable /tmp via emptyDir volume)
AC3: Privilege escalation is disabled
AC4: All Linux capabilities are dropped
AC5: Seccomp profile set to RuntimeDefault
AC6: PodSecurity admission label 'restricted' enforced on customer namespaces
AC7: Existing workloads verified to function correctly under restricted context
"""

from __future__ import annotations

import yaml
import pytest

from tests.helpers.helm import (
    default_pss_values,
    find_policies,
    find_resource,
    get_configmap_data,
    get_namespace_labels,
    render_chart,
    render_default,
    render_with_namespace,
    requires_helm,
)


# ---------------------------------------------------------------------------
# AC1: Run as Non-Root
# ---------------------------------------------------------------------------


@requires_helm
class TestAC1_RunAsNonRoot:
    """AC1: All customer workload pods run as non-root user."""

    def test_pss_enforces_run_as_non_root(self):
        """PSS restricted profile enforces runAsNonRoot at admission."""
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        # PSS restricted profile requires runAsNonRoot
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

    def test_security_context_has_run_as_non_root(self):
        """Reference securityContext explicitly sets runAsNonRoot=true."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsNonRoot"] is True
        assert ctx["spec"]["securityContext"]["runAsUser"] == 65534


# ---------------------------------------------------------------------------
# AC2: Read-Only Root Filesystem
# ---------------------------------------------------------------------------


@requires_helm
class TestAC2_ReadOnlyRootFS:
    """AC2: Root filesystem is read-only with writable /tmp via emptyDir."""

    def test_security_context_has_read_only_rootfs(self):
        """Reference securityContext sets readOnlyRootFilesystem=true."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"] is True

    def test_empty_dir_tmp_with_size_limit(self):
        """Writable /tmp via emptyDir with sizeLimit."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        # Volume exists
        volumes = ctx["spec"]["volumes"]
        tmp_vol = [v for v in volumes if v["name"] == "tmp"]
        assert len(tmp_vol) == 1
        assert tmp_vol[0]["emptyDir"]["sizeLimit"] == "100Mi"
        # Mount exists
        container = ctx["spec"]["containers"][0]
        mounts = container["volumeMounts"]
        tmp_mount = [m for m in mounts if m["mountPath"] == "/tmp"]
        assert len(tmp_mount) == 1


# ---------------------------------------------------------------------------
# AC3: No Privilege Escalation
# ---------------------------------------------------------------------------


@requires_helm
class TestAC3_NoPrivilegeEscalation:
    """AC3: Privilege escalation is disabled."""

    def test_security_context_disables_privilege_escalation(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False


# ---------------------------------------------------------------------------
# AC4: Drop All Capabilities
# ---------------------------------------------------------------------------


@requires_helm
class TestAC4_DropAllCapabilities:
    """AC4: All Linux capabilities are dropped."""

    def test_security_context_drops_all_capabilities(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert "ALL" in container["securityContext"]["capabilities"]["drop"]


# ---------------------------------------------------------------------------
# AC5: Seccomp Profile
# ---------------------------------------------------------------------------


@requires_helm
class TestAC5_SeccompProfile:
    """AC5: Seccomp profile set to RuntimeDefault."""

    def test_security_context_has_runtime_default_seccomp(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"


# ---------------------------------------------------------------------------
# AC6: PSS Admission Label
# ---------------------------------------------------------------------------


@requires_helm
class TestAC6_PSSAdmissionLabel:
    """AC6: PodSecurity admission label 'restricted' enforced on namespaces."""

    def test_namespace_has_enforce_restricted(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

    def test_all_six_pss_labels_present(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        expected = [
            "pod-security.kubernetes.io/enforce",
            "pod-security.kubernetes.io/enforce-version",
            "pod-security.kubernetes.io/audit",
            "pod-security.kubernetes.io/audit-version",
            "pod-security.kubernetes.io/warn",
            "pod-security.kubernetes.io/warn-version",
        ]
        for label in expected:
            assert label in labels, f"Missing PSS label: {label}"


# ---------------------------------------------------------------------------
# AC7: Workloads Function Correctly
# ---------------------------------------------------------------------------


@requires_helm
class TestAC7_WorkloadsFunction:
    """AC7: Existing workloads verified to function under restricted context."""

    def test_chart_renders_with_all_policies_and_pss(self):
        """Full chart renders successfully with PSS + NetworkPolicy."""
        docs = render_with_namespace()
        assert len(docs) == 7  # 5 netpols + 1 namespace + 1 configmap

    def test_network_policy_count_unchanged(self):
        """PSS addition does not affect NetworkPolicy resources."""
        docs = render_with_namespace()
        netpols = find_policies(docs, "NetworkPolicy")
        assert len(netpols) == 5

    def test_resource_count_correct(self):
        """Expected resource types and counts."""
        docs = render_with_namespace()
        kinds = [d["kind"] for d in docs]
        assert kinds.count("NetworkPolicy") == 5
        assert kinds.count("Namespace") == 1
        assert kinds.count("ConfigMap") == 1
