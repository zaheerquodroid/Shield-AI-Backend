"""Attack simulation tests for ShieldAI Pod Security Standards.

These tests verify that the Helm chart's PSS configuration prevents
common container escape, privilege escalation, and PSS downgrade attacks.
"""

from __future__ import annotations

import yaml
import pytest

from tests.helpers.helm import (
    default_callback_values,
    default_pss_values,
    find_policies,
    find_resource,
    get_configmap_data,
    get_namespace_labels,
    render_chart,
    render_chart_error,
    render_default,
    render_with_namespace,
    requires_helm,
)


# ---------------------------------------------------------------------------
# TestPrivilegeEscalationPrevention
# ---------------------------------------------------------------------------


@requires_helm
class TestPrivilegeEscalationPrevention:
    """Verify PSS prevents privilege escalation vectors."""

    def test_pss_enforces_restricted_rejects_privileged_pods(self):
        """PSS restricted profile rejects pods with privileged: true."""
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

    def test_pss_restricted_blocks_host_pid(self):
        """PSS restricted profile blocks hostPID: true at admission."""
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        # restricted profile blocks hostPID
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

    def test_pss_restricted_blocks_host_network(self):
        """PSS restricted profile blocks hostNetwork: true at admission."""
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

    def test_pss_restricted_blocks_host_ipc(self):
        """PSS restricted profile blocks hostIPC: true at admission."""
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

    def test_configmap_prevents_root_uid(self):
        """Reference securityContext sets runAsUser to non-root (65534)."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsUser"] == 65534
        assert ctx["spec"]["securityContext"]["runAsNonRoot"] is True

    def test_configmap_prevents_privilege_escalation(self):
        """Reference securityContext disables allowPrivilegeEscalation."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False


# ---------------------------------------------------------------------------
# TestContainerEscapeMitigation
# ---------------------------------------------------------------------------


@requires_helm
class TestContainerEscapeMitigation:
    """Verify security context mitigates container escape techniques."""

    def test_read_only_root_filesystem(self):
        """Read-only rootfs prevents writing malicious binaries."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"] is True

    def test_no_capabilities(self):
        """All capabilities dropped prevents capability-based escapes."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert "ALL" in container["securityContext"]["capabilities"]["drop"]

    def test_seccomp_enforced(self):
        """Seccomp RuntimeDefault blocks dangerous syscalls."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        profile_type = ctx["spec"]["securityContext"]["seccompProfile"]["type"]
        assert profile_type in ("RuntimeDefault", "Localhost")

    def test_no_new_privileges(self):
        """allowPrivilegeEscalation=false sets no_new_privs flag."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False

    def test_tmpfs_limited(self):
        """emptyDir /tmp has sizeLimit preventing disk-filling attacks."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        volumes = ctx["spec"]["volumes"]
        tmp_vol = [v for v in volumes if v["name"] == "tmp"][0]
        size_limit = tmp_vol["emptyDir"]["sizeLimit"]
        assert size_limit is not None
        assert size_limit != ""


# ---------------------------------------------------------------------------
# TestPSSDowngradeAttacks
# ---------------------------------------------------------------------------


@requires_helm
class TestPSSDowngradeAttacks:
    """Verify fail guards prevent PSS downgrade attacks."""

    def test_downgrade_enforce_to_privileged_blocked(self):
        """Attacker cannot downgrade enforce to privileged."""
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "privileged",
            "audit": "restricted",
            "warn": "restricted",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "privileged" in stderr

    def test_downgrade_enforce_to_baseline_allowed(self):
        """Baseline is weaker but allowed (with matching audit/warn)."""
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "baseline",
            "audit": "baseline",
            "warn": "baseline",
            "version": "latest",
        }
        docs = render_chart(values)
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce"] == "baseline"

    def test_weaker_audit_than_enforce_blocked(self):
        """audit=privileged when enforce=restricted is blocked."""
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "restricted",
            "audit": "privileged",
            "warn": "restricted",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "weaker" in stderr or "audit" in stderr

    def test_weaker_warn_than_enforce_blocked(self):
        """warn=privileged when enforce=restricted is blocked."""
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "restricted",
            "audit": "restricted",
            "warn": "privileged",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "weaker" in stderr or "warn" in stderr

    def test_invalid_enforce_level_blocked(self):
        """Typo in enforce level is rejected."""
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "restrcited",
            "audit": "restricted",
            "warn": "restricted",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "Invalid" in stderr or "restrcited" in stderr

    def test_empty_enforce_level_blocked(self):
        """Empty enforce level is rejected."""
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "",
            "audit": "restricted",
            "warn": "restricted",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "Invalid" in stderr

    def test_audit_baseline_with_enforce_restricted_blocked(self):
        """audit=baseline when enforce=restricted hides violations."""
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "restricted",
            "audit": "baseline",
            "warn": "restricted",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "weaker" in stderr or "audit" in stderr

    def test_warn_baseline_with_enforce_restricted_blocked(self):
        """warn=baseline when enforce=restricted hides violations."""
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "restricted",
            "audit": "restricted",
            "warn": "baseline",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "weaker" in stderr or "warn" in stderr


# ---------------------------------------------------------------------------
# TestPSSBypassWithoutNamespace — guards fire even without namespace creation
# ---------------------------------------------------------------------------


@requires_helm
class TestPSSBypassWithoutNamespace:
    """Verify PSS validation fires when namespaceManagement.create=false.

    Without this hardening, an attacker could set enforce=privileged and
    the NOTES.txt would instruct the user to manually apply that label,
    effectively guiding them to disable all pod security.
    """

    def test_enforce_privileged_blocked_without_namespace(self):
        """enforce=privileged must fail even with namespaceManagement.create=false."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "namespaceManagement": {"create": False},
            "podSecurity": {
                "enabled": True,
                "enforce": "privileged",
                "audit": "restricted",
                "warn": "restricted",
                "version": "latest",
            },
        }
        stderr = render_chart_error(values)
        assert "privileged" in stderr

    def test_invalid_level_blocked_without_namespace(self):
        """Typo in enforce level must fail without namespace creation."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "namespaceManagement": {"create": False},
            "podSecurity": {
                "enabled": True,
                "enforce": "resctricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "latest",
            },
        }
        stderr = render_chart_error(values)
        assert "Invalid" in stderr or "resctricted" in stderr

    def test_audit_downgrade_blocked_without_namespace(self):
        """audit=privileged must fail without namespace creation."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "namespaceManagement": {"create": False},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "privileged",
                "warn": "restricted",
                "version": "latest",
            },
        }
        stderr = render_chart_error(values)
        assert "weaker" in stderr or "audit" in stderr

    def test_root_uid_blocked_without_namespace(self):
        """runAsUser=0 must fail without namespace creation."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "namespaceManagement": {"create": False},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "latest",
            },
            "securityContext": {
                "pod": {
                    "runAsNonRoot": True,
                    "runAsUser": 0,
                    "runAsGroup": 65534,
                    "fsGroup": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "container": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "tmpVolume": {"enabled": True, "sizeLimit": "100Mi"},
            },
        }
        stderr = render_chart_error(values)
        assert "runAsUser" in stderr

    def test_seccomp_unconfined_blocked_without_namespace(self):
        """Unconfined seccomp must fail without namespace creation."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "namespaceManagement": {"create": False},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "latest",
            },
            "securityContext": {
                "pod": {
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "runAsGroup": 65534,
                    "fsGroup": 65534,
                    "seccompProfile": {"type": "Unconfined"},
                },
                "container": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "tmpVolume": {"enabled": True, "sizeLimit": "100Mi"},
            },
        }
        stderr = render_chart_error(values)
        assert "Unconfined" in stderr or "seccompProfile" in stderr


# ---------------------------------------------------------------------------
# TestSecurityContextBypass
# ---------------------------------------------------------------------------


@requires_helm
class TestSecurityContextBypass:
    """Verify fail guards prevent security context bypass."""

    def _base_values(self):
        return {
            "callback": {"cidr": "203.0.113.10/32"},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "latest",
            },
            "securityContext": {
                "pod": {
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "runAsGroup": 65534,
                    "fsGroup": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "container": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "tmpVolume": {"enabled": True, "sizeLimit": "100Mi"},
            },
        }

    def test_override_run_as_non_root_blocked(self):
        """Attacker cannot set runAsNonRoot=false."""
        values = self._base_values()
        values["securityContext"]["pod"]["runAsNonRoot"] = False
        stderr = render_chart_error(values)
        assert "runAsNonRoot" in stderr

    def test_add_capabilities_blocked(self):
        """Attacker cannot replace drop ALL with specific caps."""
        values = self._base_values()
        values["securityContext"]["container"]["capabilities"] = {
            "drop": ["NET_RAW"],
        }
        stderr = render_chart_error(values)
        assert "ALL" in stderr or "capabilities" in stderr

    def test_enable_privilege_escalation_blocked(self):
        """Attacker cannot set allowPrivilegeEscalation=true."""
        values = self._base_values()
        values["securityContext"]["container"]["allowPrivilegeEscalation"] = True
        stderr = render_chart_error(values)
        assert "allowPrivilegeEscalation" in stderr

    def test_writable_rootfs_allowed_in_configmap(self):
        """readOnlyRootFilesystem is not enforced by PSS — only in ConfigMap.

        Setting readOnlyRootFilesystem=false should NOT cause template failure
        because PSS restricted profile does not enforce it.
        """
        values = self._base_values()
        values["securityContext"]["container"]["readOnlyRootFilesystem"] = False
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"] is False

    def test_seccomp_unconfined_blocked(self):
        """Unconfined seccomp is rejected at template level — PSS restricted requires
        RuntimeDefault or Localhost. Catching this early prevents contradictory
        ConfigMap guidance that would be rejected at admission anyway.
        """
        values = self._base_values()
        values["securityContext"]["pod"]["seccompProfile"] = {"type": "Unconfined"}
        stderr = render_chart_error(values)
        assert "Unconfined" in stderr or "seccompProfile" in stderr

    def test_run_as_user_0_blocked(self):
        """Attacker cannot set runAsUser=0 (root UID) even with runAsNonRoot=true.

        runAsUser: 0 + runAsNonRoot: true is contradictory and K8s rejects it,
        but we catch it at template time to prevent misleading ConfigMap guidance.
        """
        values = self._base_values()
        values["securityContext"]["pod"]["runAsUser"] = 0
        stderr = render_chart_error(values)
        assert "runAsUser" in stderr and "0" in stderr

    def test_unlimited_tmp_possible_but_has_default(self):
        """tmp sizeLimit can be overridden but default is 100Mi."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        volumes = ctx["spec"]["volumes"]
        tmp_vol = [v for v in volumes if v["name"] == "tmp"][0]
        assert tmp_vol["emptyDir"]["sizeLimit"] == "100Mi"


# ---------------------------------------------------------------------------
# TestResourceExhaustionPrevention
# ---------------------------------------------------------------------------


@requires_helm
class TestResourceExhaustionPrevention:
    """Verify settings prevent resource exhaustion attacks."""

    def test_tmp_size_limit_present(self):
        """emptyDir has sizeLimit to prevent disk filling."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        volumes = ctx["spec"]["volumes"]
        tmp_vol = [v for v in volumes if v["name"] == "tmp"][0]
        assert "sizeLimit" in tmp_vol["emptyDir"]

    def test_no_unlimited_empty_dir(self):
        """Default emptyDir sizeLimit is not empty or zero."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        volumes = ctx["spec"]["volumes"]
        tmp_vol = [v for v in volumes if v["name"] == "tmp"][0]
        size_limit = tmp_vol["emptyDir"]["sizeLimit"]
        assert size_limit and size_limit != "0"

    def test_fs_group_set(self):
        """fsGroup is set to prevent file ownership issues."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["fsGroup"] == 65534

    def test_run_as_group_set(self):
        """runAsGroup is set to prevent GID 0 attacks."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsGroup"] == 65534


# ---------------------------------------------------------------------------
# TestDefenseInDepth
# ---------------------------------------------------------------------------


@requires_helm
class TestDefenseInDepth:
    """Verify PSS works alongside NetworkPolicy for defense in depth."""

    def test_pss_and_netpol_together(self):
        """Both PSS and NetworkPolicy render in the same chart."""
        docs = render_with_namespace()
        netpols = find_policies(docs, "NetworkPolicy")
        assert len(netpols) == 5
        ns = find_resource(docs, "Namespace")
        assert ns is not None
        cm = find_resource(docs, "ConfigMap", "security-context")
        assert cm is not None

    def test_pss_disabled_leaves_netpol(self):
        """Disabling PSS does not affect NetworkPolicy resources."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "podSecurity": {
                "enabled": False,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "latest",
            },
        }
        docs = render_chart(values)
        netpols = find_policies(docs, "NetworkPolicy")
        assert len(netpols) == 5
        cm_docs = [d for d in docs if d.get("kind") == "ConfigMap"]
        assert len(cm_docs) == 0

    def test_configmap_matches_pss_defaults(self):
        """ConfigMap security context is consistent with PSS restricted requirements."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        # PSS restricted requires all of these
        assert ctx["spec"]["securityContext"]["runAsNonRoot"] is True
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False
        assert "ALL" in container["securityContext"]["capabilities"]["drop"]

    def test_all_acceptance_criteria_covered(self):
        """Single render covers all 7 ACs simultaneously."""
        docs = render_with_namespace()

        # AC1: runAsNonRoot
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsNonRoot"] is True

        # AC2: readOnlyRootFilesystem + /tmp
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        volumes = ctx["spec"]["volumes"]
        assert any(v["name"] == "tmp" for v in volumes)

        # AC3: allowPrivilegeEscalation=false
        assert container["securityContext"]["allowPrivilegeEscalation"] is False

        # AC4: capabilities drop ALL
        assert "ALL" in container["securityContext"]["capabilities"]["drop"]

        # AC5: seccompProfile RuntimeDefault
        assert ctx["spec"]["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"

        # AC6: PSS labels
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

        # AC7: chart renders with all policies
        netpols = find_policies(docs, "NetworkPolicy")
        assert len(netpols) == 5

    def test_namespace_and_netpol_same_namespace(self):
        """Namespace resource and NetworkPolicies target the same namespace."""
        values = default_pss_values()
        values["namespace"] = "tenant-delta"
        docs = render_chart(values)
        ns = find_resource(docs, "Namespace")
        assert ns["metadata"]["name"] == "tenant-delta"
        netpols = find_policies(docs, "NetworkPolicy")
        for pol in netpols:
            assert pol["metadata"]["namespace"] == "tenant-delta"

    def test_total_resource_count_with_namespace(self):
        """With namespace enabled: 5 NetworkPolicies + 1 Namespace + 1 ConfigMap = 7."""
        docs = render_with_namespace()
        assert len(docs) == 7


# ---------------------------------------------------------------------------
# TestNegativeUIDGIDAttacks — Round 2 hardening
# ---------------------------------------------------------------------------


@requires_helm
class TestNegativeUIDGIDAttacks:
    """Verify negative UID/GID values are rejected.

    Linux maps negative UIDs/GIDs to large unsigned values (e.g. -1 → 4294967295).
    In some container runtimes, negative values can bypass root checks or map
    to UID 0. The fail guards must reject any value <= 0.
    """

    def _base_values(self):
        return {
            "callback": {"cidr": "203.0.113.10/32"},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "latest",
            },
            "securityContext": {
                "pod": {
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "runAsGroup": 65534,
                    "fsGroup": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "container": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "tmpVolume": {"enabled": True, "sizeLimit": "100Mi"},
            },
        }

    def test_negative_run_as_user_blocked(self):
        """runAsUser=-1 maps to UID 4294967295 on some runtimes — must be blocked."""
        values = self._base_values()
        values["securityContext"]["pod"]["runAsUser"] = -1
        stderr = render_chart_error(values)
        assert "runAsUser" in stderr
        assert "> 0" in stderr

    def test_negative_large_run_as_user_blocked(self):
        """runAsUser=-65534 must be blocked."""
        values = self._base_values()
        values["securityContext"]["pod"]["runAsUser"] = -65534
        stderr = render_chart_error(values)
        assert "runAsUser" in stderr

    def test_negative_run_as_group_blocked(self):
        """runAsGroup=-1 could map to root group — must be blocked."""
        values = self._base_values()
        values["securityContext"]["pod"]["runAsGroup"] = -1
        stderr = render_chart_error(values)
        assert "runAsGroup" in stderr
        assert "> 0" in stderr

    def test_run_as_group_zero_blocked(self):
        """runAsGroup=0 is the root group — must be blocked."""
        values = self._base_values()
        values["securityContext"]["pod"]["runAsGroup"] = 0
        stderr = render_chart_error(values)
        assert "runAsGroup" in stderr
        assert "root group" in stderr

    def test_negative_fs_group_blocked(self):
        """fsGroup=-1 could grant unexpected volume permissions — must be blocked."""
        values = self._base_values()
        values["securityContext"]["pod"]["fsGroup"] = -1
        stderr = render_chart_error(values)
        assert "fsGroup" in stderr
        assert "> 0" in stderr

    def test_fs_group_zero_blocked(self):
        """fsGroup=0 grants root group access to volumes — must be blocked."""
        values = self._base_values()
        values["securityContext"]["pod"]["fsGroup"] = 0
        stderr = render_chart_error(values)
        assert "fsGroup" in stderr
        assert "root group" in stderr


# ---------------------------------------------------------------------------
# TestVersionPinningAttacks — Round 2 hardening
# ---------------------------------------------------------------------------


@requires_helm
class TestVersionPinningAttacks:
    """Verify version field cannot be abused to disable PSS enforcement."""

    def test_empty_version_blocked(self):
        """Empty version disables PSS version pinning — must be blocked."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "",
            },
        }
        stderr = render_chart_error(values)
        assert "version" in stderr and "empty" in stderr.lower()

    def test_empty_version_blocked_with_namespace(self):
        """Empty version also blocked when creating namespace."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "namespaceManagement": {"create": True},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "",
            },
        }
        stderr = render_chart_error(values)
        assert "version" in stderr

    def test_valid_version_pinning_accepted(self):
        """Specific version like v1.28 is accepted."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "namespaceManagement": {"create": True},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "restricted",
                "version": "v1.28",
            },
        }
        docs = render_chart(values)
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce-version"] == "v1.28"


# ---------------------------------------------------------------------------
# TestServiceAccountTokenExposure — Round 2 hardening
# ---------------------------------------------------------------------------


@requires_helm
class TestServiceAccountTokenExposure:
    """Verify ConfigMap guidance includes automountServiceAccountToken: false.

    If a compromised container has access to the service account token,
    it can authenticate to the Kubernetes API and perform lateral movement.
    """

    def test_automount_disabled_in_configmap(self):
        """ConfigMap must include automountServiceAccountToken: false."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["automountServiceAccountToken"] is False

    def test_automount_disabled_with_namespace(self):
        """automountServiceAccountToken: false present with namespace enabled."""
        docs = render_with_namespace()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["automountServiceAccountToken"] is False


# ---------------------------------------------------------------------------
# TestYAMLInjectionPrevention — Round 2 hardening
# ---------------------------------------------------------------------------


@requires_helm
class TestYAMLInjectionPrevention:
    """Verify Helm values are properly quoted to prevent YAML type confusion.

    Unquoted values in Helm templates can cause YAML type coercion:
    - "true"/"false" → boolean
    - "123" → integer
    - "1.0" → float
    - "null" → None
    Quoting prevents these coercions from changing semantic meaning.
    """

    def test_capabilities_drop_all_is_quoted_string(self):
        """capabilities.drop ALL is rendered as quoted 'ALL' string."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        # The raw YAML should have "ALL" (quoted) not bare ALL
        assert '"ALL"' in data["security-context.yaml"]

    def test_size_limit_is_quoted_string(self):
        """sizeLimit is rendered as quoted string to prevent numeric coercion."""
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        assert '"100Mi"' in data["security-context.yaml"]

    def test_pss_labels_are_quoted(self):
        """All PSS label values are quoted to prevent YAML type confusion."""
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = ns["metadata"]["labels"]
        # After YAML parsing, values should be strings (not booleans etc.)
        pss_keys = [
            "pod-security.kubernetes.io/enforce",
            "pod-security.kubernetes.io/enforce-version",
            "pod-security.kubernetes.io/audit",
            "pod-security.kubernetes.io/audit-version",
            "pod-security.kubernetes.io/warn",
            "pod-security.kubernetes.io/warn-version",
        ]
        for key in pss_keys:
            assert isinstance(labels[key], str), f"Label {key} is not a string: {type(labels[key])}"

    def test_custom_size_limit_is_quoted(self):
        """Custom sizeLimit value is also quoted."""
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "securityContext": {
                "pod": {
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "runAsGroup": 65534,
                    "fsGroup": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "container": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "tmpVolume": {"enabled": True, "sizeLimit": "500Mi"},
            },
        }
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        assert '"500Mi"' in data["security-context.yaml"]
