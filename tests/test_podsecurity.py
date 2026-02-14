"""Unit tests for ShieldAI Pod Security Standards Helm chart resources.

Tests cover namespace rendering, PSS admission labels, fail guards,
security context ConfigMap, and tmp volume configuration.
"""

from __future__ import annotations

import yaml
import pytest

from tests.helpers.helm import (
    default_pss_values,
    find_resource,
    get_configmap_data,
    get_namespace_labels,
    render_chart,
    render_chart_error,
    render_with_namespace,
    render_default,
    find_policies,
    requires_helm,
)


# ---------------------------------------------------------------------------
# TestNamespaceRendering — namespace creation and structure
# ---------------------------------------------------------------------------


@requires_helm
class TestNamespaceRendering:
    """Verify namespace resource rendering."""

    def test_namespace_not_created_by_default(self):
        docs = render_default()
        ns_docs = [d for d in docs if d.get("kind") == "Namespace"]
        assert len(ns_docs) == 0

    def test_namespace_created_when_enabled(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        assert ns is not None

    def test_namespace_kind_and_api_version(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        assert ns["kind"] == "Namespace"
        assert ns["apiVersion"] == "v1"

    def test_namespace_name_matches_release(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        assert ns["metadata"]["name"] == "default"

    def test_namespace_custom_name(self):
        values = default_pss_values()
        values["namespace"] = "tenant-gamma"
        docs = render_chart(values)
        ns = find_resource(docs, "Namespace")
        assert ns["metadata"]["name"] == "tenant-gamma"

    def test_namespace_has_common_labels(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert "app.kubernetes.io/name" in labels
        assert "app.kubernetes.io/instance" in labels
        assert "helm.sh/chart" in labels

    def test_namespace_has_pss_labels(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert "pod-security.kubernetes.io/enforce" in labels

    def test_namespace_not_created_when_false(self):
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "namespaceManagement": {"create": False},
        }
        docs = render_chart(values)
        ns_docs = [d for d in docs if d.get("kind") == "Namespace"]
        assert len(ns_docs) == 0


# ---------------------------------------------------------------------------
# TestPSSLabels — Pod Security Standards admission labels
# ---------------------------------------------------------------------------


@requires_helm
class TestPSSLabels:
    """Verify PSS admission label values on namespace."""

    def test_enforce_restricted(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"

    def test_audit_restricted(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/audit"] == "restricted"

    def test_warn_restricted(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/warn"] == "restricted"

    def test_enforce_version_latest(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce-version"] == "latest"

    def test_audit_version_latest(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/audit-version"] == "latest"

    def test_warn_version_latest(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/warn-version"] == "latest"

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
            assert label in labels, f"Missing label: {label}"

    def test_custom_enforce_baseline(self):
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "baseline",
            "audit": "baseline",
            "warn": "baseline",
            "version": "v1.28",
        }
        docs = render_chart(values)
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert labels["pod-security.kubernetes.io/enforce"] == "baseline"
        assert labels["pod-security.kubernetes.io/enforce-version"] == "v1.28"

    def test_pss_labels_absent_when_disabled(self):
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": False,
            "enforce": "restricted",
            "audit": "restricted",
            "warn": "restricted",
            "version": "latest",
        }
        docs = render_chart(values)
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        assert "pod-security.kubernetes.io/enforce" not in labels

    def test_label_format_correct(self):
        docs = render_with_namespace()
        ns = find_resource(docs, "Namespace")
        labels = get_namespace_labels(ns)
        for key in labels:
            if key.startswith("pod-security.kubernetes.io/"):
                value = labels[key]
                assert isinstance(value, str)
                assert len(value) > 0


# ---------------------------------------------------------------------------
# TestPSSFailGuards — template fails on dangerous configurations
# ---------------------------------------------------------------------------


@requires_helm
class TestPSSFailGuards:
    """Verify template fails on dangerous PSS configurations."""

    def test_enforce_privileged_fails(self):
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

    def test_invalid_enforce_level_fails(self):
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "typo-level",
            "audit": "restricted",
            "warn": "restricted",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "Invalid" in stderr or "typo-level" in stderr

    def test_invalid_audit_level_fails(self):
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "restricted",
            "audit": "invalid-level",
            "warn": "restricted",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "Invalid" in stderr or "invalid-level" in stderr

    def test_invalid_warn_level_fails(self):
        values = default_pss_values()
        values["podSecurity"] = {
            "enabled": True,
            "enforce": "restricted",
            "audit": "restricted",
            "warn": "invalid-level",
            "version": "latest",
        }
        stderr = render_chart_error(values)
        assert "Invalid" in stderr or "invalid-level" in stderr

    def test_audit_weaker_than_enforce_fails(self):
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

    def test_warn_weaker_than_enforce_fails(self):
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

    def test_audit_privileged_with_enforce_restricted_fails(self):
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

    def test_baseline_enforce_with_matching_audit_warn_succeeds(self):
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


# ---------------------------------------------------------------------------
# TestSecurityContextConfigMap — reference security context
# ---------------------------------------------------------------------------


@requires_helm
class TestSecurityContextConfigMap:
    """Verify security context ConfigMap rendering."""

    def test_configmap_rendered(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        assert cm is not None

    def test_configmap_has_data(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        assert "security-context.yaml" in data

    def test_run_as_non_root(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsNonRoot"] is True

    def test_run_as_user_65534(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsUser"] == 65534

    def test_run_as_group_65534(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsGroup"] == 65534

    def test_allow_privilege_escalation_false(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["allowPrivilegeEscalation"] is False

    def test_read_only_root_filesystem(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"] is True

    def test_capabilities_drop_all(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        assert "ALL" in container["securityContext"]["capabilities"]["drop"]

    def test_seccomp_profile_runtime_default(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"

    def test_configmap_not_rendered_when_disabled(self):
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
        cm_docs = [d for d in docs if d.get("kind") == "ConfigMap"]
        assert len(cm_docs) == 0

    def test_configmap_has_policy_label(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        labels = cm["metadata"]["labels"]
        assert labels["shieldai.io/policy"] == "pod-security-context"

    def test_configmap_namespace(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        assert cm["metadata"]["namespace"] == "default"


# ---------------------------------------------------------------------------
# TestTmpVolume — emptyDir /tmp volume
# ---------------------------------------------------------------------------


@requires_helm
class TestTmpVolume:
    """Verify /tmp emptyDir volume in security context ConfigMap."""

    def test_empty_dir_present(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        volumes = ctx["spec"]["volumes"]
        tmp_vol = [v for v in volumes if v["name"] == "tmp"]
        assert len(tmp_vol) == 1
        assert "emptyDir" in tmp_vol[0]

    def test_size_limit_100mi(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        volumes = ctx["spec"]["volumes"]
        tmp_vol = [v for v in volumes if v["name"] == "tmp"][0]
        assert tmp_vol["emptyDir"]["sizeLimit"] == "100Mi"

    def test_mount_path_tmp(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        container = ctx["spec"]["containers"][0]
        mounts = container["volumeMounts"]
        tmp_mount = [m for m in mounts if m["name"] == "tmp"]
        assert len(tmp_mount) == 1
        assert tmp_mount[0]["mountPath"] == "/tmp"

    def test_can_disable_tmp_volume(self):
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
                "tmpVolume": {"enabled": False, "sizeLimit": "100Mi"},
            },
        }
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert "volumes" not in ctx["spec"]

    def test_custom_size_limit(self):
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
                "tmpVolume": {"enabled": True, "sizeLimit": "50Mi"},
            },
        }
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        volumes = ctx["spec"]["volumes"]
        tmp_vol = [v for v in volumes if v["name"] == "tmp"][0]
        assert tmp_vol["emptyDir"]["sizeLimit"] == "50Mi"


# ---------------------------------------------------------------------------
# TestSecurityContextFailGuards — template fails on insecure settings
# ---------------------------------------------------------------------------


@requires_helm
class TestSecurityContextFailGuards:
    """Verify template fails when security context violates PSS requirements."""

    def _insecure_values(self, **overrides):
        """Build values with one insecure override."""
        base = {
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
        # Apply overrides
        for key, value in overrides.items():
            parts = key.split(".")
            target = base
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
        return base

    def test_run_as_non_root_false_fails(self):
        values = self._insecure_values(**{"securityContext.pod.runAsNonRoot": False})
        stderr = render_chart_error(values)
        assert "runAsNonRoot" in stderr

    def test_allow_privilege_escalation_true_fails(self):
        values = self._insecure_values(
            **{"securityContext.container.allowPrivilegeEscalation": True}
        )
        stderr = render_chart_error(values)
        assert "allowPrivilegeEscalation" in stderr

    def test_missing_capabilities_drop_all_fails(self):
        values = self._insecure_values(
            **{"securityContext.container.capabilities": {"drop": ["NET_RAW"]}}
        )
        stderr = render_chart_error(values)
        assert "ALL" in stderr or "capabilities" in stderr

    def test_empty_capabilities_drop_fails(self):
        values = self._insecure_values(
            **{"securityContext.container.capabilities": {"drop": []}}
        )
        stderr = render_chart_error(values)
        assert "ALL" in stderr or "capabilities" in stderr

    def test_custom_run_as_user_succeeds(self):
        values = self._insecure_values(**{"securityContext.pod.runAsUser": 1000})
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsUser"] == 1000

    def test_seccomp_localhost_succeeds(self):
        values = self._insecure_values(
            **{"securityContext.pod.seccompProfile": {"type": "Localhost"}}
        )
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["seccompProfile"]["type"] == "Localhost"

    def test_run_as_user_0_fails(self):
        """UID 0 is root — must be rejected even if runAsNonRoot=true."""
        values = self._insecure_values(**{"securityContext.pod.runAsUser": 0})
        stderr = render_chart_error(values)
        assert "runAsUser" in stderr and "0" in stderr

    def test_seccomp_unconfined_fails(self):
        """Unconfined seccomp is rejected by PSS restricted — fail at template level."""
        values = self._insecure_values(
            **{"securityContext.pod.seccompProfile": {"type": "Unconfined"}}
        )
        stderr = render_chart_error(values)
        assert "Unconfined" in stderr or "seccompProfile" in stderr

    def test_seccomp_invalid_type_fails(self):
        """Invalid seccomp type must be rejected."""
        values = self._insecure_values(
            **{"securityContext.pod.seccompProfile": {"type": "Typo"}}
        )
        stderr = render_chart_error(values)
        assert "Typo" in stderr or "seccompProfile" in stderr


# ---------------------------------------------------------------------------
# TestPSSValidationWithoutNamespace — PSS guards fire even without namespace creation
# ---------------------------------------------------------------------------


@requires_helm
class TestPSSValidationWithoutNamespace:
    """Verify PSS level validation fires when podSecurity.enabled=true,
    even when namespaceManagement.create=false (the default)."""

    def test_enforce_privileged_fails_without_namespace(self):
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
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

    def test_invalid_enforce_fails_without_namespace(self):
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "podSecurity": {
                "enabled": True,
                "enforce": "bogus",
                "audit": "restricted",
                "warn": "restricted",
                "version": "latest",
            },
        }
        stderr = render_chart_error(values)
        assert "bogus" in stderr or "Invalid" in stderr

    def test_audit_weaker_than_enforce_fails_without_namespace(self):
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
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

    def test_warn_weaker_than_enforce_fails_without_namespace(self):
        values = {
            "callback": {"cidr": "203.0.113.10/32"},
            "podSecurity": {
                "enabled": True,
                "enforce": "restricted",
                "audit": "restricted",
                "warn": "baseline",
                "version": "latest",
            },
        }
        stderr = render_chart_error(values)
        assert "weaker" in stderr or "warn" in stderr

    def test_valid_config_succeeds_without_namespace(self):
        """Default config with podSecurity.enabled=true, create=false should work."""
        values = {"callback": {"cidr": "203.0.113.10/32"}}
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        assert cm is not None


# ---------------------------------------------------------------------------
# TestRound2FailGuards — negative UID/GID, empty version, automount
# ---------------------------------------------------------------------------


@requires_helm
class TestRound2FailGuards:
    """Verify round 2 hardening fail guards."""

    def _insecure_values(self, **overrides):
        base = {
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
        for key, value in overrides.items():
            parts = key.split(".")
            target = base
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
        return base

    def test_negative_run_as_user_fails(self):
        values = self._insecure_values(**{"securityContext.pod.runAsUser": -1})
        stderr = render_chart_error(values)
        assert "runAsUser" in stderr and "> 0" in stderr

    def test_negative_run_as_group_fails(self):
        values = self._insecure_values(**{"securityContext.pod.runAsGroup": -1})
        stderr = render_chart_error(values)
        assert "runAsGroup" in stderr and "> 0" in stderr

    def test_run_as_group_zero_fails(self):
        values = self._insecure_values(**{"securityContext.pod.runAsGroup": 0})
        stderr = render_chart_error(values)
        assert "runAsGroup" in stderr and "root group" in stderr

    def test_negative_fs_group_fails(self):
        values = self._insecure_values(**{"securityContext.pod.fsGroup": -1})
        stderr = render_chart_error(values)
        assert "fsGroup" in stderr and "> 0" in stderr

    def test_fs_group_zero_fails(self):
        values = self._insecure_values(**{"securityContext.pod.fsGroup": 0})
        stderr = render_chart_error(values)
        assert "fsGroup" in stderr and "root group" in stderr

    def test_empty_version_fails(self):
        values = self._insecure_values(**{"podSecurity.version": ""})
        stderr = render_chart_error(values)
        assert "version" in stderr

    def test_empty_version_fails_with_namespace(self):
        values = self._insecure_values(**{"podSecurity.version": ""})
        values["namespaceManagement"] = {"create": True}
        stderr = render_chart_error(values)
        assert "version" in stderr

    def test_automount_service_account_token_false(self):
        docs = render_default()
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["automountServiceAccountToken"] is False

    def test_valid_non_root_uid_succeeds(self):
        """UID 1000 is valid and should render."""
        values = self._insecure_values(**{"securityContext.pod.runAsUser": 1000})
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsUser"] == 1000

    def test_valid_non_root_gid_succeeds(self):
        """GID 1000 is valid and should render."""
        values = self._insecure_values(**{"securityContext.pod.runAsGroup": 1000})
        docs = render_chart(values)
        cm = find_resource(docs, "ConfigMap", "security-context")
        data = get_configmap_data(cm)
        ctx = yaml.safe_load(data["security-context.yaml"])
        assert ctx["spec"]["securityContext"]["runAsGroup"] == 1000
