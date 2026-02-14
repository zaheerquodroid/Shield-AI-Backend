"""Helm chart test helpers for rendering and inspecting Kubernetes resources."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

import pytest
import yaml

# Path to the helm chart
CHART_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "helm", "shieldai-security-policies"
)
CHART_DIR = os.path.normpath(CHART_DIR)

# Skip marker if helm is not installed
requires_helm = pytest.mark.skipif(
    shutil.which("helm") is None,
    reason="helm CLI not installed",
)


def render_chart(
    values_override: dict[str, Any] | None = None,
    *,
    release_name: str = "test",
    namespace: str = "default",
    set_flags: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Render the helm chart and return parsed YAML documents.

    Args:
        values_override: Dict merged over values.yaml (written as temp file).
        release_name: Helm release name.
        namespace: Helm release namespace.
        set_flags: Extra --set flags (e.g. ["callback.cidr=1.2.3.4/32"]).

    Returns:
        List of parsed Kubernetes resource dicts.

    Raises:
        subprocess.CalledProcessError: If helm template fails.
    """
    cmd = ["helm", "template", release_name, CHART_DIR, "--namespace", namespace]

    if set_flags:
        for flag in set_flags:
            cmd.extend(["--set", flag])

    tmp_file = None
    try:
        if values_override:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            )
            yaml.dump(values_override, tmp_file)
            tmp_file.close()
            cmd.extend(["-f", tmp_file.name])

        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=30
        )
        docs = []
        for doc in yaml.safe_load_all(result.stdout):
            if doc is not None:
                docs.append(doc)
        return docs
    finally:
        if tmp_file and os.path.exists(tmp_file.name):
            os.unlink(tmp_file.name)


def render_chart_error(
    values_override: dict[str, Any] | None = None,
    *,
    set_flags: list[str] | None = None,
) -> str:
    """Render the helm chart expecting failure, return stderr.

    Returns:
        The stderr output from the failed helm template command.

    Raises:
        AssertionError: If helm template succeeds unexpectedly.
    """
    cmd = ["helm", "template", "test", CHART_DIR, "--namespace", "default"]

    if set_flags:
        for flag in set_flags:
            cmd.extend(["--set", flag])

    tmp_file = None
    try:
        if values_override:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            )
            yaml.dump(values_override, tmp_file)
            tmp_file.close()
            cmd.extend(["-f", tmp_file.name])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        assert result.returncode != 0, (
            f"Expected helm template to fail but it succeeded.\n"
            f"stdout: {result.stdout[:500]}"
        )
        return result.stderr
    finally:
        if tmp_file and os.path.exists(tmp_file.name):
            os.unlink(tmp_file.name)


def find_policy(docs: list[dict[str, Any]], name_contains: str) -> dict[str, Any]:
    """Find a NetworkPolicy by name substring.

    Args:
        docs: List of parsed K8s resource dicts.
        name_contains: Substring to match in metadata.name.

    Returns:
        The matching resource dict.

    Raises:
        ValueError: If no matching policy is found.
    """
    for doc in docs:
        name = doc.get("metadata", {}).get("name", "")
        if name_contains in name:
            return doc
    available = [d.get("metadata", {}).get("name", "?") for d in docs]
    raise ValueError(
        f"No policy containing '{name_contains}' found. Available: {available}"
    )


def find_policies(docs: list[dict[str, Any]], kind: str = "NetworkPolicy") -> list[dict[str, Any]]:
    """Return all resources of a given kind."""
    return [d for d in docs if d.get("kind") == kind]


def get_egress_rules(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract egress rules from a NetworkPolicy spec."""
    return policy.get("spec", {}).get("egress", [])


def get_ingress_rules(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract ingress rules from a NetworkPolicy spec."""
    return policy.get("spec", {}).get("ingress", [])


def get_policy_types(policy: dict[str, Any]) -> list[str]:
    """Extract policyTypes from a NetworkPolicy spec."""
    return policy.get("spec", {}).get("policyTypes", [])


def get_except_cidrs(policy: dict[str, Any]) -> list[str]:
    """Extract all CIDRs from ipBlock.except lists across all egress rules."""
    cidrs = []
    for rule in get_egress_rules(policy):
        for to in rule.get("to", []):
            ip_block = to.get("ipBlock", {})
            cidrs.extend(ip_block.get("except", []))
    return cidrs


def get_pod_selector(policy: dict[str, Any]) -> dict[str, Any]:
    """Extract the podSelector from a NetworkPolicy spec."""
    return policy.get("spec", {}).get("podSelector", {})


def get_egress_ports(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract all port definitions from egress rules."""
    ports = []
    for rule in get_egress_rules(policy):
        ports.extend(rule.get("ports", []))
    return ports


def default_callback_values() -> dict[str, Any]:
    """Return minimal values override with callback.cidr set."""
    return {"callback": {"cidr": "203.0.113.10/32"}}


def render_default() -> list[dict[str, Any]]:
    """Render chart with default values + required callback CIDR."""
    return render_chart(default_callback_values())


def find_resource(
    docs: list[dict[str, Any]], kind: str, name_contains: str = ""
) -> dict[str, Any]:
    """Find a Kubernetes resource by kind and optional name substring.

    Args:
        docs: List of parsed K8s resource dicts.
        kind: Resource kind (e.g. "Namespace", "ConfigMap").
        name_contains: Optional substring to match in metadata.name.

    Returns:
        The matching resource dict.

    Raises:
        ValueError: If no matching resource is found.
    """
    for doc in docs:
        if doc.get("kind") != kind:
            continue
        if name_contains and name_contains not in doc.get("metadata", {}).get("name", ""):
            continue
        return doc
    available = [
        f"{d.get('kind')}:{d.get('metadata', {}).get('name', '?')}" for d in docs
    ]
    raise ValueError(
        f"No {kind} containing '{name_contains}' found. Available: {available}"
    )


def get_configmap_data(configmap: dict[str, Any]) -> dict[str, str]:
    """Extract .data from a ConfigMap resource."""
    return configmap.get("data", {})


def get_namespace_labels(namespace: dict[str, Any]) -> dict[str, str]:
    """Extract labels from a Namespace resource."""
    return namespace.get("metadata", {}).get("labels", {})


def default_pss_values() -> dict[str, Any]:
    """Return values with namespace creation + callback CIDR for PSS tests."""
    return {
        "callback": {"cidr": "203.0.113.10/32"},
        "namespaceManagement": {"create": True},
    }


def render_with_namespace(
    values_override: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Render chart with namespace creation enabled.

    Merges the given values_override on top of default_pss_values().
    """
    values = default_pss_values()
    if values_override:
        _deep_merge(values, values_override)
    return render_chart(values)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (mutates base)."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base
