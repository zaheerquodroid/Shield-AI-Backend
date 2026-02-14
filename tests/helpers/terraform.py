"""Terraform HCL test helpers for parsing and inspecting .tf files."""

from __future__ import annotations

import os
from typing import Any

import pytest

# Path constants
_TESTS_DIR = os.path.dirname(os.path.dirname(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
ROOT_DIR = os.path.join(_PROJECT_ROOT, "terraform")
MODULES_DIR = os.path.join(ROOT_DIR, "modules")


def _can_import_hcl2() -> bool:
    try:
        import hcl2  # noqa: F401
        return True
    except ImportError:
        return False


# Skip marker if hcl2 is not installed
requires_hcl2 = pytest.mark.skipif(
    not _can_import_hcl2(),
    reason="python-hcl2 not installed",
)


def _import_hcl2():
    """Lazy import to avoid top-level failure when hcl2 is missing."""
    import hcl2
    return hcl2


def parse_tf_file(file_path: str) -> dict[str, Any]:
    """Parse a single .tf file and return the HCL2 dict.

    Args:
        file_path: Absolute path to a .tf file.

    Returns:
        Parsed HCL2 dict.
    """
    hcl2 = _import_hcl2()
    with open(file_path) as f:
        return hcl2.load(f)


def parse_tf_dir(dir_path: str) -> dict[str, Any]:
    """Parse all .tf files in a directory and return a merged dict.

    HCL2 keys (resource, variable, output, data, locals, module) are lists;
    this merges them by extending lists across files.

    Args:
        dir_path: Absolute path to a directory containing .tf files.

    Returns:
        Merged HCL2 dict.
    """
    merged: dict[str, Any] = {}
    tf_files = sorted(f for f in os.listdir(dir_path) if f.endswith(".tf"))

    for filename in tf_files:
        parsed = parse_tf_file(os.path.join(dir_path, filename))
        for key, value in parsed.items():
            if key in merged:
                if isinstance(merged[key], list) and isinstance(value, list):
                    merged[key].extend(value)
                else:
                    merged[key] = value
            else:
                merged[key] = value

    return merged


def find_resources(parsed: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    """Extract all resources of a given type from parsed HCL.

    Args:
        parsed: Result of parse_tf_dir or parse_tf_file.
        resource_type: Terraform resource type (e.g. "aws_cloudfront_distribution").

    Returns:
        List of resource body dicts (each is {name: {attrs}}).
    """
    results = []
    for resource_block in parsed.get("resource", []):
        if resource_type in resource_block:
            results.append(resource_block[resource_type])
    return results


def find_resource(
    parsed: dict[str, Any], resource_type: str, name: str
) -> dict[str, Any]:
    """Extract a single named resource from parsed HCL.

    Args:
        parsed: Result of parse_tf_dir or parse_tf_file.
        resource_type: Terraform resource type.
        name: Terraform resource name.

    Returns:
        Resource attributes dict.

    Raises:
        ValueError: If the resource is not found.
    """
    for resource_block in parsed.get("resource", []):
        if resource_type in resource_block:
            type_block = resource_block[resource_type]
            if name in type_block:
                return type_block[name]
    raise ValueError(f"Resource {resource_type}.{name} not found")


def find_variables(parsed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract all variable definitions from parsed HCL.

    Returns:
        Dict of {var_name: {type, default, description, sensitive, validation, ...}}.
    """
    variables = {}
    for var_block in parsed.get("variable", []):
        for name, attrs in var_block.items():
            variables[name] = attrs
    return variables


def find_outputs(parsed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract all output definitions from parsed HCL.

    Returns:
        Dict of {output_name: {value, description, ...}}.
    """
    outputs = {}
    for output_block in parsed.get("output", []):
        for name, attrs in output_block.items():
            outputs[name] = attrs
    return outputs


def find_data_sources(
    parsed: dict[str, Any], data_type: str = ""
) -> list[dict[str, Any]]:
    """Extract data sources from parsed HCL.

    Args:
        parsed: Result of parse_tf_dir or parse_tf_file.
        data_type: Optional filter by data source type.

    Returns:
        List of data source body dicts.
    """
    results = []
    for data_block in parsed.get("data", []):
        if data_type:
            if data_type in data_block:
                results.append(data_block[data_type])
        else:
            results.append(data_block)
    return results


def find_modules(parsed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract all module blocks from parsed HCL.

    Returns:
        Dict of {module_name: {source, ...attrs}}.
    """
    modules = {}
    for mod_block in parsed.get("module", []):
        for name, attrs in mod_block.items():
            modules[name] = attrs
    return modules


def get_resource_attr(resource: dict[str, Any], *path: str) -> Any:
    """Safely navigate nested resource attributes.

    Args:
        resource: Resource attributes dict.
        *path: Sequence of keys to traverse.

    Returns:
        The value at the path, or None if any key is missing.
    """
    current = resource
    for key in path:
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list) and len(current) > 0:
            # HCL2 often wraps blocks in single-element lists
            current = current[0] if isinstance(current[0], dict) else None
            if current is not None:
                current = current.get(key)
        else:
            return None
        if current is None:
            return None
    return current


def get_tags(resource: dict[str, Any]) -> dict[str, str]:
    """Extract tags dict from a resource.

    Args:
        resource: Resource attributes dict.

    Returns:
        Tags dict, or empty dict if no tags.
    """
    tags = resource.get("tags")
    if isinstance(tags, list) and len(tags) > 0:
        return tags[0] if isinstance(tags[0], dict) else {}
    if isinstance(tags, dict):
        return tags
    return {}


def parse_cloudfront_module() -> dict[str, Any]:
    """Convenience: parse the cloudfront-saas module directory."""
    return parse_tf_dir(os.path.join(MODULES_DIR, "cloudfront-saas"))


def parse_root_module() -> dict[str, Any]:
    """Convenience: parse the root terraform directory."""
    return parse_tf_dir(ROOT_DIR)


def parse_proxy_ecs_module() -> dict[str, Any]:
    """Convenience: parse the proxy-ecs module directory."""
    return parse_tf_dir(os.path.join(MODULES_DIR, "proxy-ecs"))


def parse_cloudflare_edge_module() -> dict[str, Any]:
    """Convenience: parse the cloudflare-edge module directory."""
    return parse_tf_dir(os.path.join(MODULES_DIR, "cloudflare-edge"))


def find_rules_in_waf(waf_resource: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract all rule blocks from a WAF WebACL resource.

    Args:
        waf_resource: WAF WebACL resource attributes dict.

    Returns:
        List of rule dicts.
    """
    rules = waf_resource.get("rule", [])
    if isinstance(rules, dict):
        return [rules]
    return rules


def find_rule_by_name(
    waf_resource: dict[str, Any], rule_name: str
) -> dict[str, Any] | None:
    """Find a specific WAF rule by name.

    Args:
        waf_resource: WAF WebACL resource attributes dict.
        rule_name: The rule name to search for.

    Returns:
        The rule dict, or None if not found.
    """
    for rule in find_rules_in_waf(waf_resource):
        if rule.get("name") == rule_name:
            return rule
    return None
