"""GitHub Actions test helpers for parsing and inspecting action.yml, workflows, and templates."""

from __future__ import annotations

import os
from typing import Any

import yaml

# Path constants
_TESTS_DIR = os.path.dirname(os.path.dirname(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)

ACTION_DIR = os.path.join(_PROJECT_ROOT, "github-actions", "security-scan")
SCRIPTS_DIR = os.path.join(ACTION_DIR, "scripts")
WORKFLOWS_DIR = os.path.join(_PROJECT_ROOT, ".github", "workflows")
TEMPLATES_DIR = os.path.join(_PROJECT_ROOT, "templates")


def load_action_yml() -> dict[str, Any]:
    """Parse the composite action action.yml file.

    Returns:
        Parsed YAML dict.
    """
    path = os.path.join(ACTION_DIR, "action.yml")
    with open(path) as f:
        return yaml.safe_load(f)


def load_workflow(name: str) -> dict[str, Any]:
    """Parse a workflow YAML file from .github/workflows/.

    Args:
        name: Filename (e.g. 'security-scan.yml').

    Returns:
        Parsed YAML dict.
    """
    path = os.path.join(WORKFLOWS_DIR, name)
    with open(path) as f:
        return yaml.safe_load(f)


def load_template(name: str) -> dict[str, Any]:
    """Parse a template YAML file from templates/.

    Args:
        name: Filename (e.g. 'dependabot.yml').

    Returns:
        Parsed YAML dict.
    """
    path = os.path.join(TEMPLATES_DIR, name)
    with open(path) as f:
        return yaml.safe_load(f)


def get_action_inputs(action: dict[str, Any]) -> dict[str, Any]:
    """Extract input definitions from a composite action.

    Returns:
        Dict of {input_name: {description, required, default, ...}}.
    """
    return action.get("inputs", {})


def get_action_outputs(action: dict[str, Any]) -> dict[str, Any]:
    """Extract output definitions from a composite action.

    Returns:
        Dict of {output_name: {description, value}}.
    """
    return action.get("outputs", {})


def get_composite_steps(action: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract steps from a composite action's runs block.

    Returns:
        List of step dicts.
    """
    return action.get("runs", {}).get("steps", [])


def find_step_by_name(
    steps: list[dict[str, Any]], name: str
) -> dict[str, Any] | None:
    """Find a step by exact name match.

    Args:
        steps: List of step dicts.
        name: Step name to match.

    Returns:
        The matching step dict, or None.
    """
    for step in steps:
        if step.get("name") == name:
            return step
    return None


def find_step_by_id(
    steps: list[dict[str, Any]], step_id: str
) -> dict[str, Any] | None:
    """Find a step by its id attribute.

    Args:
        steps: List of step dicts.
        step_id: Step id to match.

    Returns:
        The matching step dict, or None.
    """
    for step in steps:
        if step.get("id") == step_id:
            return step
    return None


def find_steps_containing(
    steps: list[dict[str, Any]], text: str
) -> list[dict[str, Any]]:
    """Find steps whose name, run, or uses fields contain the given text.

    Args:
        steps: List of step dicts.
        text: Substring to search for.

    Returns:
        List of matching step dicts.
    """
    matches = []
    for step in steps:
        for field in ("name", "run", "uses"):
            value = step.get(field, "")
            if isinstance(value, str) and text in value:
                matches.append(step)
                break
    return matches


def get_step_condition(step: dict[str, Any]) -> str | None:
    """Extract the 'if' condition from a step.

    Returns:
        The condition string, or None if no condition.
    """
    return step.get("if")


def get_workflow_permissions(workflow: dict[str, Any]) -> dict[str, str]:
    """Extract top-level permissions from a workflow.

    Returns:
        Dict of {permission: access_level}.
    """
    perms = workflow.get("permissions", {})
    if isinstance(perms, str):
        return {"_all": perms}
    return perms or {}


def get_workflow_jobs(workflow: dict[str, Any]) -> dict[str, Any]:
    """Extract jobs from a workflow.

    Returns:
        Dict of {job_name: job_config}.
    """
    return workflow.get("jobs", {})
