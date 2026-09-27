"""Helpers for tests that check GitHub Actions workflow files."""

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

_PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def load_workflow(path: Path) -> dict[str, Any]:
    """Load a workflow, mapping the YAML 1.1 boolean key ``True`` back to ``on``."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path} is not a mapping")
    if True in data:
        data["on"] = data.pop(True)
    return data


def action_refs(workflow: Mapping[str, Any]) -> list[str]:
    """Return every ``uses:`` value in the workflow's jobs."""
    refs: list[str] = []
    for job in workflow.get("jobs", {}).values():
        if "uses" in job:
            refs.append(job["uses"])
        refs.extend(step["uses"] for step in job.get("steps", []) if "uses" in step)
    return refs


def assert_hardened(path: Path) -> None:
    """Assert the hardening rules of E01-18 for one workflow file."""
    text = path.read_text(encoding="utf-8")
    assert "pull_request_target" not in text, f"{path.name}: pull_request_target is forbidden"
    assert "secrets." not in text, f"{path.name}: secrets must not be referenced"
    workflow = load_workflow(path)
    assert workflow.get("permissions") == {"contents": "read"}, f"{path.name}: permissions"
    for name, job in workflow.get("jobs", {}).items():
        permissions = job.get("permissions")
        assert permissions in (None, {"contents": "read"}, {}), f"{path.name}: {name} widens"
    for ref in action_refs(workflow):
        assert _PINNED.match(ref), f"{path.name}: {ref} is not pinned to a commit SHA"
