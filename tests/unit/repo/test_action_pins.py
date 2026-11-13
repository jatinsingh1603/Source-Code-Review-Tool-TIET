"""The published GitHub Action pins every action it runs to a commit SHA.

The composite action runs inside client pipelines with their token and LLM key in the
environment, so a moved upstream tag must not change what it executes.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
ACTION = ROOT / "action" / "action.yml"
EXAMPLES = sorted((ROOT / "action" / "examples").glob("*.yml"))
README = ROOT / "action" / "README.md"
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")

pytestmark = pytest.mark.unit


def _composite_refs() -> list[str]:
    data: dict[str, Any] = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    return [step["uses"] for step in data["runs"]["steps"] if "uses" in step]


def test_composite_action_has_remote_steps() -> None:
    assert _composite_refs(), "action.yml no longer uses any action; update this test"


@pytest.mark.parametrize("ref", _composite_refs())
def test_composite_action_steps_are_pinned(ref: str) -> None:
    assert PINNED.match(ref), f"{ref} is not pinned to a commit SHA"


def _example_refs() -> list[str]:
    refs: list[str] = []
    for path in EXAMPLES:
        data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in data["jobs"].values():
            refs.extend(step["uses"] for step in job.get("steps", []) if "uses" in step)
    return refs


def test_examples_use_the_codekavach_action() -> None:
    refs = _example_refs()
    assert EXAMPLES
    assert any("/action@" in ref and "Source-Code-Review-Tool-TIET" in ref for ref in refs)


@pytest.mark.parametrize("ref", _example_refs())
def test_example_steps_are_pinned(ref: str) -> None:
    assert PINNED.match(ref), f"{ref} is not pinned to a commit SHA"


def test_readme_snippet_is_pinned() -> None:
    refs = re.findall(r"^- uses: (\S+)", README.read_text(encoding="utf-8"), flags=re.MULTILINE)
    assert refs
    for ref in refs:
        assert PINNED.match(ref), f"README: {ref} is not pinned to a commit SHA"
