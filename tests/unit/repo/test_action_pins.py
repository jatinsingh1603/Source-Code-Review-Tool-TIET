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
