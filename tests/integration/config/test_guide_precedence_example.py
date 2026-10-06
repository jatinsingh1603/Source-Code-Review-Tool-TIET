"""The worked precedence example of the configuration guide, reproduced (E03-41).

The guide shows a user file, a project file and two tables of what ``config show --origin``
reports. The files are kept as fixtures; this test checks that the guide shows exactly those
files, and that every value and origin in the tables is what the loader produces.
"""

import json
import shlex
from pathlib import Path
from typing import Any

import pytest

from tests.support.cli import run_cli
from tests.support.config import ConfigSandbox
from tests.support.doc_blocks import extract_blocks

ROOT = Path(__file__).resolve().parents[3]
GUIDE = ROOT / "docs" / "configuration" / "README.md"
FIXTURES = ROOT / "tests" / "fixtures" / "config" / "guide_precedence"
PRECEDENCE_MARKER = "guide-precedence"
KEYS_MARKER = "guide-precedence-keys"


def table_rows(marker: str) -> list[list[str]]:
    """The body rows of the table directly under ``<!-- marker -->``, cells without backticks."""
    lines = GUIDE.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"<!-- {marker} -->") + 1
    rows: list[list[str]] = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip().replace("`", "") for cell in line.strip().strip("|").split("|")]
        rows.append(cells)
    return rows[2:]  # the header and its separator


@pytest.fixture
def sandbox(config_sandbox: ConfigSandbox) -> ConfigSandbox:
    config_sandbox.write_user((FIXTURES / "user.toml").read_text(encoding="utf-8"))
    config_sandbox.write_project((FIXTURES / "project.toml").read_text(encoding="utf-8"))
    return config_sandbox


def show(command: str, sandbox: ConfigSandbox) -> dict[str, Any]:
    """Run a ``codekavach ...`` command line of the guide and return its JSON document."""
    tokens = shlex.split(command)
    env: dict[str, str] = {}
    while tokens and "=" in tokens[0] and not tokens[0].startswith("-"):
        name, value = tokens.pop(0).split("=", 1)
        env[name] = value
    assert tokens[0] == "codekavach", command
    result = run_cli(
        [*tokens[1:], "--format", "json"],
        cwd=sandbox.root,
        home=sandbox.home,
        env={**sandbox.env, **env},
    )
    assert result.exit_code == 0, result.stderr
    document: dict[str, Any] = json.loads(result.stdout)
    return document


def value_at(document: dict[str, Any], key: str) -> Any:
    node: Any = document["settings"]
    for part in key.split("."):
        node = node[part]
    return node


def test_the_guide_shows_the_fixture_files() -> None:
    blocks = extract_blocks(GUIDE.read_text(encoding="utf-8"), GUIDE.name)
    user = next(block for block in blocks if block.marker == "user-file")
    project = next(block for block in blocks if block.marker == "project-file")
    assert user.text == (FIXTURES / "user.toml").read_text(encoding="utf-8")
    assert project.text == (FIXTURES / "project.toml").read_text(encoding="utf-8")


def test_the_tables_are_present() -> None:
    assert len(table_rows(PRECEDENCE_MARKER)) == 4
    assert [row[0] for row in table_rows(KEYS_MARKER)] == [
        "scan.jobs",
        "scan.exclude",
        "privacy.never_send",
    ]


@pytest.mark.parametrize("row", table_rows(PRECEDENCE_MARKER), ids=lambda row: row[0][:60])
def test_each_run_gives_the_value_and_origin_the_guide_shows(
    row: list[str], sandbox: ConfigSandbox
) -> None:
    command, value, layer = row
    document = show(command, sandbox)
    assert value_at(document, "scan.fail_on") == value
    assert document["origins"]["scan.fail_on"]["layer"] == layer


def test_the_other_keys_of_the_example(sandbox: ConfigSandbox) -> None:
    document = show("codekavach config show --origin", sandbox)
    rows = {row[0]: row for row in table_rows(KEYS_MARKER)}
    origins = document["origins"]

    assert value_at(document, "scan.jobs") == int(rows["scan.jobs"][1])
    assert origins["scan.jobs"]["layer"] == rows["scan.jobs"][2]

    assert value_at(document, "scan.exclude") == json.loads(rows["scan.exclude"][1])
    assert origins["scan.exclude"]["layer"] == rows["scan.exclude"][2]

    never_send = value_at(document, "privacy.never_send")
    assert "**/secrets/**" in never_send
    assert "config/prod/**" in never_send
    assert "**/.env" in never_send  # the defaults are still there
    assert tuple(origins["privacy.never_send"]["contributors"]) == tuple(
        rows["privacy.never_send"][2].split(", ")
    )
    assert "**/secrets/**" in rows["privacy.never_send"][1]
    assert "config/prod/**" in rows["privacy.never_send"][1]


def test_the_profile_outranks_the_project_file(sandbox: ConfigSandbox) -> None:
    # The sentence the guide stresses: the project says medium, the selected profile says high.
    document = show("codekavach config show --origin", sandbox)
    assert value_at(document, "scan.fail_on") == "high"
    assert document["origins"]["scan.fail_on"]["source"] == "builtin:ci"
