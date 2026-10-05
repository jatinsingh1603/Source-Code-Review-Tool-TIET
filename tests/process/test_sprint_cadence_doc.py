"""The sprint cadence guide agrees with the board configuration and is linked to."""

import json
import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
GUIDE = REPO / "docs" / "process" / "sprint-cadence.md"
BOARD = REPO / "tools" / "project" / "board.json"
PLAN = REPO / "docs" / "PLAN.md"
BOARD_FIELDS = ("Priority", "Size", "Epic", "Milestone", "Sprint")
LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")


@pytest.fixture(scope="module")
def guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def board() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(BOARD.read_text(encoding="utf-8"))
    return loaded


def table_rows(text: str) -> list[list[str]]:
    """The cells of every Markdown table row in ``text``."""
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in text.splitlines()
        if line.lstrip().startswith("|")
    ]


def test_every_sprint_iteration_is_listed_with_its_dates(guide: str, board: dict[str, Any]) -> None:
    iterations = board["fields"]["Sprint"]["configuration"]["iterations"]
    assert len(iterations) == 13
    rows = {row[0]: row for row in table_rows(guide) if row[0].startswith("Sprint ")}
    assert list(rows) == [iteration["title"] for iteration in iterations]
    for iteration in iterations:
        row = rows[iteration["title"]]
        start = date.fromisoformat(iteration["startDate"])
        assert row[1] == iteration["startDate"], row
        assert start.weekday() == 0, "a sprint starts on a Monday"
        assert row[2] == (start + timedelta(days=6)).isoformat(), row


def test_status_options_and_board_fields_are_documented(guide: str, board: dict[str, Any]) -> None:
    rows = table_rows(guide)
    first_cells = {row[0] for row in rows}
    statuses = [option["name"] for option in board["fields"]["Status"]["options"]]
    assert statuses == ["Backlog", "Ready", "In progress", "In review", "Done"]
    for status in statuses:
        assert status in first_cells, status
        row = next(row for row in rows if row[0] == status)
        assert all(cell for cell in row[1:]), f"{status} needs entry and exit conditions"
    for name in BOARD_FIELDS:
        assert name in board["fields"]
        assert name in first_cells, name
    for name in ("Priority", "Size"):
        for option in board["fields"][name]["options"]:
            assert f"`{option['name']}`" in guide, option["name"]


def test_milestones_are_named_as_in_the_plan(guide: str) -> None:
    plan_rows = [row for row in table_rows(PLAN.read_text(encoding="utf-8")) if len(row) == 3]
    milestones = {row[0]: row[1] for row in plan_rows if re.fullmatch(r"M\d .+", row[0])}
    assert len(milestones) == 9
    for title, due in milestones.items():
        assert f"{title} ({due})" in guide or f"{title} is due on {due}" in guide, title


@pytest.mark.parametrize("page", ["README.md", "AGENTS.md"])
def test_entry_pages_link_to_the_guide(page: str) -> None:
    text = (REPO / page).read_text(encoding="utf-8")
    targets = [target for target in LINK.findall(text) if "sprint-cadence" in target]
    assert targets, f"{page} has no link to the sprint cadence guide"
    for target in targets:
        assert (REPO / target).resolve() == GUIDE.resolve()


def test_relative_links_of_the_guide_resolve(guide: str) -> None:
    for target in LINK.findall(guide):
        if target.startswith(("http://", "https://")):
            continue
        assert (GUIDE.parent / target).exists(), target


def test_guide_is_a_runbook_with_roles(guide: str) -> None:
    headings = [line[3:].strip() for line in guide.splitlines() if line.startswith("## ")]
    assert headings == [
        "1. Sprint calendar",
        "2. Board fields",
        "3. Columns",
        "4. Weekly rhythm",
        "5. Roles",
        "6. Related pages",
    ]
    for phrase in ("Sprint planning", "Mid-sprint check", "E42-03", "E42-07", "E42-09"):
        assert phrase in guide, phrase
