"""The status-note template and every note follow one format that tooling can read."""

import json
import re
from datetime import date, timedelta
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
STATUS = REPO / "docs" / "status"
TEMPLATE = STATUS / "TEMPLATE.md"
FIRST_NOTE = STATUS / "2026-09-27-sprint-01.md"
BOARD = REPO / "tools" / "project" / "board.json"
PLAN = REPO / "docs" / "PLAN.md"

HEADINGS = [
    "Sprint",
    "Milestone status",
    "Highlights",
    "Metrics",
    "Risks and blockers",
    "Next sprint",
    "Overall status",
]
TABLE_HEADER = "| Milestone | Due | Open | Closed | Percent | State |"
STATES = ("ON_TRACK", "AT_RISK", "OFF_TRACK")
MARKERS = (
    "<!-- milestone:auto-start -->",
    "<!-- milestone:auto-end -->",
    "<!-- metrics:auto-start -->",
    "<!-- metrics:auto-end -->",
)
NOTE_NAME = re.compile(r"(\d{4}-\d{2}-\d{2})-sprint-(\d{2})\.md")
NOTES = sorted(path for path in STATUS.glob("*.md") if NOTE_NAME.fullmatch(path.name))


def h2_headings(text: str) -> list[str]:
    return [line[3:].strip() for line in text.splitlines() if line.startswith("## ")]


def region(text: str, name: str) -> list[str]:
    """The lines between the ``name:auto`` markers."""
    start, end = f"<!-- {name}:auto-start -->", f"<!-- {name}:auto-end -->"
    assert text.count(start) == 1, start
    assert text.count(end) == 1, end
    inner = text.split(start, 1)[1].split(end, 1)[0]
    return [line for line in inner.splitlines() if line.strip()]


def milestone_rows(text: str) -> list[list[str]]:
    lines = region(text, "milestone")
    assert lines[0] == TABLE_HEADER
    assert set(lines[1]) <= set("|- ")
    return [[cell.strip() for cell in line.strip("|").split("|")] for line in lines[2:]]


def check_format(text: str) -> None:
    assert h2_headings(text) == HEADINGS
    positions = [text.index(marker) for marker in MARKERS]
    assert positions == sorted(positions)
    assert (
        text.index("## Milestone status")
        < positions[0]
        < positions[1]
        < text.index("## Highlights")
    )
    assert (
        text.index("## Metrics") < positions[2] < positions[3] < text.index("## Risks and blockers")
    )
    for row in milestone_rows(text):
        assert len(row) == 6, row
        date.fromisoformat(row[1])
        opened, closed = int(row[2]), int(row[3])
        total = opened + closed
        assert row[4] == f"{round(100 * closed / total) if total else 0}%", row
        assert row[5] in STATES, row
    metrics = [line.split("|")[1].strip() for line in region(text, "metrics")[2:]]
    assert metrics == [
        "Issues closed in the sprint",
        "Points closed in the sprint",
        "Velocity (mean points closed per sprint so far)",
    ]
    assert "XS=1, S=2, M=5, L=8" in text
    overall = text.split("## Overall status", 1)[1]
    assert any(state in overall for state in STATES)


def test_template_has_the_seven_headings_in_order_and_the_markers() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert h2_headings(text) == HEADINGS
    for marker in MARKERS:
        assert text.count(marker) == 1, marker
    check_format(text)


def test_template_table_header_is_exact() -> None:
    lines = TEMPLATE.read_text(encoding="utf-8").splitlines()
    header = lines[lines.index("<!-- milestone:auto-start -->") + 1]
    assert header == "| Milestone | Due | Open | Closed | Percent | State |"


def test_template_documents_naming_points_and_vocabulary() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    head = text.split("# Status note", 1)[0]
    assert "YYYY-MM-DD-sprint-NN.md" in head
    assert "Sunday" in head
    assert "Points per Size: XS=1, S=2, M=5, L=8." in text
    assert "State is one of ON_TRACK, AT_RISK, OFF_TRACK." in text


def test_there_is_a_first_note() -> None:
    assert FIRST_NOTE in NOTES


@pytest.mark.parametrize("note", NOTES, ids=[path.name for path in NOTES])
def test_note_follows_the_template(note: Path) -> None:
    text = note.read_text(encoding="utf-8")
    check_format(text)
    assert "<!--\n" not in text, "delete the usage comment of the template in a note"
    match = NOTE_NAME.fullmatch(note.name)
    assert match is not None
    end, number = date.fromisoformat(match.group(1)), int(match.group(2))
    assert end.weekday() == 6, "the date in the file name is the Sunday that ends the sprint"
    board = json.loads(BOARD.read_text(encoding="utf-8"))
    iterations = board["fields"]["Sprint"]["configuration"]["iterations"]
    start = date.fromisoformat(
        next(item["startDate"] for item in iterations if item["title"] == f"Sprint {number}")
    )
    assert end == start + timedelta(days=6)
    assert f"| Sprint | Sprint {number} |" in text
    assert f"{start.isoformat()} (Monday) to {end.isoformat()} (Sunday)" in text


def test_first_note_names_sprint_1_and_every_milestone_of_the_plan() -> None:
    text = FIRST_NOTE.read_text(encoding="utf-8")
    assert "| Sprint | Sprint 1 |" in text
    assert "| Milestone in focus | M0 Foundations |" in text
    plan = PLAN.read_text(encoding="utf-8")
    planned = dict(re.findall(r"^\| (M\d [^|]+?) \| (\d{4}-\d{2}-\d{2}) \|", plan, flags=re.M))
    assert len(planned) == 9
    rows = {row[0]: row[1] for row in milestone_rows(text)}
    assert rows == planned


def test_status_index_lists_every_note() -> None:
    index = (STATUS / "README.md").read_text(encoding="utf-8")
    assert "(TEMPLATE.md)" in index
    for note in NOTES:
        assert f"({note.name})" in index, note.name
