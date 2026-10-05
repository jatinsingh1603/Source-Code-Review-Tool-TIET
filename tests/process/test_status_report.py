"""Unit tests of ``tools/status_report.py``: classification, points, aggregation, token, HTTP."""

import io
import json
import tomllib
import urllib.error
from datetime import date
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from tests.process._tool import RECORDING, REPO
from tests.process._tool import status_report as tool

M0 = tool.Milestone("M0 Foundations", date(2026, 9, 21), date(2026, 9, 27))
M1 = tool.Milestone("M1 Privacy layer MVP + Demo 1", date(2026, 9, 28), date(2026, 10, 5))
PLANTED = "planted-value-for-the-leak-test"
SIZE_FIELD, EPIC_FIELD, SPRINT_FIELD = "field-size", "field-epic", "field-sprint"
BOARD = tool.Board(
    project_id="project-1",
    fields={
        SIZE_FIELD: ("Size", {"option-s": "S", "option-l": "L"}),
        EPIC_FIELD: ("Epic", {"option-e42": "E42 Project management"}),
        SPRINT_FIELD: ("Sprint", {"iteration-1": "Sprint 1"}),
    },
    sprints=[
        tool.Sprint(1, "Sprint 1", date(2026, 9, 21)),
        tool.Sprint(2, "Sprint 2", date(2026, 9, 28)),
        tool.Sprint(3, "Sprint 3", date(2026, 10, 5)),
    ],
)


def item(number: int, **changes: Any) -> Any:
    values: dict[str, Any] = {
        "number": number,
        "title": f"[E01-{number:02d}] infra: item {number}",
        "created": date(2026, 9, 20),
        "closed": None,
        "milestone": M0.title,
        "labels": frozenset({"size:M"}),
    }
    values.update(changes)
    return tool.Item(**values)


# expected progress and the state classifier


@pytest.mark.parametrize(
    ("on", "expected"),
    [
        (date(2026, 9, 20), 0.0),  # the day before the start
        (date(2026, 9, 21), 100 / 7),  # first day
        (date(2026, 9, 24), 400 / 7),
        (date(2026, 9, 26), 600 / 7),
        (date(2026, 9, 27), 100.0),  # the due date
        (date(2026, 10, 30), 100.0),  # after it
    ],
)
def test_expected_progress_is_linear_from_start_to_due_date(on: date, expected: float) -> None:
    assert tool.expected_percent(M0, on) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("percent", "expected", "state"),
    [
        (60.0, 60.0, "ON_TRACK"),  # exactly as expected
        (60.01, 60.0, "ON_TRACK"),
        (0.0, 0.0, "ON_TRACK"),
        (100.0, 100.0, "ON_TRACK"),
        (59.99, 60.0, "AT_RISK"),
        (40.0, 60.0, "AT_RISK"),  # the edge of the band
        (39.99, 60.0, "OFF_TRACK"),
        (20.0, 60.0, "OFF_TRACK"),  # the example of the issue
        (35.0, 100.0, "OFF_TRACK"),
        (80.0, 100.0, "AT_RISK"),
        (79.0, 100.0, "OFF_TRACK"),
    ],
)
def test_state_classifier(percent: float, expected: float, state: str) -> None:
    assert tool.classify(percent, expected) == state
    assert tool.AT_RISK_BAND == 20.0


def test_milestone_progress_across_boundary_dates() -> None:
    items = [
        item(1, closed=date(2026, 9, 22)),
        item(2, closed=date(2026, 9, 27)),
        item(3, closed=date(2026, 9, 28)),
        item(4),
        item(5, created=date(2026, 9, 30)),
        item(6, milestone=M1.title),
        item(7, milestone=None, closed=date(2026, 9, 23)),
    ]
    on_due = tool.milestone_progress(items, [M0, M1], date(2026, 9, 27))
    assert [(r.title, r.open, r.closed, r.percent, r.state) for r in on_due] == [
        (M0.title, 2, 2, 50, "OFF_TRACK"),
        (M1.title, 1, 0, 0, "ON_TRACK"),
    ]
    first_day = tool.milestone_progress(items, [M0], date(2026, 9, 22))[0]
    assert (first_day.open, first_day.closed, first_day.state) == (3, 1, "AT_RISK")
    later = tool.milestone_progress(items, [M0, M1], date(2026, 10, 1))
    assert [(r.open, r.closed, r.percent, r.state) for r in later] == [
        (2, 3, 60, "OFF_TRACK"),
        (1, 0, 0, "OFF_TRACK"),
    ]
    empty = tool.milestone_progress([], [M0], date(2026, 9, 20))[0]
    assert (empty.open, empty.closed, empty.percent, empty.state) == (0, 0, 0, "ON_TRACK")


# points and epics


def test_size_to_points_mapping() -> None:
    assert dict(tool.POINTS) == {"XS": 1, "S": 2, "M": 5, "L": 8}
    sizes = {"size:XS": 1, "size:S": 2, "size:M": 5, "size:L": 8, "size:XL": 0}
    for label, points in sizes.items():
        assert item(1, labels=frozenset({label, "P1-high"})).points == points
    assert item(1, labels=frozenset()).points == 0
    assert item(1, labels=frozenset()).size is None
    board_wins = item(1, labels=frozenset({"size:XS"}), fields={"Size": "L"})
    assert (board_wins.size, board_wins.points) == ("L", 8)


def test_epic_aggregation() -> None:
    items = [
        item(1, title="[E01] Epic: scaffolding", labels=frozenset({"type:epic"})),
        item(2, title="[E01-01] a", closed=date(2026, 9, 22)),
        item(3, title="[E01-02] b", labels=frozenset({"size:S"})),
        item(4, title="[E02-01] c", labels=frozenset({"size:L"}), closed=date(2026, 9, 29)),
        item(5, title="[E02-02] d", fields={"Epic": "E42 Project management", "Size": "S"}),
        item(6, title="no key", labels=frozenset(), closed=date(2026, 9, 21)),
        item(7, title="[E01-03] later", created=date(2026, 10, 2)),
    ]
    rows = {row.epic: row for row in tool.epic_progress(items, date(2026, 9, 27))}
    assert list(rows) == ["(no epic)", "E01", "E02", "E42 Project management"]
    summary = {
        epic: (row.open, row.closed, row.points_open, row.points_closed)
        for epic, row in rows.items()
    }
    assert summary == {
        "(no epic)": (0, 1, 0, 0),
        "E01": (1, 1, 2, 5),
        "E02": (1, 0, 8, 0),
        "E42 Project management": (1, 0, 2, 0),
    }


def test_sprint_metrics_and_velocity() -> None:
    items = [
        item(1, closed=date(2026, 9, 21)),
        item(2, closed=date(2026, 9, 27), labels=frozenset({"size:S"})),
        item(3, closed=date(2026, 9, 28), labels=frozenset({"size:L"})),
        item(4, closed=date(2026, 10, 4), labels=frozenset()),
        item(5),
    ]
    first = tool.sprint_metrics(items, BOARD, BOARD.sprint(1))
    assert (first.issues_closed, first.points_closed, first.velocity) == (2, 7, 7.0)
    second = tool.sprint_metrics(items, BOARD, BOARD.sprint(2))
    assert (second.issues_closed, second.points_closed, second.velocity) == (2, 8, 7.5)
    third = tool.sprint_metrics(items, BOARD, BOARD.sprint(3))
    assert (third.issues_closed, third.points_closed, third.velocity) == (0, 0, 5.0)
    assert "| 7.5 |" in tool.metrics_table(second)
    assert "| 7 |" in tool.metrics_table(first)
    with pytest.raises(tool.StatusReportError, match="no Sprint 9; known sprints: 1, 2, 3"):
        BOARD.sprint(9)


# items of the API answer


def test_field_values_are_mapped_by_option_and_iteration_id() -> None:
    node = {
        "content": {
            "number": 7,
            "title": "[E05-01] cli: x",
            "createdAt": "2026-09-20T23:59:00Z",
            "closedAt": "2026-09-27T23:30:00+00:00",
            "milestone": {"title": M0.title},
            "labels": {"nodes": [{"name": "size:M"}, {"name": "P1-high"}]},
        },
        "fieldValues": {
            "nodes": [
                {},
                {"optionId": "option-l", "field": {"id": SIZE_FIELD}},
                {"optionId": "option-e42", "field": {"id": EPIC_FIELD}},
                {"iterationId": "iteration-1", "field": {"id": SPRINT_FIELD}},
                {"optionId": "unknown-option", "field": {"id": SIZE_FIELD}},
                {"optionId": "option-s", "field": {"id": "unknown-field"}},
            ]
        },
    }
    parsed = tool.parse_item(node, BOARD)
    assert parsed.fields == {"Size": "L", "Epic": "E42 Project management", "Sprint": "Sprint 1"}
    assert (parsed.size, parsed.points, parsed.epic) == ("L", 8, "E42 Project management")
    assert (parsed.created, parsed.closed) == (date(2026, 9, 20), date(2026, 9, 27))
    assert tool.parse_item({"content": {}}, BOARD) is None
    assert tool.parse_item({"content": None}, BOARD) is None


def test_items_are_fetched_page_by_page() -> None:
    cursors: list[Any] = []
    replay = tool.replay_graph(RECORDING)

    def graph(query: str, variables: dict[str, Any]) -> Any:
        cursors.append(variables["cursor"])
        assert variables["projectId"] == BOARD.project_id
        assert "items(first: $pageSize, after: $cursor)" in query
        return replay(query, variables)

    items = tool.fetch_items(graph, BOARD)
    assert cursors == [None, "CURSOR_PAGE_1"]
    assert [entry.number for entry in items] == list(range(1, 13))
    with pytest.raises(tool.StatusReportError, match="no further answer"):
        replay("", {})
    with pytest.raises(tool.StatusReportError, match="project was not found"):
        tool.fetch_items(lambda _query, _variables: {"node": None}, BOARD)


def test_board_and_plan_are_read_from_the_repository() -> None:
    board = tool.load_board()
    source = json.loads(tool.BOARD_FILE.read_text(encoding="utf-8"))
    assert board.project_id == source["project"]["id"]
    assert [sprint.number for sprint in board.sprints] == list(range(1, 14))
    assert board.sprint(1).end == date(2026, 9, 27)
    names = {name for name, _ in board.fields.values()}
    assert {"Status", "Priority", "Size", "Epic", "Sprint"} <= names
    milestones = tool.load_milestones(board.sprints[0].start)
    assert [m.title for m in milestones][:2] == [M0.title, M1.title]
    assert (milestones[0].start, milestones[1].start) == (M0.start, M1.start)
    assert len(milestones) == 9


def test_tool_holds_no_project_coordinates() -> None:
    """Ids come from tools/project/board.json; none is written into the script."""
    script = tool.BOARD_FILE.parents[1].joinpath("status_report.py").read_text(encoding="utf-8")
    source = json.loads(tool.BOARD_FILE.read_text(encoding="utf-8"))
    ids = [source["project"]["id"]] + [entry["id"] for entry in source["fields"].values()]
    for entry in source["fields"].values():
        ids += [option["id"] for option in entry.get("options", [])]
        ids += [it["id"] for it in entry.get("configuration", {}).get("iterations", [])]
    assert len(ids) > 60
    for identifier in ids:
        assert identifier not in script


# token


def test_token_comes_from_the_environment_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tool.shutil, "which", lambda _name: None)
    assert tool.resolve_token({"GITHUB_TOKEN": f" {PLANTED} ", "GH_TOKEN": "other"}) == PLANTED
    assert tool.resolve_token({"GITHUB_TOKEN": "", "GH_TOKEN": PLANTED}) == PLANTED
    with pytest.raises(tool.StatusReportError) as caught:
        tool.resolve_token({})
    assert "GITHUB_TOKEN or GH_TOKEN" in str(caught.value)
    assert "gh auth login" in str(caught.value)


def test_token_falls_back_to_the_gh_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = f"{PLANTED}\n"

    def run(command: list[str], **_options: Any) -> Completed:
        calls.append(command)
        return Completed()

    monkeypatch.setattr(tool.shutil, "which", lambda _name: "/usr/bin/gh")
    monkeypatch.setattr(tool.subprocess, "run", run)
    assert tool.resolve_token({}) == PLANTED
    assert calls == [["/usr/bin/gh", "auth", "token"]]
    Completed.returncode = 1
    with pytest.raises(tool.StatusReportError):
        tool.resolve_token({})


# HTTP


class FakeResponse(io.BytesIO):
    def __enter__(self) -> "FakeResponse":
        return self


def http_error(status: int, remaining: str | None = None) -> urllib.error.HTTPError:
    headers = Message()
    if remaining is not None:
        headers["X-RateLimit-Remaining"] = remaining
    body = io.BytesIO(f"bad credentials for {PLANTED}".encode())
    return urllib.error.HTTPError(tool.API_URL, status, "refused", headers, body)


def test_graphql_sends_one_authorised_post_to_the_github_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []

    def urlopen(request: Any, timeout: float) -> FakeResponse:
        seen.append((request, timeout))
        return FakeResponse(json.dumps({"data": {"node": {"id": "x"}}}).encode())

    monkeypatch.setattr(tool.urllib.request, "urlopen", urlopen)
    data = tool.live_graph(PLANTED)("query { viewer { login } }", {"cursor": None})
    assert data == {"node": {"id": "x"}}
    ((request, timeout),) = seen
    assert request.full_url == "https://api.github.com/graphql" == tool.API_URL
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == f"Bearer {PLANTED}"
    assert json.loads(request.data) == {
        "query": "query { viewer { login } }",
        "variables": {"cursor": None},
    }
    assert timeout == tool.TIMEOUT_SECONDS


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (http_error(401), "refused the token (HTTP 401)"),
        (http_error(403, "12"), "refused the token (HTTP 403)"),
        (http_error(403, "0"), "rate limit is used up (HTTP 403)"),
        (http_error(429, "0"), "rate limit is used up (HTTP 429)"),
        (http_error(502), "answered with HTTP 502"),
        (urllib.error.URLError(f"no route for {PLANTED}"), "cannot reach the GitHub API: URLError"),
        (TimeoutError(), "cannot reach the GitHub API: TimeoutError"),
    ],
)
def test_http_failures_are_reported_without_the_token(
    monkeypatch: pytest.MonkeyPatch, failure: Exception, message: str
) -> None:
    def urlopen(_request: Any, timeout: float) -> FakeResponse:
        raise failure

    monkeypatch.setattr(tool.urllib.request, "urlopen", urlopen)
    with pytest.raises(tool.StatusReportError) as caught:
        tool.live_graph(PLANTED)("query", {})
    assert message in str(caught.value)
    assert PLANTED not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"<html>", "did not answer with JSON"),
        (b"[]", "not a JSON object"),
        (b'{"data": null}', "has no data"),
        (b'{"errors": [{"type": "NOT_FOUND", "message": "x"}]}', "reported errors: NOT_FOUND"),
        (b'{"errors": [{"message": "x"}], "data": {}}', "reported errors: error"),
    ],
)
def test_unexpected_answers_are_reported(
    monkeypatch: pytest.MonkeyPatch, payload: bytes, message: str
) -> None:
    monkeypatch.setattr(tool.urllib.request, "urlopen", lambda _r, timeout: FakeResponse(payload))
    with pytest.raises(tool.StatusReportError, match=message):
        tool.live_graph(PLANTED)("query", {})


# lint exemption


def test_only_this_tool_is_exempt_from_the_network_import_ban() -> None:
    config = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    ignores = config["tool"]["ruff"]["lint"]["per-file-ignores"]
    exempt = [pattern for pattern, codes in ignores.items() if "TID251" in codes]
    assert [pattern for pattern in exempt if pattern.startswith("tools")] == [
        "tools/status_report.py"
    ]
    others = [
        path
        for path in sorted((REPO / "tools").rglob("*.py"))
        if path.name != "status_report.py"
        and "urllib.request" in Path(path).read_text(encoding="utf-8")
    ]
    assert others == []


def test_sprint_guide_documents_the_tool() -> None:
    guide = (REPO / "docs" / "process" / "sprint-cadence.md").read_text(encoding="utf-8")
    for phrase in (
        "python tools/status_report.py draft --sprint 2",
        "python tools/status_report.py fetch",
        "`GITHUB_TOKEN` or `GH_TOKEN`",
        "--replay FILE",
        "--force",
    ):
        assert phrase in guide, phrase
    assert tool.note_path(tool.load_board().sprint(2)).name == "2026-10-04-sprint-02.md"
