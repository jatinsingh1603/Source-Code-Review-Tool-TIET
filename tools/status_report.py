"""Fetch the progress of the project board and draft the weekly status note (E42-04).

Usage::

    python tools/status_report.py fetch [--sprint N] [--replay FILE]
    python tools/status_report.py draft --sprint N [--stdout | --out PATH] [--replay FILE]
    python tools/status_report.py post-status --sprint N [--post] [--replay FILE]
    python tools/status_report.py charts --milestone TITLE [--out-dir DIR] [--replay FILE]

``fetch`` prints progress per milestone and per epic as JSON. ``draft`` loads
``docs/status/TEMPLATE.md``, fills the regions between the ``milestone:auto`` and ``metrics:auto``
markers and the facts of the Sprint table, and leaves the prose sections as they are. The format
of the note is fixed by E42-03 and checked by ``tests/process/test_status_note_format.py``.
``post-status`` computes the overall state of the project and prints the Projects v2 status
update it would post; it sends it only with ``--post`` (E42-05). ``charts`` writes the burndown
of a milestone and the velocity per sprint as CSV, and as PNG when matplotlib is installed
(E42-06).

This is project tooling, not part of the shipped package: it reads CodeKavach's own board and
depends on no product module. Project coordinates (project id, field and option ids, sprint
dates) come from ``tools/project/board.json``; milestone due dates from ``docs/PLAN.md``.

The only host contacted is the GitHub GraphQL API, and only without ``--replay``. The token is
read from ``GITHUB_TOKEN`` or ``GH_TOKEN``, or from ``gh auth token``; it is sent in the request
header and is not printed, logged or written anywhere.
"""

import argparse
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
BOARD_FILE: Final = REPO_ROOT / "tools" / "project" / "board.json"
PLAN_FILE: Final = REPO_ROOT / "docs" / "PLAN.md"
STATUS_DIR: Final = REPO_ROOT / "docs" / "status"
TEMPLATE_FILE: Final = STATUS_DIR / "TEMPLATE.md"
CHARTS_DIR: Final = STATUS_DIR / "charts"
CHART_SIZE: Final = (8.0, 4.5)  # inches
CHART_DPI: Final = 100

API_URL: Final = "https://api.github.com/graphql"
TOKEN_VARIABLES: Final = ("GITHUB_TOKEN", "GH_TOKEN")
TIMEOUT_SECONDS: Final = 30
PAGE_SIZE: Final = 100
MAX_PAGES: Final = 50

POINTS: Final[Mapping[str, int]] = {"XS": 1, "S": 2, "M": 5, "L": 8}
ON_TRACK: Final = "ON_TRACK"
AT_RISK: Final = "AT_RISK"
OFF_TRACK: Final = "OFF_TRACK"
# A milestone up to this many percentage points behind the expected progress is AT_RISK.
AT_RISK_BAND: Final = 20.0
EPIC_LABEL: Final = "type:epic"
SIZE_LABEL_PREFIX: Final = "size:"
NO_EPIC: Final = "(no epic)"
# From best to worst; the overall state of the project is the worst open milestone.
SEVERITY: Final = (ON_TRACK, AT_RISK, OFF_TRACK)
# Internal state -> ProjectV2StatusUpdateStatus. COMPLETE and INACTIVE are set by people.
API_STATUS: Final[Mapping[str, str]] = {
    ON_TRACK: "ON_TRACK",
    AT_RISK: "AT_RISK",
    OFF_TRACK: "OFF_TRACK",
}
# Our own bound for the body of a status update; nine milestone lines need about 800.
BODY_LIMIT: Final = 1500

MILESTONE_HEADER: Final = "| Milestone | Due | Open | Closed | Percent | State |"
MILESTONE_RULE: Final = "|-----------|-----|------|--------|---------|-------|"
METRICS_HEADER: Final = "| Metric | Value |"
METRICS_RULE: Final = "|--------|-------|"

ITEMS_QUERY: Final = """
query($projectId: ID!, $cursor: String, $pageSize: Int!) {
  node(id: $projectId) {
    ... on ProjectV2 {
      items(first: $pageSize, after: $cursor) {
        nodes {
          content {
            ... on Issue {
              number
              title
              state
              createdAt
              closedAt
              milestone { title }
              labels(first: 20) { nodes { name } }
            }
          }
          fieldValues(first: 30) {
            nodes {
              ... on ProjectV2ItemFieldSingleSelectValue {
                optionId
                field { ... on ProjectV2SingleSelectField { id } }
              }
              ... on ProjectV2ItemFieldIterationValue {
                iterationId
                field { ... on ProjectV2IterationField { id } }
              }
            }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

STATUS_UPDATE_MUTATION: Final = """
mutation($input: CreateProjectV2StatusUpdateInput!) {
  createProjectV2StatusUpdate(input: $input) {
    statusUpdate { id }
  }
}
"""

Graph = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]


class StatusReportError(Exception):
    """A problem to report to the user in one line; the tool exits with status 1."""


# board, plan


@dataclass(frozen=True)
class Sprint:
    """One iteration of the board's Sprint field."""

    number: int
    title: str
    start: date

    @property
    def end(self) -> date:
        """The Sunday that ends the sprint."""
        return self.start + timedelta(days=6)


@dataclass(frozen=True)
class Board:
    """The coordinates of the project board, as ``tools/project/board.json`` records them."""

    project_id: str
    # field id -> (field name, {option or iteration id -> name})
    fields: Mapping[str, tuple[str, Mapping[str, str]]]
    sprints: Sequence[Sprint]

    def sprint(self, number: int) -> Sprint:
        """The sprint with this number.

        Raises:
            StatusReportError: The board has no such sprint.
        """
        for sprint in self.sprints:
            if sprint.number == number:
                return sprint
        known = ", ".join(str(sprint.number) for sprint in self.sprints)
        raise StatusReportError(f"the board has no Sprint {number}; known sprints: {known}")


def load_board(path: Path = BOARD_FILE) -> Board:
    """Read the board coordinates.

    Raises:
        StatusReportError: The file is missing or does not have the expected shape.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        fields: dict[str, tuple[str, Mapping[str, str]]] = {}
        sprints: list[Sprint] = []
        for name, entry in raw["fields"].items():
            if "options" in entry:
                fields[entry["id"]] = (name, {o["id"]: o["name"] for o in entry["options"]})
            elif "configuration" in entry:
                iterations = entry["configuration"]["iterations"]
                fields[entry["id"]] = (name, {i["id"]: i["title"] for i in iterations})
                if name == "Sprint":
                    sprints = [
                        Sprint(
                            number=int(i["title"].rsplit(" ", 1)[1]),
                            title=i["title"],
                            start=date.fromisoformat(i["startDate"]),
                        )
                        for i in iterations
                    ]
        return Board(project_id=raw["project"]["id"], fields=fields, sprints=sprints)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        raise StatusReportError(
            f"cannot read board coordinates from {path}: {type(error).__name__}"
        ) from error


@dataclass(frozen=True)
class Milestone:
    """A milestone of ``docs/PLAN.md`` section 5 with the period its progress is measured over."""

    title: str
    start: date
    due: date


_MILESTONE_ROW: Final = re.compile(r"^\| (M\d+ [^|]+?) \| (\d{4}-\d{2}-\d{2}) \|", re.MULTILINE)


def load_milestones(first_start: date, path: Path = PLAN_FILE) -> list[Milestone]:
    """The milestones of the plan, in order.

    The plan gives due dates only. The first milestone starts with the first sprint; each later
    one starts on the day after the due date of the one before it.

    Raises:
        StatusReportError: The plan cannot be read or has no milestone table.
    """
    try:
        rows = _MILESTONE_ROW.findall(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise StatusReportError(f"cannot read {path}: {type(error).__name__}") from error
    if not rows:
        raise StatusReportError(f"no milestone table found in {path}")
    milestones: list[Milestone] = []
    start = first_start
    for title, due_text in rows:
        due = date.fromisoformat(due_text)
        milestones.append(Milestone(title=title, start=start, due=due))
        start = due + timedelta(days=1)
    return milestones


# GitHub


def resolve_token(env: Mapping[str, str] | None = None) -> str:
    """The GitHub token from the environment, or from ``gh auth token``.

    Raises:
        StatusReportError: No token is available.
    """
    env = os.environ if env is None else env
    for name in TOKEN_VARIABLES:
        value = env.get(name, "").strip()
        if value:
            return value
    gh = shutil.which("gh")
    if gh is not None:
        try:
            completed = subprocess.run(
                [gh, "auth", "token"], capture_output=True, text=True, check=False, timeout=15
            )
        except (OSError, subprocess.SubprocessError):
            completed = None
        if completed is not None and completed.returncode == 0 and completed.stdout.strip():
            return completed.stdout.strip()
    raise StatusReportError(
        f"no GitHub token: set {' or '.join(TOKEN_VARIABLES)}, or log in with `gh auth login`; "
        "use --replay FILE to work from a recorded response"
    )


def _graphql(query: str, variables: Mapping[str, Any], *, token: str) -> Mapping[str, Any]:
    """Send one GraphQL request to GitHub and return its ``data``.

    Raises:
        StatusReportError: The request failed, was refused or rate limited, or the answer is
            not what the API documents. The message never contains the token.
    """
    body = json.dumps({"query": query, "variables": dict(variables)}).encode("utf-8")
    request = urllib.request.Request(
        API_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
            "User-Agent": "codekavach-status-report",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        remaining = error.headers.get("X-RateLimit-Remaining") if error.headers else None
        raise StatusReportError(_http_message(error.code, remaining)) from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise StatusReportError(f"cannot reach the GitHub API: {type(error).__name__}") from None
    except ValueError:
        raise StatusReportError("the GitHub API did not answer with JSON") from None
    return _data_of(payload)


def _http_message(status: int, remaining: str | None) -> str:
    """What to tell the user about a refused request; ``remaining`` is the rate-limit header."""
    if status in {403, 429} and remaining == "0":
        return f"the GitHub API rate limit is used up (HTTP {status}); try again after the reset"
    if status in {401, 403}:
        return (
            f"the GitHub API refused the token (HTTP {status}); it needs read access to the "
            "repository and the project"
        )
    return f"the GitHub API answered with HTTP {status}"


def _data_of(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise StatusReportError("the GitHub API answer is not a JSON object")
    errors = payload.get("errors")
    if errors:
        kinds = sorted({str(e.get("type", "error")) for e in errors if isinstance(e, Mapping)})
        raise StatusReportError(f"the GitHub API reported errors: {', '.join(kinds) or 'error'}")
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise StatusReportError("the GitHub API answer has no data")
    return data


def live_graph(token: str) -> Graph:
    """A ``Graph`` that asks GitHub."""
    return lambda query, variables: _graphql(query, variables, token=token)


def replay_graph(path: Path) -> Graph:
    """A ``Graph`` that returns the recorded answers of ``path`` in order; it opens no connection.

    Raises:
        StatusReportError: The file cannot be read or is not a JSON list.
    """
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise StatusReportError(
            f"cannot read the recording {path}: {type(error).__name__}"
        ) from error
    if not isinstance(recorded, list):
        raise StatusReportError(f"the recording {path} is not a JSON list of answers")
    answers = iter(recorded)

    def graph(_query: str, _variables: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            return _data_of(next(answers))
        except StopIteration:
            raise StatusReportError(f"the recording {path} has no further answer") from None

    return graph


# items


@dataclass(frozen=True)
class Item:
    """One issue of the board."""

    number: int
    title: str
    created: date | None
    closed: date | None
    milestone: str | None
    labels: frozenset[str] = frozenset()
    fields: Mapping[str, str] = field(default_factory=dict)

    @property
    def is_epic(self) -> bool:
        """Whether this is the tracking issue of an epic."""
        return EPIC_LABEL in self.labels

    @property
    def size(self) -> str | None:
        """The Size of the board, or of the ``size:`` label when the board has none."""
        value = self.fields.get("Size")
        if value is not None:
            return value
        return next(
            (
                label.removeprefix(SIZE_LABEL_PREFIX)
                for label in sorted(self.labels)
                if label.startswith(SIZE_LABEL_PREFIX)
            ),
            None,
        )

    @property
    def points(self) -> int:
        """Points of the Size; 0 for an issue without Size or with a Size that has no value."""
        return POINTS.get(self.size or "", 0)

    @property
    def epic(self) -> str:
        """The Epic of the board, or the key in the title (``[E42-04]`` gives ``E42``)."""
        value = self.fields.get("Epic")
        if value is not None:
            return value
        match = re.match(r"\[(E\d+)", self.title)
        return match.group(1) if match else NO_EPIC

    def closed_by(self, day: date) -> bool:
        """Whether the issue was closed on or before ``day``."""
        return self.closed is not None and self.closed <= day

    def exists_on(self, day: date) -> bool:
        """Whether the issue had been created by the end of ``day``."""
        return self.created is None or self.created <= day


def _day(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).date()


def parse_item(node: Mapping[str, Any], board: Board) -> Item | None:
    """An ``Item`` from one node of the answer; ``None`` for a draft or a pull request."""
    content = node.get("content")
    if not isinstance(content, Mapping) or "number" not in content:
        return None
    values: dict[str, str] = {}
    for value in (node.get("fieldValues") or {}).get("nodes") or []:
        if not isinstance(value, Mapping):
            continue
        known = board.fields.get((value.get("field") or {}).get("id", ""))
        chosen = value.get("optionId") or value.get("iterationId")
        if known is not None and isinstance(chosen, str) and chosen in known[1]:
            values[known[0]] = known[1][chosen]
    labels = ((content.get("labels") or {}).get("nodes")) or []
    return Item(
        number=int(content["number"]),
        title=str(content.get("title", "")),
        created=_day(content.get("createdAt")),
        closed=_day(content.get("closedAt")),
        milestone=(content.get("milestone") or {}).get("title"),
        labels=frozenset(str(label["name"]) for label in labels if isinstance(label, Mapping)),
        fields=values,
    )


def fetch_items(graph: Graph, board: Board) -> list[Item]:
    """Every issue of the project, following the ``after`` cursors.

    Raises:
        StatusReportError: The answer does not have the documented shape.
    """
    items: list[Item] = []
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        data = graph(
            ITEMS_QUERY, {"projectId": board.project_id, "cursor": cursor, "pageSize": PAGE_SIZE}
        )
        try:
            page = data["node"]["items"]
            nodes, info = page["nodes"], page["pageInfo"]
        except (KeyError, TypeError):
            raise StatusReportError("the project was not found in the GitHub API answer") from None
        for node in nodes:
            item = parse_item(node, board) if isinstance(node, Mapping) else None
            if item is not None:
                items.append(item)
        if not info.get("hasNextPage"):
            return sorted(items, key=lambda item: item.number)
        cursor = info.get("endCursor")
    raise StatusReportError(f"the project has more than {MAX_PAGES * PAGE_SIZE} items")


# progress


def expected_percent(milestone: Milestone, on: date) -> float:
    """The share of a milestone expected to be closed on ``on``: linear from start to due date."""
    if on >= milestone.due:
        return 100.0
    if on < milestone.start:
        return 0.0
    span = (milestone.due - milestone.start).days + 1
    return 100.0 * ((on - milestone.start).days + 1) / span


def classify(percent: float, expected: float) -> str:
    """ON_TRACK at or above the expected progress, AT_RISK within the band below it."""
    if percent >= expected:
        return ON_TRACK
    if expected - percent <= AT_RISK_BAND:
        return AT_RISK
    return OFF_TRACK


@dataclass(frozen=True)
class MilestoneProgress:
    """Open and closed issues of a milestone on a day, and how that compares with the plan."""

    title: str
    due: date
    open: int
    closed: int
    state: str

    @property
    def percent(self) -> int:
        """Closed issues as a whole percentage of all issues of the milestone."""
        total = self.open + self.closed
        return round(100 * self.closed / total) if total else 0


def milestone_progress(
    items: Sequence[Item], milestones: Sequence[Milestone], on: date
) -> list[MilestoneProgress]:
    """One row per milestone of the plan, counting the issues that existed on ``on``."""
    rows = []
    for milestone in milestones:
        mine = [i for i in items if i.milestone == milestone.title and i.exists_on(on)]
        closed = sum(1 for item in mine if item.closed_by(on))
        percent = 100.0 * closed / len(mine) if mine else 0.0
        rows.append(
            MilestoneProgress(
                title=milestone.title,
                due=milestone.due,
                open=len(mine) - closed,
                closed=closed,
                state=classify(percent, expected_percent(milestone, on)),
            )
        )
    return rows


@dataclass(frozen=True)
class EpicProgress:
    """Open and closed work items of an epic on a day; the tracking issue is not counted."""

    epic: str
    open: int
    closed: int
    points_open: int
    points_closed: int


def epic_progress(items: Sequence[Item], on: date) -> list[EpicProgress]:
    """One row per epic, in name order."""
    grouped: dict[str, list[Item]] = {}
    for item in items:
        if not item.is_epic and item.exists_on(on):
            grouped.setdefault(item.epic, []).append(item)
    rows = []
    for epic in sorted(grouped):
        closed = [item for item in grouped[epic] if item.closed_by(on)]
        still_open = [item for item in grouped[epic] if not item.closed_by(on)]
        rows.append(
            EpicProgress(
                epic=epic,
                open=len(still_open),
                closed=len(closed),
                points_open=sum(item.points for item in still_open),
                points_closed=sum(item.points for item in closed),
            )
        )
    return rows


@dataclass(frozen=True)
class SprintMetrics:
    """What was closed in a sprint, and the mean of the sprints up to it."""

    issues_closed: int
    points_closed: int
    velocity: float


def _closed_in(items: Sequence[Item], sprint: Sprint) -> list[Item]:
    return [
        item
        for item in items
        if item.closed is not None and sprint.start <= item.closed <= sprint.end
    ]


def sprint_metrics(items: Sequence[Item], board: Board, sprint: Sprint) -> SprintMetrics:
    """Issues and points closed in ``sprint``; velocity is the mean points of sprints so far."""
    closed = _closed_in(items, sprint)
    so_far = [other for other in board.sprints if other.number <= sprint.number]
    totals = [sum(item.points for item in _closed_in(items, other)) for other in so_far]
    return SprintMetrics(
        issues_closed=len(closed),
        points_closed=sum(item.points for item in closed),
        velocity=sum(totals) / len(totals) if totals else 0.0,
    )


# the status update of the project (E42-05)


def overall_state(rows: Sequence[MilestoneProgress]) -> str:
    """The worst state among the milestones that are not complete; ON_TRACK when all are."""
    worst = ON_TRACK
    for row in rows:
        complete = row.open == 0 and row.closed > 0
        if not complete and SEVERITY.index(row.state) > SEVERITY.index(worst):
            worst = row.state
    return worst


def target_date(milestones: Sequence[Milestone], on: date) -> date:
    """The nearest milestone due date on or after ``on``; the last due date when all have passed."""
    upcoming = [milestone.due for milestone in milestones if milestone.due >= on]
    return min(upcoming) if upcoming else max(milestone.due for milestone in milestones)


def status_body(sprint: Sprint, state: str, rows: Sequence[MilestoneProgress]) -> str:
    """A headline and one line per milestone: counts and states only, no issue content.

    Raises:
        StatusReportError: The body is longer than ``BODY_LIMIT``.
    """
    lines = [
        f"{sprint.title} ({sprint.start.isoformat()} to {sprint.end.isoformat()}): {state}",
        "",
    ]
    lines += [
        f"- {row.title}: {row.closed} of {row.open + row.closed} closed ({row.percent}%), "
        f"due {row.due.isoformat()}, {row.state}"
        for row in rows
    ]
    body = "\n".join(lines)
    if len(body) > BODY_LIMIT:
        raise StatusReportError(
            f"the status update body has {len(body)} characters; limit {BODY_LIMIT}"
        )
    return body


def status_update_input(
    board: Board,
    sprint: Sprint,
    milestones: Sequence[Milestone],
    rows: Sequence[MilestoneProgress],
) -> dict[str, str]:
    """The ``input`` of ``createProjectV2StatusUpdate`` for the end of ``sprint``."""
    state = overall_state(rows)
    return {
        "projectId": board.project_id,
        "status": API_STATUS[state],
        "startDate": sprint.start.isoformat(),
        "targetDate": target_date(milestones, sprint.end).isoformat(),
        "body": status_body(sprint, state, rows),
    }


# charts (E42-06)


@dataclass(frozen=True)
class BurndownPoint:
    """Points of a milestone still open at the end of a day, next to the ideal line."""

    day: date
    remaining: int | None  # None for a day after the day the series was built on
    ideal: float


def burndown_series(
    items: Sequence[Item], milestone: Milestone, as_of: date
) -> list[BurndownPoint]:
    """One point per calendar day from the start of ``milestone`` to its due date.

    Every issue of the milestone counts with the points of its Size; an open issue counts on
    every day up to ``as_of``. The ideal line falls evenly from the total on the first day to
    zero on the due date.
    """
    mine = [item for item in items if item.milestone == milestone.title]
    total = sum(item.points for item in mine)
    days = (milestone.due - milestone.start).days
    series = []
    for offset in range(days + 1):
        day = milestone.start + timedelta(days=offset)
        remaining = sum(item.points for item in mine if not item.closed_by(day))
        ideal = total * (1 - offset / days) if days else 0.0
        series.append(
            BurndownPoint(day=day, remaining=remaining if day <= as_of else None, ideal=ideal)
        )
    return series


def velocity_series(items: Sequence[Item], board: Board) -> list[tuple[Sprint, int]]:
    """Points closed per sprint: an issue belongs to the sprint whose week holds its close date."""
    return [
        (sprint, sum(item.points for item in _closed_in(items, sprint))) for sprint in board.sprints
    ]


def burndown_csv(series: Sequence[BurndownPoint]) -> str:
    """``date,remaining_points,ideal_points``; remaining is empty for days that have not come."""
    lines = ["date,remaining_points,ideal_points"]
    lines += [
        f"{point.day.isoformat()},{'' if point.remaining is None else point.remaining},"
        f"{point.ideal:.1f}"
        for point in series
    ]
    return "\n".join(lines) + "\n"


def velocity_csv(series: Sequence[tuple[Sprint, int]]) -> str:
    """``sprint,start_date,points_closed``, one row per sprint of the board."""
    lines = ["sprint,start_date,points_closed"]
    lines += [f"{sprint.title},{sprint.start.isoformat()},{points}" for sprint, points in series]
    return "\n".join(lines) + "\n"


def milestone_key(title: str) -> str:
    """The short key used in file names: ``M1`` for ``M1 Privacy layer MVP + Demo 1``."""
    return title.split(" ", 1)[0]


def render_charts(
    milestone: Milestone,
    burndown: Sequence[BurndownPoint],
    velocity: Sequence[tuple[Sprint, int]],
    burndown_png: Path,
    velocity_png: Path,
) -> bool:
    """Write the two PNG charts; ``False`` when matplotlib is not installed.

    matplotlib is an optional tooling dependency and is imported here only. The figures have a
    fixed size and carry no software or time metadata.
    """
    try:
        matplotlib = importlib.import_module("matplotlib")
        matplotlib.use("Agg")
        pyplot = importlib.import_module("matplotlib.pyplot")
    except ImportError:
        return False
    metadata = {"Software": None}

    figure, axes = pyplot.subplots(figsize=CHART_SIZE, dpi=CHART_DPI)
    known = [point for point in burndown if point.remaining is not None]
    axes.plot([p.day for p in burndown], [p.ideal for p in burndown], "--", label="Ideal")
    axes.plot([p.day for p in known], [p.remaining for p in known], marker="o", label="Remaining")
    axes.set_title(f"Burndown: {milestone.title}")
    axes.set_xlabel("Date")
    axes.set_ylabel("Remaining points")
    axes.set_ylim(bottom=0)
    axes.legend()
    figure.autofmt_xdate()
    figure.savefig(burndown_png, metadata=metadata)
    pyplot.close(figure)

    figure, axes = pyplot.subplots(figsize=CHART_SIZE, dpi=CHART_DPI)
    axes.bar([str(sprint.number) for sprint, _ in velocity], [points for _, points in velocity])
    axes.set_title("Velocity: points closed per sprint")
    axes.set_xlabel("Sprint")
    axes.set_ylabel("Points closed")
    figure.savefig(velocity_png, metadata=metadata)
    pyplot.close(figure)
    return True


# the note


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.1f}"


def milestone_table(rows: Sequence[MilestoneProgress]) -> str:
    """The content of the ``milestone:auto`` region."""
    lines = [MILESTONE_HEADER, MILESTONE_RULE]
    lines += [
        f"| {row.title} | {row.due.isoformat()} | {row.open} | {row.closed} | {row.percent}% "
        f"| {row.state} |"
        for row in rows
    ]
    return "\n".join(lines)


def metrics_table(metrics: SprintMetrics) -> str:
    """The content of the ``metrics:auto`` region."""
    return "\n".join(
        [
            METRICS_HEADER,
            METRICS_RULE,
            f"| Issues closed in the sprint | {metrics.issues_closed} |",
            f"| Points closed in the sprint | {metrics.points_closed} |",
            f"| Velocity (mean points closed per sprint so far) | {_number(metrics.velocity)} |",
        ]
    )


def _replace_region(text: str, name: str, content: str) -> str:
    start, end = f"<!-- {name}:auto-start -->", f"<!-- {name}:auto-end -->"
    if text.count(start) != 1 or text.count(end) != 1 or text.index(start) > text.index(end):
        raise StatusReportError(f"the template has no single '{name}:auto' region")
    head, rest = text.split(start, 1)
    _, tail = rest.split(end, 1)
    return f"{head}{start}\n{content}\n{end}{tail}"


def _replace_line(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise StatusReportError(f"the template does not have exactly one line '{old.strip()}'")
    return text.replace(old, new)


def render_note(
    template: str,
    sprint: Sprint,
    rows: Sequence[MilestoneProgress],
    metrics: SprintMetrics,
    written_on: date,
) -> str:
    """The template with its two regions and the facts of the Sprint table filled in.

    The usage comment at the top of the template is dropped; everything else is kept.

    Raises:
        StatusReportError: The template no longer has the regions or lines of E42-03.
    """
    text = template
    if text.startswith("<!--"):
        text = text.split("-->", 1)[1].lstrip("\n")
    text = _replace_region(text, "milestone", milestone_table(rows))
    text = _replace_region(text, "metrics", metrics_table(metrics))
    text = _replace_line(
        text, "# Status note: Sprint NN\n", f"# Status note: Sprint {sprint.number:02d}\n"
    )
    text = _replace_line(text, "| Sprint | Sprint NN |\n", f"| Sprint | {sprint.title} |\n")
    text = _replace_line(
        text,
        "| Dates | YYYY-MM-DD (Monday) to YYYY-MM-DD (Sunday) |\n",
        f"| Dates | {sprint.start.isoformat()} (Monday) to {sprint.end.isoformat()} (Sunday) |\n",
    )
    return _replace_line(
        text, "| Written on | YYYY-MM-DD |\n", f"| Written on | {written_on.isoformat()} |\n"
    )


def note_path(sprint: Sprint) -> Path:
    """Where the note of ``sprint`` belongs: ``docs/status/YYYY-MM-DD-sprint-NN.md``."""
    return STATUS_DIR / f"{sprint.end.isoformat()}-sprint-{sprint.number:02d}.md"


# commands


def _graph_for(arguments: argparse.Namespace) -> Graph:
    if arguments.replay is not None:
        return replay_graph(Path(arguments.replay))
    return live_graph(resolve_token())


def _today() -> date:
    return datetime.now(UTC).date()


def run_fetch(arguments: argparse.Namespace) -> int:
    """Print milestone and epic progress as JSON."""
    board = load_board()
    on = board.sprint(arguments.sprint).end if arguments.sprint is not None else _today()
    items = fetch_items(_graph_for(arguments), board)
    milestones = load_milestones(board.sprints[0].start)
    statuses: dict[str, int] = {}
    for item in items:
        status = item.fields.get("Status", "(none)")
        statuses[status] = statuses.get(status, 0) + 1
    report = {
        "as_of": on.isoformat(),
        "issues": len(items),
        "status": dict(sorted(statuses.items())),
        "milestones": [
            {
                "milestone": row.title,
                "due": row.due.isoformat(),
                "open": row.open,
                "closed": row.closed,
                "percent": row.percent,
                "state": row.state,
            }
            for row in milestone_progress(items, milestones, on)
        ],
        "epics": [
            {
                "epic": row.epic,
                "open": row.open,
                "closed": row.closed,
                "points_open": row.points_open,
                "points_closed": row.points_closed,
            }
            for row in epic_progress(items, on)
        ],
    }
    print(json.dumps(report, indent=2))
    return 0


def run_draft(arguments: argparse.Namespace) -> int:
    """Write the drafted note of a sprint to stdout or to a file."""
    board = load_board()
    sprint = board.sprint(arguments.sprint)
    destination = Path(arguments.out) if arguments.out is not None else note_path(sprint)
    if not arguments.stdout and destination.exists() and not arguments.force:
        raise StatusReportError(
            f"{destination} exists; pass --force to replace it, or --stdout or --out PATH"
        )
    try:
        template = TEMPLATE_FILE.read_text(encoding="utf-8")
    except OSError as error:
        raise StatusReportError(f"cannot read {TEMPLATE_FILE}: {type(error).__name__}") from error
    items = fetch_items(_graph_for(arguments), board)
    milestones = load_milestones(board.sprints[0].start)
    note = render_note(
        template,
        sprint,
        milestone_progress(items, milestones, sprint.end),
        sprint_metrics(items, board, sprint),
        _today(),
    )
    if arguments.stdout:
        sys.stdout.write(note)
        return 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(note.encode("utf-8"))
    print(f"wrote {destination}")
    return 0


def run_post_status(arguments: argparse.Namespace) -> int:
    """Print the status update of a sprint; send it only with ``--post``."""
    board = load_board()
    sprint = board.sprint(arguments.sprint)
    # Resolved before anything else: --post without a token stops here, before any request.
    token = resolve_token() if arguments.post else None
    if arguments.replay is not None:
        graph = replay_graph(Path(arguments.replay))
    else:
        graph = live_graph(token if token is not None else resolve_token())
    items = fetch_items(graph, board)
    milestones = load_milestones(board.sprints[0].start)
    variables = {
        "input": status_update_input(
            board, sprint, milestones, milestone_progress(items, milestones, sprint.end)
        )
    }
    print(f"status={variables['input']['status']} targetDate={variables['input']['targetDate']}")
    print(STATUS_UPDATE_MUTATION.strip())
    print(json.dumps(variables, indent=2))
    if token is None:
        print("dry run: nothing was posted; pass --post to send this status update")
        return 0
    answer = _graphql(STATUS_UPDATE_MUTATION, variables, token=token)
    update = (answer.get("createProjectV2StatusUpdate") or {}).get("statusUpdate") or {}
    if not update.get("id"):
        raise StatusReportError("the GitHub API did not confirm the status update")
    print("posted the status update")
    return 0


def run_charts(arguments: argparse.Namespace) -> int:
    """Write the burndown of a milestone and the velocity per sprint: CSV, and PNG if possible."""
    board = load_board()
    milestones = load_milestones(board.sprints[0].start)
    milestone = next((m for m in milestones if m.title == arguments.milestone), None)
    if milestone is None:
        known = "; ".join(m.title for m in milestones)
        raise StatusReportError(f"no milestone '{arguments.milestone}' in the plan; known: {known}")
    try:
        as_of = date.fromisoformat(arguments.as_of) if arguments.as_of is not None else _today()
    except ValueError:
        raise StatusReportError(
            f"--as-of needs a date as YYYY-MM-DD, got '{arguments.as_of}'"
        ) from None
    items = fetch_items(_graph_for(arguments), board)
    burndown = burndown_series(items, milestone, as_of)
    velocity = velocity_series(items, board)
    directory = Path(arguments.out_dir) if arguments.out_dir is not None else CHARTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    burndown_base = directory / f"burndown-{milestone_key(milestone.title)}"
    velocity_base = directory / "velocity"
    burndown_base.with_suffix(".csv").write_bytes(burndown_csv(burndown).encode("utf-8"))
    velocity_base.with_suffix(".csv").write_bytes(velocity_csv(velocity).encode("utf-8"))
    print(f"wrote {burndown_base.with_suffix('.csv')}")
    print(f"wrote {velocity_base.with_suffix('.csv')}")
    drawn = render_charts(
        milestone,
        burndown,
        velocity,
        burndown_base.with_suffix(".png"),
        velocity_base.with_suffix(".png"),
    )
    if drawn:
        print(f"wrote {burndown_base.with_suffix('.png')}")
        print(f"wrote {velocity_base.with_suffix('.png')}")
    else:
        print(
            "matplotlib is not installed: wrote the CSV files only "
            "(see docs/process/sprint-cadence.md)"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """The command line of the tool."""
    parser = argparse.ArgumentParser(
        prog="status_report.py",
        description="Fetch the progress of the project board and draft the weekly status note.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("fetch", help="print milestone and epic progress as JSON")
    fetch.add_argument(
        "--sprint", type=int, help="count as of the end of this sprint (default: today)"
    )
    fetch.set_defaults(run=run_fetch)
    draft = commands.add_parser("draft", help="draft the status note of a sprint")
    draft.add_argument("--sprint", type=int, required=True, help="sprint number")
    target = draft.add_mutually_exclusive_group()
    target.add_argument(
        "--stdout", action="store_true", help="print the note instead of writing it"
    )
    target.add_argument("--out", metavar="PATH", help="write the note to PATH")
    draft.add_argument("--force", action="store_true", help="replace an existing note")
    draft.set_defaults(run=run_draft)
    post = commands.add_parser(
        "post-status", help="print the project status update of a sprint; send it with --post"
    )
    post.add_argument("--sprint", type=int, required=True, help="sprint number")
    mode = post.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run", action="store_true", help="print the update and send nothing (the default)"
    )
    mode.add_argument("--post", action="store_true", help="send the update to the project")
    post.set_defaults(run=run_post_status)
    charts = commands.add_parser(
        "charts", help="write the burndown of a milestone and the velocity per sprint"
    )
    charts.add_argument("--milestone", required=True, help="milestone title as in docs/PLAN.md")
    charts.add_argument("--as-of", metavar="DATE", help="last day with known data (default: today)")
    charts.add_argument(
        "--out-dir", metavar="DIR", help="where to write (default: docs/status/charts)"
    )
    charts.set_defaults(run=run_charts)
    for command in (fetch, draft, post, charts):
        command.add_argument(
            "--replay",
            metavar="FILE",
            help="answer from a recorded response instead of the GitHub API (no token, no network)",
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the tool; 0 on success, 1 on a reported problem (argparse exits 2 on usage errors)."""
    arguments = build_parser().parse_args(argv)
    try:
        status: int = arguments.run(arguments)
    except StatusReportError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
