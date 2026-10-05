"""``tools/status_report.py charts``: the burndown of a milestone and the velocity per sprint."""

from datetime import date
from pathlib import Path
from typing import Any

import pytest

from tests.process._tool import FIXTURES, RECORDING, REPO
from tests.process._tool import status_report as tool
from tests.support.golden import assert_matches_golden
from tests.support.no_network import refuse_network

M0 = tool.Milestone("M0 Foundations", date(2026, 9, 21), date(2026, 9, 27))
BOARD = tool.Board(
    project_id="project-1",
    fields={},
    sprints=[
        tool.Sprint(1, "Sprint 1", date(2026, 9, 21)),
        tool.Sprint(2, "Sprint 2", date(2026, 9, 28)),
        tool.Sprint(3, "Sprint 3", date(2026, 10, 5)),
    ],
)
ARGUMENTS = ["charts", "--milestone", M0.title, "--as-of", "2026-10-05", "--replay", str(RECORDING)]


def item(number: int, size: str | None, closed: date | None = None, **changes: Any) -> Any:
    values: dict[str, Any] = {
        "number": number,
        "title": f"[E01-{number:02d}] infra: item {number}",
        "created": date(2026, 9, 20),
        "closed": closed,
        "milestone": M0.title,
        "labels": frozenset({f"size:{size}"} if size else set()),
    }
    values.update(changes)
    return tool.Item(**values)


@pytest.fixture
def no_matplotlib(monkeypatch: pytest.MonkeyPatch) -> None:
    real = tool.importlib.import_module

    def import_module(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.split(".", maxsplit=1)[0] == "matplotlib":
            raise ImportError("No module named 'matplotlib'")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(tool.importlib, "import_module", import_module)


@pytest.fixture
def no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tool.shutil, "which", lambda _name: None)


# series


def test_burndown_of_a_small_issue_set() -> None:
    items = [
        item(1, "M", date(2026, 9, 21)),  # closed on the first day
        item(2, "S", date(2026, 9, 24)),
        item(3, "L", date(2026, 9, 27)),  # closed on the due date
        item(4, "XS"),  # open
        item(5, "M", date(2026, 9, 30)),  # closed after the due date
        item(6, None, date(2026, 9, 22)),  # no Size: no points
        item(7, "L", date(2026, 9, 22), milestone="M1 Privacy layer MVP + Demo 1"),
    ]
    series = tool.burndown_series(items, M0, date(2026, 10, 5))
    assert [point.day for point in series] == [date(2026, 9, day) for day in range(21, 28)]
    assert [point.remaining for point in series] == [16, 16, 16, 14, 14, 14, 6]
    assert [round(point.ideal, 1) for point in series] == [21.0, 17.5, 14.0, 10.5, 7.0, 3.5, 0.0]


def test_days_after_the_as_of_date_have_no_remaining_value() -> None:
    items = [item(1, "M", date(2026, 9, 22)), item(2, "S")]
    series = tool.burndown_series(items, M0, date(2026, 9, 23))
    assert [point.remaining for point in series] == [7, 2, 2, None, None, None, None]
    assert series[-1].ideal == 0.0
    text = tool.burndown_csv(series)
    assert text.splitlines()[:5] == [
        "date,remaining_points,ideal_points",
        "2026-09-21,7,7.0",
        "2026-09-22,2,5.8",
        "2026-09-23,2,4.7",
        "2026-09-24,,3.5",
    ]
    assert text.endswith("2026-09-27,,0.0\n")


def test_milestone_without_points_gives_a_flat_valid_series() -> None:
    series = tool.burndown_series([item(1, None)], M0, date(2026, 10, 5))
    assert [(point.remaining, point.ideal) for point in series] == [(0, 0.0)] * 7
    lines = tool.burndown_csv(series).splitlines()
    assert lines[0] == "date,remaining_points,ideal_points"
    assert lines[1:] == [f"2026-09-{day},0,0.0" for day in range(21, 28)]
    assert tool.burndown_series([], M0, date(2026, 10, 5))[0].remaining == 0


def test_velocity_buckets_by_the_week_of_the_close_date() -> None:
    items = [
        item(1, "M", date(2026, 9, 21)),  # exactly on the start of Sprint 1
        item(2, "S", date(2026, 9, 27)),  # last day of Sprint 1
        item(3, "L", date(2026, 9, 28)),  # exactly on the start of Sprint 2
        item(4, "XS", date(2026, 10, 4)),
        item(5, "M", date(2026, 9, 20)),  # before the first sprint: in no bucket
        item(6, "M"),  # open
        item(7, "XL", date(2026, 10, 5)),  # XL has no point value
    ]
    series = tool.velocity_series(items, BOARD)
    assert [(sprint.number, points) for sprint, points in series] == [(1, 7), (2, 9), (3, 0)]
    assert tool.velocity_csv(series) == (
        "sprint,start_date,points_closed\n"
        "Sprint 1,2026-09-21,7\n"
        "Sprint 2,2026-09-28,9\n"
        "Sprint 3,2026-10-05,0\n"
    )


def test_file_name_key() -> None:
    assert tool.milestone_key("M1 Privacy layer MVP + Demo 1") == "M1"
    assert tool.milestone_key("M0 Foundations") == "M0"
    assert tool.CHARTS_DIR == tool.STATUS_DIR / "charts"


# the command


def test_charts_writes_the_csv_files_without_matplotlib(
    no_token: None, no_matplotlib: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with refuse_network() as network:
        code = tool.main([*ARGUMENTS, "--out-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert (code, captured.err) == (0, "")
    assert network.attempts == []
    assert sorted(path.name for path in tmp_path.iterdir()) == ["burndown-M0.csv", "velocity.csv"]
    assert "matplotlib is not installed: wrote the CSV files only" in captured.out
    burndown = (tmp_path / "burndown-M0.csv").read_bytes()
    velocity = (tmp_path / "velocity.csv").read_bytes()
    assert b"\r" not in burndown + velocity
    assert_matches_golden(burndown, FIXTURES / "expected_burndown_M0.csv")
    assert_matches_golden(velocity, FIXTURES / "expected_velocity.csv")
    assert burndown.decode().splitlines()[1] == "2026-09-21,23,23.0"
    assert burndown.decode().splitlines()[-1] == "2026-09-27,11,0.0"
    assert len(velocity.decode().splitlines()) == 14  # the header and thirteen sprints


def test_charts_writes_the_png_files_when_matplotlib_is_installed(
    no_token: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("matplotlib", reason="matplotlib is an optional tooling dependency")
    assert tool.main([*ARGUMENTS, "--out-dir", str(tmp_path)]) == 0
    names = sorted(path.name for path in tmp_path.iterdir())
    assert names == ["burndown-M0.csv", "burndown-M0.png", "velocity.csv", "velocity.png"]
    for name in ("burndown-M0.png", "velocity.png"):
        data = (tmp_path / name).read_bytes()
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
        assert b"Software" not in data
    assert "matplotlib is not installed" not in capsys.readouterr().out


def test_unknown_milestone_and_bad_date_are_reported(
    no_token: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    replay = ["--replay", str(RECORDING), "--out-dir", str(tmp_path)]
    assert tool.main(["charts", "--milestone", "M9 Nothing", *replay]) == 1
    assert "no milestone 'M9 Nothing' in the plan; known: M0 Foundations" in capsys.readouterr().err
    assert tool.main(["charts", "--milestone", M0.title, "--as-of", "today", *replay]) == 1
    assert "--as-of needs a date as YYYY-MM-DD" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_documentation_and_resource_record() -> None:
    guide = (REPO / "docs" / "process" / "sprint-cadence.md").read_text(encoding="utf-8")
    for phrase in (
        'python tools/status_report.py charts --milestone "M1 Privacy layer MVP + Demo 1"',
        "`burndown-M1.csv` and `velocity.csv`",
        "uv run --with matplotlib",
    ):
        assert phrase in guide, phrase
    resources = (REPO / "RESOURCE.md").read_text(encoding="utf-8")
    assert "optional tooling dependency of `tools/status_report.py charts`" in resources
    lock = (REPO / "uv.lock").read_text(encoding="utf-8")
    assert 'name = "matplotlib"' not in lock
