"""``tools/status_report.py`` ``draft`` and ``fetch`` against a recorded synthetic board."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.process._tool import FIXTURES, RECORDING, REPO, SCRIPT
from tests.process._tool import status_report as tool
from tests.process.test_status_note_format import check_format
from tests.support.golden import assert_matches_golden
from tests.support.no_network import refuse_network

GOLDEN = FIXTURES / "expected_sprint01_note.md"
GENERATED = "| Written on |"
TOKEN_VARIABLES = ("GITHUB_TOKEN", "GH_TOKEN")


def without_generation_date(note: str) -> str:
    """The note without the one line that holds the day it was generated."""
    lines = note.splitlines(keepends=True)
    assert sum(line.startswith(GENERATED) for line in lines) == 1
    return "".join(line for line in lines if not line.startswith(GENERATED))


@pytest.fixture
def no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in TOKEN_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tool.shutil, "which", lambda _name: None)


def test_draft_from_the_recording_matches_the_golden_note(
    no_token: None, capsys: pytest.CaptureFixture[str]
) -> None:
    with refuse_network() as network:
        code = tool.main(["draft", "--sprint", "1", "--stdout", "--replay", str(RECORDING)])
    captured = capsys.readouterr()
    assert (code, captured.err) == (0, "")
    assert network.attempts == []
    note = captured.out
    check_format(note)
    assert "| Sprint | Sprint 1 |" in note
    assert "| Dates | 2026-09-21 (Monday) to 2026-09-27 (Sunday) |" in note
    assert "<!--\n" not in note
    assert "| M0 Foundations | 2026-09-27 | 3 | 4 | 57% | OFF_TRACK |" in note
    assert "| Issues closed in the sprint | 5 |" in note
    assert "| Points closed in the sprint | 12 |" in note
    assert_matches_golden(without_generation_date(note), GOLDEN)


def test_prose_of_the_template_is_left_as_it_is(
    no_token: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert tool.main(["draft", "--sprint", "2", "--stdout", "--replay", str(RECORDING)]) == 0
    note = capsys.readouterr().out
    template = tool.TEMPLATE_FILE.read_text(encoding="utf-8")
    for heading in (
        "## Highlights",
        "## Risks and blockers",
        "## Next sprint",
        "## Overall status",
    ):
        ours = note.split(heading, 1)[1].split("\n## ", 1)[0]
        theirs = template.split(heading, 1)[1].split("\n## ", 1)[0]
        assert ours == theirs, heading
    assert "| Sprint | Sprint 2 |" in note
    assert "| M0 Foundations | 2026-09-27 | 3 | 5 | 62% | OFF_TRACK |" in note
    assert "| Issues closed in the sprint | 1 |" in note
    assert "| Velocity (mean points closed per sprint so far) | 10 |" in note


def test_the_documented_command_runs_without_token_or_network() -> None:
    env = {key: value for key, value in os.environ.items() if key not in TOKEN_VARIABLES}
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "draft", "--sprint", "1", "--stdout", "--replay",
         str(RECORDING.relative_to(REPO))],
        cwd=REPO, env=env, capture_output=True, text=True, encoding="utf-8", check=False,
    )  # fmt: skip
    assert completed.returncode == 0, completed.stderr
    check_format(completed.stdout)
    assert without_generation_date(completed.stdout) == GOLDEN.read_text(encoding="utf-8")


def test_missing_token_exits_non_zero_and_names_the_variables(
    no_token: None, capsys: pytest.CaptureFixture[str]
) -> None:
    with refuse_network() as network:
        code = tool.main(["draft", "--sprint", "1", "--stdout"])
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err.startswith("error: no GitHub token: set GITHUB_TOKEN or GH_TOKEN")
    assert "--replay" in captured.err
    assert network.attempts == []
    assert tool.main(["fetch"]) == 1


def test_draft_writes_the_note_and_does_not_replace_one(
    no_token: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "notes" / "note.md"
    arguments = ["draft", "--sprint", "1", "--replay", str(RECORDING), "--out", str(target)]
    assert tool.main(arguments) == 0
    check_format(target.read_text(encoding="utf-8"))
    assert b"\r\n" not in target.read_bytes()
    target.write_text("edited by hand\n", encoding="utf-8")
    capsys.readouterr()
    assert tool.main(arguments) == 1
    assert "exists; pass --force" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == "edited by hand\n"
    assert tool.main([*arguments, "--force"]) == 0
    check_format(target.read_text(encoding="utf-8"))


def test_default_path_follows_the_naming_convention(
    no_token: None, capsys: pytest.CaptureFixture[str]
) -> None:
    board = tool.load_board()
    assert tool.note_path(board.sprint(1)) == tool.STATUS_DIR / "2026-09-27-sprint-01.md"
    assert tool.note_path(board.sprint(13)).name == "2026-12-20-sprint-13.md"
    # The note of Sprint 1 was written by hand; its path is not replaced without --force.
    assert tool.main(["draft", "--sprint", "1", "--replay", str(RECORDING)]) == 1
    assert "pass --force" in capsys.readouterr().err


def test_fetch_prints_milestones_and_epics(
    no_token: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert tool.main(["fetch", "--sprint", "1", "--replay", str(RECORDING)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["as_of"] == "2026-09-27"
    assert report["issues"] == 12
    assert report["milestones"][0] == {
        "milestone": "M0 Foundations",
        "due": "2026-09-27",
        "open": 3,
        "closed": 4,
        "percent": 57,
        "state": "OFF_TRACK",
    }
    assert len(report["milestones"]) == 9
    epics = {row["epic"]: row for row in report["epics"]}
    assert epics["E01"] == {
        "epic": "E01", "open": 0, "closed": 2, "points_open": 0, "points_closed": 7,
    }  # fmt: skip
    assert epics["E02"]["points_open"] == 8
    assert epics["E06"]["points_open"] == 5  # the XL issue has no point value


def test_usage_and_template_errors(
    no_token: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replay = ["--replay", str(RECORDING)]
    assert tool.main(["draft", "--sprint", "99", "--stdout", *replay]) == 1
    assert "no Sprint 99" in capsys.readouterr().err
    with pytest.raises(SystemExit) as usage:
        tool.main(["draft", "--stdout", *replay])
    assert usage.value.code == 2
    capsys.readouterr()
    missing = tmp_path / "missing.json"
    assert tool.main(["fetch", "--replay", str(missing)]) == 1
    assert "cannot read the recording" in capsys.readouterr().err
    broken = tmp_path / "TEMPLATE.md"
    broken.write_text("# Status note: Sprint NN\n\n## Sprint\n", encoding="utf-8")
    monkeypatch.setattr(tool, "TEMPLATE_FILE", broken)
    assert tool.main(["draft", "--sprint", "1", "--stdout", *replay]) == 1
    assert "no single 'milestone:auto' region" in capsys.readouterr().err
