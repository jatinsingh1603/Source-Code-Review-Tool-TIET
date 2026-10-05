"""``tools/status_report.py post-status``: the overall state and the project status update."""

import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from tests.process._tool import FIXTURES, RECORDING, REPO, SCRIPT
from tests.process._tool import status_report as tool
from tests.support.golden import assert_matches_golden
from tests.support.no_network import refuse_network

GOLDEN = FIXTURES / "expected_post_status_sprint01.txt"
TOKEN_VARIABLES = ("GITHUB_TOKEN", "GH_TOKEN")
PLANTED = "planted-value-for-the-leak-test"
DUE = date(2026, 10, 5)


def row(state: str, *, open_: int = 1, closed: int = 1, title: str = "M") -> Any:
    return tool.MilestoneProgress(title=title, due=DUE, open=open_, closed=closed, state=state)


@pytest.fixture
def no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in TOKEN_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tool.shutil, "which", lambda _name: None)


# the overall state


@pytest.mark.parametrize(
    ("states", "expected"),
    [
        (["ON_TRACK", "ON_TRACK"], "ON_TRACK"),
        (["ON_TRACK", "AT_RISK", "ON_TRACK"], "AT_RISK"),
        (["AT_RISK", "OFF_TRACK", "ON_TRACK"], "OFF_TRACK"),
        (["OFF_TRACK", "AT_RISK"], "OFF_TRACK"),
        (["AT_RISK", "AT_RISK"], "AT_RISK"),
        ([], "ON_TRACK"),
    ],
)
def test_overall_state_is_the_worst_milestone_state(states: list[str], expected: str) -> None:
    assert tool.overall_state([row(state) for state in states]) == expected


def test_complete_milestones_do_not_count() -> None:
    complete_but_late = row("OFF_TRACK", open_=0, closed=7)
    assert tool.overall_state([complete_but_late, row("ON_TRACK")]) == "ON_TRACK"
    assert tool.overall_state([complete_but_late, row("AT_RISK")]) == "AT_RISK"
    assert tool.overall_state([complete_but_late]) == "ON_TRACK"
    empty_and_late = row("OFF_TRACK", open_=0, closed=0)  # no issues yet: not complete
    assert tool.overall_state([empty_and_late, row("ON_TRACK")]) == "OFF_TRACK"


def test_internal_states_map_onto_the_api_enum() -> None:
    assert dict(tool.API_STATUS) == {
        "ON_TRACK": "ON_TRACK",
        "AT_RISK": "AT_RISK",
        "OFF_TRACK": "OFF_TRACK",
    }
    assert set(tool.API_STATUS) == set(tool.SEVERITY)
    assert "COMPLETE" not in tool.API_STATUS.values()
    assert "INACTIVE" not in tool.API_STATUS.values()


def test_target_date_is_the_nearest_upcoming_due_date() -> None:
    milestones = tool.load_milestones(date(2026, 9, 21))
    assert tool.target_date(milestones, date(2026, 9, 27)) == date(2026, 9, 27)
    assert tool.target_date(milestones, date(2026, 10, 4)) == date(2026, 10, 5)
    assert tool.target_date(milestones, date(2026, 10, 11)) == date(2026, 10, 26)
    assert tool.target_date(milestones, date(2027, 1, 1)) == date(2026, 12, 21)


def test_body_has_a_headline_and_one_line_per_milestone() -> None:
    sprint = tool.Sprint(2, "Sprint 2", date(2026, 9, 28))
    rows = [row("OFF_TRACK", open_=3, closed=5, title="M0 Foundations"), row("ON_TRACK")]
    body = tool.status_body(sprint, "OFF_TRACK", rows)
    assert body.splitlines() == [
        "Sprint 2 (2026-09-28 to 2026-10-04): OFF_TRACK",
        "",
        "- M0 Foundations: 5 of 8 closed (62%), due 2026-10-05, OFF_TRACK",
        "- M: 1 of 2 closed (50%), due 2026-10-05, ON_TRACK",
    ]
    assert body.isascii()
    with pytest.raises(tool.StatusReportError, match="limit 1500"):
        tool.status_body(sprint, "ON_TRACK", [row("ON_TRACK", title="M" * 200)] * 9)


# the command


def test_dry_run_is_the_default_and_prints_the_exact_payload(
    no_token: None, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[Any] = []
    monkeypatch.setattr(tool, "_graphql", lambda *args, **kwargs: sent.append((args, kwargs)))
    with refuse_network() as network:
        code = tool.main(["post-status", "--sprint", "1", "--replay", str(RECORDING)])
    captured = capsys.readouterr()
    assert (code, captured.err) == (0, "")
    assert network.attempts == []
    assert sent == []
    lines = captured.out.splitlines()
    assert lines[0] == "status=OFF_TRACK targetDate=2026-09-27"
    assert lines[-1] == "dry run: nothing was posted; pass --post to send this status update"
    assert "createProjectV2StatusUpdate(input: $input)" in captured.out
    variables = json.loads(captured.out.split("}\n}\n", 1)[1].rsplit("\ndry run", 1)[0])
    assert variables["input"] == {
        "projectId": tool.load_board().project_id,
        "status": "OFF_TRACK",
        "startDate": "2026-09-21",
        "targetDate": "2026-09-27",
        "body": variables["input"]["body"],
    }
    assert variables["input"]["body"].startswith("Sprint 1 (2026-09-21 to 2026-09-27): OFF_TRACK")
    assert (
        "- M0 Foundations: 4 of 7 closed (57%), due 2026-09-27, OFF_TRACK"
        in (variables["input"]["body"])
    )
    project_id = tool.load_board().project_id
    assert_matches_golden(captured.out.replace(project_id, "<project id>"), GOLDEN)
    assert tool.main(["post-status", "--sprint", "1", "--dry-run", "--replay", str(RECORDING)]) == 0
    assert capsys.readouterr().out == captured.out


def test_sprint_2_targets_the_next_milestone(
    no_token: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert tool.main(["post-status", "--sprint", "2", "--replay", str(RECORDING)]) == 0
    assert capsys.readouterr().out.startswith("status=OFF_TRACK targetDate=2026-10-05\n")


def test_post_without_a_token_stops_before_anything_is_sent(
    no_token: None, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[Any] = []
    monkeypatch.setattr(tool, "_graphql", lambda *args, **kwargs: sent.append((args, kwargs)))
    with refuse_network() as network:
        code = tool.main(["post-status", "--sprint", "1", "--post", "--replay", str(RECORDING)])
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "no GitHub token: set GITHUB_TOKEN or GH_TOKEN" in captured.err
    assert sent == []
    assert network.attempts == []


def test_post_without_a_token_exits_non_zero_as_a_process() -> None:
    env = {key: value for key, value in os.environ.items() if key not in TOKEN_VARIABLES}
    env["PATH"] = str(Path(sys.executable).parent)  # no gh on the path: no token from the CLI
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "post-status", "--sprint", "1", "--post", "--replay",
         str(RECORDING)],
        cwd=REPO, env=env, capture_output=True, text=True, encoding="utf-8", check=False,
    )  # fmt: skip
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "no GitHub token" in completed.stderr


def test_post_sends_one_mutation_with_the_printed_variables(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[Any] = []

    def graphql(query: str, variables: Any, *, token: str) -> Any:
        sent.append((query, variables, token))
        return {"createProjectV2StatusUpdate": {"statusUpdate": {"id": "update-1"}}}

    monkeypatch.setenv("GITHUB_TOKEN", PLANTED)
    monkeypatch.setattr(tool, "_graphql", graphql)
    assert tool.main(["post-status", "--sprint", "1", "--post", "--replay", str(RECORDING)]) == 0
    captured = capsys.readouterr()
    ((query, variables, token),) = sent
    assert query == tool.STATUS_UPDATE_MUTATION
    assert token == PLANTED
    assert variables["input"]["status"] == "OFF_TRACK"
    assert json.dumps(variables, indent=2) in captured.out
    assert captured.out.splitlines()[-1] == "posted the status update"
    assert PLANTED not in captured.out + captured.err
    assert "dry run" not in captured.out

    monkeypatch.setattr(tool, "_graphql", lambda *args, **kwargs: {})
    assert tool.main(["post-status", "--sprint", "1", "--post", "--replay", str(RECORDING)]) == 1
    assert "did not confirm the status update" in capsys.readouterr().err


def test_dry_run_and_post_exclude_each_other(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as usage:
        tool.main(["post-status", "--sprint", "1", "--dry-run", "--post"])
    assert usage.value.code == 2
    capsys.readouterr()


def test_sprint_guide_documents_the_command_and_the_token_scope() -> None:
    guide = (REPO / "docs" / "process" / "sprint-cadence.md").read_text(encoding="utf-8")
    for phrase in (
        "python tools/status_report.py post-status --sprint 2",
        "post-status --sprint 2 --post",
        "a classic token with the `project` scope",
        "a fine-grained token with read and write access to Projects",
        "is a dry run",
    ):
        assert phrase in guide, phrase
