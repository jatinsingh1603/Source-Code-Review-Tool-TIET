"""The ingest flags of ``codekavach scan`` and how they reach the pipeline (E06-03)."""

from collections.abc import Callable
from pathlib import Path

import pytest

from codekavach.cli.errors import UsageError
from codekavach.cli.scan import check_target, ingest_options_from_flags
from tests.support.cli import CliResult
from tests.support.scan_stub import install_stub

Cli = Callable[..., CliResult]


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def flags(**given: object) -> dict[str, object]:
    base: dict[str, object] = {
        "target": ".",
        "ref": None,
        "depth": 1,
        "git_credential": None,
        "stdin_filename": None,
        "diff_since": None,
        "include_deleted": False,
        "subprojects": (),
    }
    base.update(given)
    return ingest_options_from_flags(**base)  # type: ignore[arg-type]


def test_no_flags_give_an_empty_mapping() -> None:
    assert flags() == {}


def test_every_flag_is_carried_when_given() -> None:
    assert flags(
        ref="v1",
        depth=3,
        git_credential="env:T",
        diff_since="main",
        include_deleted=True,
        subprojects=("a", "b"),
    ) == {
        "ref": "v1",
        "depth": 3,
        "git_credential": "env:T",
        "diff_since": "main",
        "include_deleted": True,
        "subprojects": ["a", "b"],
    }


@pytest.mark.parametrize(
    "bad",
    [
        {"ref": "--evil"},
        {"subprojects": ("../up",)},
        {"target": "-"},
        {"target": "-", "stdin_filename": "a/b.py"},
        {"stdin_filename": "a.py"},
    ],
)
def test_a_bad_flag_is_a_usage_error(bad: dict[str, object]) -> None:
    with pytest.raises(UsageError) as raised:
        flags(**bad)
    assert raised.value.code in {"ingest_option_invalid", "stdin_misuse"}


def test_a_stdin_target_with_a_filename_is_accepted() -> None:
    assert flags(target="-", stdin_filename="hook.py") == {"stdin_filename": "hook.py"}


@pytest.mark.parametrize(
    "url",
    ["file:///srv/r.git", "https://h/r", "git@h:r.git", "ssh://h/r", "/srv/missing/repo.git", "-"],
)
def test_remote_and_stdin_targets_have_no_local_path(url: str) -> None:
    assert check_target(url) is None


def test_the_flags_reach_the_pipeline(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    result = cli(
        ["scan", str(project), "--diff-since", "main", "--subproject", "src",
         "--subproject", "web", "--include-deleted", "--keep-state"],
    )  # fmt: skip
    assert result.exit_code == 0, result.stderr
    call = stub.calls[0]
    assert call["ingest_options"] == {
        "diff_since": "main",
        "include_deleted": True,
        "subprojects": ["src", "web"],
    }
    assert call["keep_work"] is True


def test_without_the_flags_the_runner_is_called_as_before(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    assert cli(["scan", str(project)]).exit_code == 0
    assert "ingest_options" not in stub.calls[0]
    assert "keep_work" not in stub.calls[0]


def test_a_stdin_scan_without_a_filename_is_refused_before_anything_runs(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    result = cli(["scan", "-"])
    assert result.exit_code == 2
    assert "stdin-filename" in result.stderr
    assert stub.calls == []


def test_a_git_url_and_its_options_reach_the_pipeline_unchanged(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    url = "https://git.example.invalid/team/app.git"
    result = cli(
        ["scan", url, "--ref", "v1.2", "--depth", "2", "--git-credential", "env:GIT_TOKEN"]
    )
    assert result.exit_code == 0, result.stderr
    assert stub.calls[0]["target"] == url
    assert stub.calls[0]["ingest_options"] == {
        "ref": "v1.2",
        "depth": 2,
        "git_credential": "env:GIT_TOKEN",
    }
