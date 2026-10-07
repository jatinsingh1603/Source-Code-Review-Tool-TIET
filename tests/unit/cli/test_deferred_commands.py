"""``sync github``, ``eval detection``, ``eval leakage`` and ``demo`` (E05-27).

The grammar is fixed now and the back ends arrive with later epics: without one a command ends
with ``backend_unavailable`` (exit 2) and names the epic; with one it is called once with the parsed
arguments. Nothing is simulated, written or sent while the back end is missing.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codekavach.cli.deferred import (
    check_dataset,
    check_levels,
    check_names,
    check_project,
    check_repository,
    check_scan,
    looks_like_path,
)
from codekavach.cli.errors import UsageError
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend

Cli = Callable[..., CliResult]
SCAN = "scan_01J8ZQ4M0A0A0A0A0A0A0A0A0A"
TRUST = "--trust-project-config"


class Case:
    """One deferred command: its words, back end seam and owning epic."""

    def __init__(self, name: str, words: list[str], seam: str, epic: str, feature: str) -> None:
        self.name = name
        self.words = words
        self.seam = seam
        self.epic = epic
        self.feature = feature


CASES = [
    Case("sync github", ["sync", "github"], "codekavach.integrations.github.run_github_sync",
         "E34", "GitHub sync"),
    Case("eval detection", ["eval", "detection", "--dataset", "owasp-benchmark"],
         "codekavach.eval.run_detection_eval", "E36", "the detection evaluation"),
    Case("eval leakage", ["eval", "leakage"], "codekavach.eval.run_leakage_eval", "E37",
         "the leakage evaluation"),
    Case("demo", ["demo"], "codekavach.cli.demo_runner.run_demo", "E13", "the demo"),
]  # fmt: skip
IDS = [case.name for case in CASES]


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def listing(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)) for path in root.rglob("*"))


# --- the grammar is visible ---------------------------------------------------------------------

DOCUMENTED = {
    "sync github": [
        "--scan", "--repo", "--project", "--issues", "--no-issues", "--board", "--no-board",
        "--dry-run", "--max-issues", "[target]",
    ],
    "eval detection": ["--dataset", "--level", "--provider", "--out", "--limit"],
    "eval leakage": ["--scan", "--dataset", "--level", "--attacker", "--out"],
    "demo": ["--fixture", "--out", "--keep-state"],
}  # fmt: skip


@pytest.mark.parametrize("name", list(DOCUMENTED))
def test_the_help_lists_every_documented_option(name: str, cli: Cli, project: Path) -> None:
    result = cli([*name.split(), "--help"], cwd=project)
    assert result.exit_code == 0, result.stderr
    for option in DOCUMENTED[name]:
        assert option in result.stdout, f"{name}: {option}"


def test_the_root_help_lists_the_three_groups(cli: Cli, project: Path) -> None:
    out = cli(["--help"], cwd=project).stdout
    for name in ("sync", "eval", "demo"):
        assert name in out


def test_the_sync_help_says_what_it_does_not_do(cli: Cli, project: Path) -> None:
    out = " ".join(cli(["sync", "github", "--help"], cwd=project).stdout.split())
    assert "does not modify code, open pull requests or push commits" in out
    assert "integrations.github.token" in out
    assert "--token" not in out


def test_the_demo_help_names_the_sequence(cli: Cli, project: Path) -> None:
    out = " ".join(cli(["demo", "--help"], cwd=project).stdout.split())
    for step in ("scan", "privacy inspect --list", "privacy ledger verify", "report"):
        assert step in out
    assert "mock provider" in out


def test_the_groups_without_a_command_show_help(cli: Cli, project: Path) -> None:
    for group in ("sync", "eval"):
        result = cli([group], cwd=project)
        assert "Usage:" in result.stdout + result.stderr


# --- without a back end ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_a_missing_back_end_is_backend_unavailable(case: Case, cli: Cli, project: Path) -> None:
    before = listing(project)
    result = cli(case.words, cwd=project)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert f"error[backend_unavailable]: {case.feature} is not available in this build" in " ".join(
        result.stderr.split()
    )
    assert f"hint: delivered by epic {case.epic}" in result.stderr
    assert listing(project) == before  # nothing was written


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_a_missing_back_end_in_json_mode_is_one_envelope(
    case: Case, cli: Cli, project: Path
) -> None:
    result = cli(["--json", *case.words], cwd=project)
    assert result.exit_code == 2
    envelope = result.json
    assert envelope["ok"] is False and envelope["exit_code"] == 2
    assert envelope["data"] is None
    (error,) = envelope["errors"]
    assert error["code"] == "backend_unavailable"
    assert error["hint"] == f"delivered by epic {case.epic}"
    assert error["message"] == f"{case.feature} is not available in this build"


def test_the_demo_writes_nothing_by_default(cli: Cli, project: Path) -> None:
    cli(["demo"], cwd=project)
    assert not (project / "codekavach-demo").exists()


# --- with a back end ----------------------------------------------------------------------------


class Recorder:
    """A fake back end that records its calls and returns a small report."""

    def __init__(self, report: Any = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.report = {"synced": 3, "dry_run": False} if report is None else report

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.report


def install(monkeypatch: pytest.MonkeyPatch, case: Case) -> Recorder:
    recorder = Recorder()
    fake_backend(monkeypatch, case.seam, recorder)
    return recorder


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_a_present_back_end_is_called_once_and_its_report_rendered(
    case: Case, cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = install(monkeypatch, case)
    result = cli(case.words, cwd=project)
    assert result.exit_code == 0, result.stderr
    assert len(recorder.calls) == 1
    assert "synced" in result.stdout
    as_json = cli(["--json", *case.words], cwd=project)
    assert as_json.exit_code == 0
    assert as_json.json["data"] == {"synced": 3, "dry_run": False}
    assert len(recorder.calls) == 2


def test_sync_github_passes_the_parsed_arguments(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = install(monkeypatch, CASES[0])
    cli(["sync", "github", str(project)], cwd=project)
    (call,) = recorder.calls
    assert call["scan"] == "latest" and call["repo"] is None and call["project"] is None
    assert (call["issues"], call["board"], call["dry_run"], call["max_issues"]) == (
        True, True, False, None,
    )  # fmt: skip
    assert call["target"] == project and call["settings"] is not None
    recorder.calls.clear()
    cli(
        [
            "sync", "github", str(project), "--scan", SCAN, "--repo", "acme/ledger.v2",
            "--project", "7", "--no-issues", "--no-board", "--dry-run", "--max-issues", "3",
        ],
        cwd=project,
    )  # fmt: skip
    (call,) = recorder.calls
    assert call["scan"] == SCAN and call["repo"] == "acme/ledger.v2" and call["project"] == "7"
    assert (call["issues"], call["board"], call["dry_run"], call["max_issues"]) == (
        False, False, True, 3,
    )  # fmt: skip


def test_the_repository_defaults_to_the_setting(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (project / "codekavach.toml").write_text(
        '[integrations.github]\nrepository = "acme/from-settings"\n', encoding="utf-8"
    )
    recorder = install(monkeypatch, CASES[0])
    assert cli([TRUST, "sync", "github"], cwd=project).exit_code == 0
    assert recorder.calls[0]["repo"] == "acme/from-settings"
    recorder.calls.clear()
    cli([TRUST, "sync", "github", "--repo", "acme/flag"], cwd=project)
    assert recorder.calls[0]["repo"] == "acme/flag"  # the flag wins


def test_sync_github_accepts_a_project_url(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = install(monkeypatch, CASES[0])
    url = "https://github.com/orgs/acme/projects/4"
    assert cli(["sync", "github", "--project", url], cwd=project).exit_code == 0
    assert recorder.calls[0]["project"] == url


def test_eval_detection_passes_the_parsed_arguments(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = install(monkeypatch, CASES[1])
    result = cli(
        [
            "eval", "detection", "--dataset", "owasp-benchmark", "--level", "l3", "--level", "L4",
            "--level", "L3", "--provider", "mock", "--provider", "lab", "--out", "results.json",
            "--limit", "50",
        ],
        cwd=project,
    )  # fmt: skip
    assert result.exit_code == 0, result.stderr
    assert recorder.calls == [
        {
            "dataset": "owasp-benchmark",
            "levels": ["L3", "L4"],
            "providers": ["mock", "lab"],
            "out": "results.json",
            "limit": 50,
        }
    ]


def test_eval_detection_accepts_an_existing_dataset_path(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (project / "bench").mkdir()
    recorder = install(monkeypatch, CASES[1])
    assert cli(["eval", "detection", "--dataset", "./bench"], cwd=project).exit_code == 0
    assert recorder.calls[0]["dataset"] == "./bench"
    assert recorder.calls[0]["levels"] == []


def test_eval_leakage_passes_the_parsed_arguments(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = install(monkeypatch, CASES[2])
    cli(["eval", "leakage"], cwd=project)
    assert recorder.calls[0] == {
        "scan": "latest", "dataset": None, "levels": [], "attackers": [], "out": None,
    }  # fmt: skip
    recorder.calls.clear()
    cli(
        ["eval", "leakage", "--scan", SCAN, "--level", "L2", "--attacker", "recover-names",
         "--attacker", "summarise", "--out", "leak.json"],
        cwd=project,
    )  # fmt: skip
    assert recorder.calls[0] == {
        "scan": SCAN, "dataset": None, "levels": ["L2"],
        "attackers": ["recover-names", "summarise"], "out": "leak.json",
    }  # fmt: skip
    recorder.calls.clear()
    cli(["eval", "leakage", "--dataset", "canaries"], cwd=project)
    assert recorder.calls[0]["scan"] is None and recorder.calls[0]["dataset"] == "canaries"


def test_demo_passes_the_parsed_arguments(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = install(monkeypatch, CASES[3])
    cli(["demo"], cwd=project)
    assert recorder.calls[0] == {
        "fixture": "kavachbank", "out": Path("codekavach-demo/"), "keep_state": False,
    }  # fmt: skip
    recorder.calls.clear()
    cli(["demo", "--fixture", "other", "--out", "here", "--keep-state"], cwd=project)
    assert recorder.calls[0] == {"fixture": "other", "out": Path("here"), "keep_state": True}


def test_a_report_that_is_not_a_mapping_is_rendered_too(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend(monkeypatch, CASES[3].seam, Recorder(report="all done"))
    assert cli(["demo"], cwd=project).stdout.strip() == "all done"


# --- validation without a back end ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("words", "code"),
    [
        (["sync", "github", "--repo", "notarepo"], "bad_repo"),
        (["sync", "github", "--repo", "a/b/c"], "bad_repo"),
        (["sync", "github", "--repo", "bad owner/name"], "bad_repo"),
        (["sync", "github", "--scan", "yesterday"], "bad_scan"),
        (["sync", "github", "--project", "not-a-number"], "bad_project"),
        (["sync", "github", "--offline"], "offline_network_conflict"),
        (["--offline", "sync", "github"], "offline_network_conflict"),
        (["eval", "detection", "--dataset", "x", "--level", "L9"], "bad_level"),
        (["eval", "detection", "--dataset", "./no-such-dir"], "dataset_not_found"),
        (["eval", "detection", "--dataset", "bad name"], "bad_dataset"),
        (["eval", "detection", "--dataset", "x", "--provider", "bad id"], "bad_name"),
        (["eval", "leakage", "--scan", "x"], "bad_scan"),
        (["eval", "leakage", "--level", "7"], "bad_level"),
        (["eval", "leakage", "--attacker", "bad/name"], "bad_name"),
        (["eval", "leakage", "--scan", "latest", "--dataset", "x"], "scan_dataset_conflict"),
        (["eval", "leakage", "--dataset", "~/no-such-dataset-dir"], "dataset_not_found"),
        (["demo", "--fixture", "./no-such-fixture"], "dataset_not_found"),
        (["sync", "github", "no-such-directory"], "target_not_found"),
    ],
)
def test_validation_comes_before_the_back_end(
    words: list[str], code: str, cli: Cli, project: Path
) -> None:
    result = cli(words, cwd=project)
    assert result.exit_code == 2, result.stderr
    assert f"error[{code}]" in result.stderr
    assert "backend_unavailable" not in result.stderr


def test_a_validation_error_never_reaches_a_present_back_end(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = install(monkeypatch, CASES[0])
    assert cli(["sync", "github", "--repo", "notarepo"], cwd=project).exit_code == 2
    assert cli(["sync", "github", "--offline"], cwd=project).exit_code == 2
    assert recorder.calls == []


@pytest.mark.parametrize(
    "words",
    [
        ["eval", "detection"],
        ["sync", "github", "--max-issues", "0"],
        ["eval", "detection", "--dataset", "x", "--limit", "0"],
        ["sync", "github", "--token", "x"],
    ],
)
def test_click_usage_errors_exit_two(words: list[str], cli: Cli, project: Path) -> None:
    result = cli(words, cwd=project)
    assert result.exit_code == 2
    assert "backend_unavailable" not in result.stderr


# --- the validators -------------------------------------------------------------------------------


def test_levels_are_normalised_deduplicated_and_ordered() -> None:
    assert check_levels([]) == []
    assert check_levels(["l2", "L0", " L2 "]) == ["L2", "L0"]
    with pytest.raises(UsageError) as info:
        check_levels(["L5"])
    assert info.value.code == "bad_level"


@pytest.mark.parametrize("value", ["a/b", "A-b_c.d/e.f-g", None])
def test_valid_repositories(value: str | None) -> None:
    assert check_repository(value) == value


@pytest.mark.parametrize("value", ["", "a", "/b", "a/", "a b/c", "a/b/c", "a/b;rm"])
def test_invalid_repositories(value: str) -> None:
    with pytest.raises(UsageError) as info:
        check_repository(value)
    assert info.value.code == "bad_repo"


def test_scan_project_and_names() -> None:
    assert check_scan("latest") == "latest" and check_scan(SCAN) == SCAN
    for bad in ("", "scan_", "scan_" + "I" * 26, "LATEST"):
        with pytest.raises(UsageError):
            check_scan(bad)
    assert check_project(None) is None and check_project("12") == "12"
    assert (
        check_project("https://github.com/orgs/a/projects/1")
        == "https://github.com/orgs/a/projects/1"
    )
    for bad in ("", "-1", "http://github.com/x", "https://", "12345678901"):
        with pytest.raises(UsageError):
            check_project(bad)
    assert check_names(["a", "b", "a"], option="--x") == ["a", "b"]
    with pytest.raises(UsageError):
        check_names(["a b"], option="--x")


def test_what_looks_like_a_path() -> None:
    assert all(looks_like_path(text) for text in ("./x", "a/b", "a\\b", "~/x", ".hidden"))
    assert not any(looks_like_path(text) for text in ("kavachbank", "owasp-benchmark", "x.y"))
    assert check_dataset("kavachbank") == "kavachbank"


# --- the reference page --------------------------------------------------------------------------

PAGE = Path(__file__).resolve().parents[3] / "docs" / "reference" / "cli-global-options.md"


def test_the_reference_explains_the_deferred_commands() -> None:
    text = PAGE.read_text(encoding="utf-8")
    section = text.split("## Commands delivered by later milestones", 1)[1]
    assert "backend_unavailable" in section
    for case in CASES:
        command = " ".join(case.words[:2]) if case.name != "demo" else "demo"
        assert f"`{command}`" in section, command
        assert case.seam.rpartition(".")[0] in section
        assert case.epic in section
