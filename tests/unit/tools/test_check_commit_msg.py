import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tests.support.workflows import load_workflow

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "tools/dev/check_commit_msg.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_commit_msg", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_commit_msg"] = module
    spec.loader.exec_module(module)
    return module


checker = _load()

# Assembled at run time: the phrases are not written literally anywhere in the repository.
CO_AUTHOR_KEY = "-".join(["Co", "authored", "by"])
TOOL_CREDIT = " ".join(["Generated", "with"])
TOOL_CREDIT_BY = " ".join(["Generated", "by"])
ROBOT = chr(0x1F916)
SUBJECT_72 = "core: " + "a" * 66
SUBJECT_73 = "core: " + "a" * 67

VALID = [
    *[f"{area}: add a thing" for area in checker.AREAS],
    "privacy: reject payloads that contain vault identifiers\n\nThe guard scans.\n\nCloses #142",
    "cli: add `--strict` to scan\n\nRefs #169",
    "cli: `scan` exits 1 on a degraded stage",
    "docs: explain levels\n\nBody line one.\nBody line two.\n\nRefs #1, #22, #333",
    "infra: bump ruff\n\nCloses #5\n",
    SUBJECT_72,
    "core: describe what closes the gap\n\nThis closes the gap left by the old loader.",
    "docs: add the Hindi name\n\nThe README explains कवच (kavach), which means armour.",
    "report: render tables\n\nA line with a # in the middle and issue #12 in prose.",
    "Merge branch 'main' into feature",
    "Merge pull request #12 from someone/branch",
    'Revert "core: add a thing"\n\nThis reverts commit abc.',
    "fixup! core: add a thing",
    "squash! core: add a thing",
]

INVALID = [
    ("Fixed stuff", "no '<area>: ' prefix"),
    ("privacy: Add guard.", "ends with a full stop"),
    ("privacy: Add guard.", "starts with a lower-case letter"),
    ("security: add guard", "unknown area 'security'"),
    ("Core: add guard", "unknown area 'Core'"),
    ("core:add guard", "exactly one space"),
    ("core:  add guard", "exactly one space"),
    ("core:", "exactly one space"),
    ("feat(core): add guard", "no '<area>: ' prefix"),
    (SUBJECT_73, "has 73 characters; the limit is 72"),
    ("core: add guard\nbody without a blank line", "the second line is not empty"),
    ("core: 2 guards", "starts with a lower-case letter"),
    ("core: add guard\n\nrefs #12", "malformed issue reference 'refs #12'"),
    ("core: add guard\n\nRefs: #12", "malformed issue reference"),
    ("core: add guard\n\nRefs #12 and #13", "malformed issue reference"),
    ("core: add guard\n\nCloses #12,#13", "malformed issue reference"),
    ("core: add guard\n\nCloses #", "malformed issue reference"),
    ("core: add guard\n\n  Refs #12", "malformed issue reference"),
    ("core: add guard\n\nCLOSES #12", "malformed issue reference"),
    ("", "the message is empty"),
    ("\n\n", "the message is empty"),
]


@pytest.mark.parametrize("message", VALID, ids=[m.splitlines()[0][:40] for m in VALID])
def test_valid_messages(message: str) -> None:
    assert checker.validate(message) == []


@pytest.mark.parametrize(("message", "problem"), INVALID)
def test_invalid_messages(message: str, problem: str) -> None:
    problems = checker.validate(message)
    assert any(problem in found for found in problems), problems


def test_the_table_is_large_enough_and_areas_match_agents_md() -> None:
    assert len(VALID) + len(INVALID) >= 25
    agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    line = next(
        line for line in agents.splitlines() if line.startswith("- Areas match the labels:")
    )
    documented = [name.strip("`.") for name in line.split(":", 1)[1].replace(",", " ").split()]
    assert list(checker.AREAS) == documented


def test_one_message_can_have_several_problems() -> None:
    problems = checker.validate("privacy: Add guard.\nno blank line\nrefs #1")
    assert len(problems) == 4


@pytest.mark.parametrize(
    "line",
    [
        f"{CO_AUTHOR_KEY}: Some Tool <tool@example.invalid>",
        f"{CO_AUTHOR_KEY.lower()}: someone <a@example.invalid>",
        f"{CO_AUTHOR_KEY.upper()}:someone <a@example.invalid>",
        f"  {CO_AUTHOR_KEY} : someone",
    ],
)
def test_co_author_trailers_are_rejected_in_any_case(line: str) -> None:
    problems = checker.validate(f"core: add guard\n\nBody.\n\n{line}")
    assert "a co-author trailer is not allowed" in problems


@pytest.mark.parametrize(
    "line",
    [
        f"{TOOL_CREDIT} [Some Tool](https://example.invalid)",
        f"{TOOL_CREDIT.upper()} a tool",
        f"{TOOL_CREDIT_BY} a tool",
        f"{TOOL_CREDIT_BY.lower()} a tool",
        f"{ROBOT} {TOOL_CREDIT} [Some Tool](https://example.invalid)",
        f"{ROBOT} [Some Tool](https://example.invalid)",
    ],
)
def test_tool_credit_lines_are_rejected_in_any_case(line: str) -> None:
    problems = checker.validate(f"core: add guard\n\n{line}")
    assert "a line that credits a tool is not allowed" in problems


def test_prose_about_generated_files_is_not_a_credit() -> None:
    assert checker.validate("docs: regenerate schemas\n\nThe generated files changed.") == []
    assert checker.validate("docs: note\n\nSchemas are generated by the export module.") == []


def test_the_script_does_not_contain_the_phrases_literally() -> None:
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert CO_AUTHOR_KEY.lower() not in source
    assert TOOL_CREDIT.lower() not in source
    assert ROBOT not in source


@pytest.mark.parametrize(
    "message",
    [
        f"core: add guard {chr(0x1F680)}",
        f"core: add guard\n\nDone {chr(0x2705)}",
        f"core: add guard\n\nWarning {chr(0x26A0)}{chr(0xFE0F)}",
        f"core: add guard\n\n{chr(0x1FAE0)}",
    ],
)
def test_emoji_are_rejected(message: str) -> None:
    assert "emoji are not allowed" in checker.validate(message)


def test_devanagari_and_other_scripts_are_accepted() -> None:
    assert checker.validate("docs: explain कोडकवच in the README\n\nकवच means armour.") == []
    assert checker.validate("docs: add a note\n\nNaïve café, Größe, 日本語, arrows → and ≥.") == []


# hook mode


def test_comment_lines_and_everything_below_the_scissors_are_ignored(tmp_path: Path) -> None:
    text = (
        "core: add guard\n"
        "\n"
        "# Please enter the commit message for your changes.\n"
        "Body.\n"
        "# On branch main\n"
        f"{checker.SCISSORS}\n"
        "diff --git a/x b/x\n"
        "+Fixed stuff.\n"
        f"+{CO_AUTHOR_KEY}: someone\n"
    )
    assert checker.strip_comments(text) == "core: add guard\n\nBody."
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text(text, encoding="utf-8")
    assert checker.main([str(message)]) == 0
    only_comments = tmp_path / "EMPTY"
    only_comments.write_text("# nothing\n", encoding="utf-8")
    assert checker.main([str(only_comments)]) == 1


def test_hook_rejection_lists_the_rules_and_shows_examples(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text("bad message\n", encoding="utf-8")
    assert checker.main([str(message)]) == 1
    error = capsys.readouterr().err
    assert "commit message rejected:" in error
    assert "no '<area>: ' prefix" in error
    assert "privacy: reject payloads that contain vault identifiers" in error
    assert "cli: add the --strict option to scan" in error
    assert f"Areas: {', '.join(checker.AREAS)}" in error
    message.write_text("infra: add commit message check\n", encoding="utf-8")
    assert checker.main([str(message)]) == 0
    assert checker.main([str(tmp_path / "missing")]) == 2


def test_help_shows_the_same_guide(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        checker.main(["--help"])
    assert stop.value.code == 0
    assert checker.GUIDE in capsys.readouterr().out


# range and CI mode


def git(repo: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(
        [executable, *arguments], cwd=repo, capture_output=True, text=True, encoding="utf-8",
        check=True,
    )  # fmt: skip
    return completed.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is not available")
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "--quiet", "--initial-branch=main")
    git(path, "config", "user.name", "Test Author")
    git(path, "config", "user.email", "author@example.invalid")
    git(path, "config", "commit.gpgsign", "false")
    for number, subject in enumerate(["core: add the base", "docs: describe it", "Fixed stuff"]):
        (path / f"file{number}.txt").write_text(subject, encoding="utf-8")
        git(path, "add", ".")
        git(path, "commit", "--quiet", "--no-verify", "-m", subject)
    monkeypatch.chdir(path)
    return path


def test_range_mode_reports_exactly_the_invalid_commit(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = git(repo, "rev-parse", "--short=7", "HEAD")
    good = [
        git(repo, "rev-parse", "--short=7", "HEAD~1"),
        git(repo, "rev-parse", "--short=7", "HEAD~2"),
    ]
    assert checker.main(["--range", "HEAD~2..HEAD"]) == 1
    error = capsys.readouterr().err
    assert f"{bad}: Fixed stuff" in error
    assert not any(sha in error for sha in good)
    assert checker.main(["--range", "HEAD~2..HEAD~1"]) == 0
    assert "1 commit message(s) follow the convention" in capsys.readouterr().out
    assert checker.main(["--range", "no-such-rev..HEAD"]) == 2


def test_ci_mode_chooses_the_range_from_the_environment(repo: Path) -> None:
    head = git(repo, "rev-parse", "HEAD")
    before = git(repo, "rev-parse", "HEAD~2")
    push = {"COMMIT_CHECK_EVENT": "push", "COMMIT_CHECK_SHA": head}
    assert checker.ci_log_arguments({**push, "COMMIT_CHECK_BEFORE": before}) == [
        f"{before}..{head}"
    ]
    new_branch = {**push, "COMMIT_CHECK_BEFORE": "0" * 40}
    assert checker.ci_log_arguments(new_branch) == ["-1", "HEAD"]
    force_push = {**push, "COMMIT_CHECK_BEFORE": "1" * 40}
    assert checker.ci_log_arguments(force_push) == ["-1", "HEAD"]
    hostile = {**push, "COMMIT_CHECK_BEFORE": "--output=/tmp/x"}
    assert checker.ci_log_arguments(hostile) == ["-1", "HEAD"]
    pull = {"COMMIT_CHECK_EVENT": "pull_request", "COMMIT_CHECK_BASE_REF": "main"}
    assert checker.ci_log_arguments(pull) == ["origin/main..HEAD"]
    assert checker.ci_log_arguments({"COMMIT_CHECK_EVENT": "workflow_dispatch"}) == ["-1", "HEAD"]
    assert checker.ci_log_arguments({}) == ["-1", "HEAD"]


def test_ci_mode_runs(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COMMIT_CHECK_EVENT", "push")
    monkeypatch.setenv("COMMIT_CHECK_SHA", git(repo, "rev-parse", "HEAD~1"))
    monkeypatch.setenv("COMMIT_CHECK_BEFORE", git(repo, "rev-parse", "HEAD~2"))
    assert checker.main(["--ci"]) == 0
    monkeypatch.setenv("COMMIT_CHECK_SHA", git(repo, "rev-parse", "HEAD"))
    assert checker.main(["--ci"]) == 1


# registration


def test_hook_and_ci_job_are_registered() -> None:
    hooks = (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    block = hooks.split("- id: commit-msg-format\n", 1)[1].split("- id:", 1)[0]
    assert "entry: uv run python tools/dev/check_commit_msg.py\n" in block
    assert "stages: [commit-msg]\n" in block
    assert "language: system\n" in block
    jobs = load_workflow(REPO_ROOT / ".github/workflows/ci.yml")["jobs"]
    assert "commits" in jobs["ci-ok"]["needs"]
    checkout, check = jobs["commits"]["steps"]
    assert checkout["with"]["fetch-depth"] == 0
    assert check["run"] == "python3 tools/dev/check_commit_msg.py --ci"
    assert "${{" not in check["run"]
    assert set(check["env"]) == {
        "COMMIT_CHECK_EVENT",
        "COMMIT_CHECK_BEFORE",
        "COMMIT_CHECK_SHA",
        "COMMIT_CHECK_BASE_REF",
    }
    assert "`check_commit_msg.py`" in (REPO_ROOT / "tools/dev/README.md").read_text(
        encoding="utf-8"
    )
