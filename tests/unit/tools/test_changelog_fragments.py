import importlib.util
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

from tests.support.workflows import load_workflow

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "tools/dev/check_changelog_fragments.py"
CATEGORIES = ["added", "changed", "deprecated", "removed", "fixed", "security"]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_changelog_fragments", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_changelog_fragments"] = module
    spec.loader.exec_module(module)
    return module


checker = _load()


@pytest.mark.parametrize(
    "name",
    [
        "12.added.md",
        "+scaffolding.added.md",
        "7.fixed.2.md",
        "README.md",
        "169.security.md",
        "+cli-help-2.changed.10.md",
        "3.deprecated.md",
        "4.removed.md",
    ],
)
def test_valid_names(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("A change.\n", encoding="utf-8")
    assert checker.invalid_fragments(tmp_path) == []
    assert checker.main([str(tmp_path)]) == 0


@pytest.mark.parametrize(
    "name",
    [
        "12.feature.md",
        "added.md",
        "12.added.txt",
        "+Bad_Slug.added.md",
        "12.added",
        "+.added.md",
        "12.Added.md",
        "notes.md",
        "12.added.x.md",
        "readme.md",
    ],
)
def test_invalid_names(tmp_path: Path, name: str, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / name).write_text("A change.\n", encoding="utf-8")
    (tmp_path / "13.added.md").write_text("A valid one.\n", encoding="utf-8")
    problems = checker.invalid_fragments(tmp_path)
    assert len(problems) == 1
    assert problems[0].startswith(f"{name}: ")
    assert checker.main([str(tmp_path)]) == 1
    assert f"{tmp_path.name}/{name}: " in capsys.readouterr().err


def test_an_empty_fragment_and_a_directory_are_invalid(tmp_path: Path) -> None:
    (tmp_path / "12.added.md").write_text("  \n", encoding="utf-8")
    (tmp_path / "13.fixed.md").mkdir()
    assert checker.invalid_fragments(tmp_path) == [
        "12.added.md: the fragment is empty",
        "13.fixed.md: not '<issue>.<type>.md' or '+<slug>.<type>.md' with a type of "
        "added, changed, deprecated, removed, fixed, security",
    ]
    assert checker.main([str(tmp_path / "missing")]) == 2


def test_fragments_of_the_repository_are_valid() -> None:
    directory = REPO_ROOT / "changelog.d"
    assert directory == checker.DEFAULT_DIRECTORY
    assert (directory / "README.md").is_file()
    assert (directory / "+scaffolding.added.md").is_file()
    assert checker.invalid_fragments(directory) == []
    assert checker.main([]) == 0


def test_towncrier_types_are_the_keep_a_changelog_categories() -> None:
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    towncrier = config["tool"]["towncrier"]
    assert [entry["directory"] for entry in towncrier["type"]] == CATEGORIES
    assert [entry["name"] for entry in towncrier["type"]] == [c.capitalize() for c in CATEGORIES]
    assert all(entry["showcontent"] is True for entry in towncrier["type"])
    assert list(checker.TYPES) == CATEGORIES
    assert (towncrier["directory"], towncrier["filename"]) == ("changelog.d", "CHANGELOG.md")
    assert towncrier["start_string"] == "<!-- towncrier release notes start -->\n"
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert changelog.endswith(towncrier["start_string"])
    assert "Keep a Changelog" in changelog
    assert "Semantic Versioning" in changelog
    groups = config["dependency-groups"]
    assert any(entry.startswith("towncrier") for entry in groups["release"])
    assert {"include-group": "release"} in groups["dev"]


def test_make_targets_ci_step_and_documents() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "\tuv run towncrier build --draft --version Unreleased\n" in makefile
    assert "changelog-check:" in makefile
    assert "\tuv run python tools/dev/check_changelog_fragments.py\n" in makefile
    lint = load_workflow(REPO_ROOT / ".github/workflows/ci.yml")["jobs"]["lint"]
    assert any("changelog-check" in step.get("run", "") for step in lint["steps"])
    agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "a `changelog.d/` fragment for user-visible changes" in agents
    record = (REPO_ROOT / "docs/adr/0004-changelog-and-versioning.md").read_text(encoding="utf-8")
    assert "| Status | Accepted |" in record
    for phrase in ("release-please", "hand-edited", "`git log`", "`0.1.0.dev0`", "`1.0.0`"):
        assert phrase in record, phrase
    readme = (REPO_ROOT / "tools/dev/README.md").read_text(encoding="utf-8")
    assert "`check_changelog_fragments.py`" in readme


def scratch_copy(target: Path) -> Path:
    target.mkdir()
    for name in ("pyproject.toml", "CHANGELOG.md"):
        shutil.copy(REPO_ROOT / name, target / name)
    shutil.copytree(REPO_ROOT / "changelog.d", target / "changelog.d")
    return target


def towncrier(directory: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "towncrier", "build", *arguments],
        cwd=directory, capture_output=True, text=True, encoding="utf-8", check=False,
    )  # fmt: skip


@pytest.mark.slow
def test_draft_renders_a_keep_a_changelog_section(tmp_path: Path) -> None:
    copy = scratch_copy(tmp_path / "copy")
    before = sorted(path.name for path in (copy / "changelog.d").iterdir())
    changelog = (copy / "CHANGELOG.md").read_bytes()
    completed = towncrier(copy, "--draft", "--version", "9.9.9")
    assert completed.returncode == 0, completed.stderr
    assert "## [9.9.9] - " in completed.stdout
    assert "### Added" in completed.stdout
    assert "- Project scaffolding:" in completed.stdout
    assert sorted(path.name for path in (copy / "changelog.d").iterdir()) == before
    assert (copy / "CHANGELOG.md").read_bytes() == changelog


@pytest.mark.slow
def test_build_inserts_the_section_below_the_marker_and_removes_fragments(tmp_path: Path) -> None:
    copy = scratch_copy(tmp_path / "copy")
    (copy / "changelog.d" / "12.security.md").write_text(
        "Privacy: comments are removed at level L2.\n", encoding="utf-8"
    )
    completed = towncrier(copy, "--version", "0.0.1", "--yes")
    assert completed.returncode == 0, completed.stderr
    text = (copy / "CHANGELOG.md").read_text(encoding="utf-8")
    preamble, released = text.split("<!-- towncrier release notes start -->\n", 1)
    assert preamble.startswith("# Changelog\n")
    assert released.lstrip("\n").startswith("## [0.0.1] - ")
    assert released.index("### Added") < released.index("### Security")
    assert "- Privacy: comments are removed at level L2. (#12)" in released
    assert sorted(path.name for path in (copy / "changelog.d").iterdir()) == ["README.md"]
