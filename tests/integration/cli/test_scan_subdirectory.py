"""``codekavach scan sub/dir`` inside a git checkout scans that directory (issue #326).

A real ``git init`` repository holds the KavachBank sample under ``fixtures/kavachbank``, the
layout of this project's own checkout. Scanning the sub-directory by a relative path from the
repository root, by an absolute path, and from inside it must report the same findings as
``scan . --subproject fixtures/kavachbank``, and more than none. Engines and rules are real; the
LLM is off, so the test opens no connection.
"""

import shutil
from pathlib import Path
from typing import Any

import pytest

from tests.support.cli import run_cli
from tests.support.hostile import git, has_git

KAVACHBANK = Path(__file__).resolve().parents[3] / "fixtures" / "kavachbank"
SUBDIR = "fixtures/kavachbank"

pytestmark = pytest.mark.skipif(not has_git(), reason="git is not installed")


@pytest.fixture(scope="module")
def checkout(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A committed repository whose sample sits two levels below the root."""
    root = tmp_path_factory.mktemp("checkout") / "repo"
    sample = root / SUBDIR
    shutil.copytree(KAVACHBANK, sample, ignore=shutil.ignore_patterns("ground-truth", "cassettes"))
    (root / "README.md").write_text("# a project with a sample inside\n", encoding="utf-8")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "init")
    return root


def scan(args: list[str], cwd: Path) -> dict[str, Any]:
    result = run_cli(
        ["scan", *args, "--no-llm", "--offline", "--fail-on", "none", "--json"],
        cwd=cwd,
        home=cwd.parent / "home",
    )
    assert result.exit_code == 0, result.stderr
    data: dict[str, Any] = result.json["data"]
    return data


@pytest.fixture(scope="module")
def by_subproject(checkout: Path) -> int:
    total: int = scan([".", "--subproject", SUBDIR], checkout)["summary"]["findings_total"]
    assert total > 0
    return total


@pytest.mark.parametrize("how", ["relative", "absolute", "from-inside"])
def test_a_subdirectory_of_a_checkout_is_scanned_like_the_subproject(
    checkout: Path, by_subproject: int, how: str
) -> None:
    target, cwd = {
        "relative": (SUBDIR, checkout),
        "absolute": (str(checkout / SUBDIR), checkout),
        "from-inside": (".", checkout / SUBDIR),
    }[how]
    data = scan([target], cwd)
    assert data["summary"]["findings_total"] == by_subproject
