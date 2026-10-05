"""Whitespace and line-ending rules of the repository, and their exemption of byte-exact files."""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
EXEMPT_PREFIXES = ("fixtures/", "tests/fixtures/")
BAD_INDEX_ENDINGS = ("i/crlf", "i/mixed")


def git(*arguments: str) -> str:
    """Run git in the repository; skip the test when that is not possible."""
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git is not available")
    inside = subprocess.run(
        [executable, "rev-parse", "--is-inside-work-tree"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )  # fmt: skip
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        pytest.skip("the directory is not a git work tree")
    completed = subprocess.run(
        [executable, *arguments],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
    )  # fmt: skip
    return completed.stdout


def is_exempt(path: str) -> bool:
    """Whether ``path`` is byte-exact: a fixture or a golden file."""
    return path.startswith(EXEMPT_PREFIXES) or (path.startswith("tests/") and "/golden/" in path)


def test_both_files_exist_and_editorconfig_is_the_root() -> None:
    editorconfig = REPO_ROOT / ".editorconfig"
    assert editorconfig.is_file()
    assert (REPO_ROOT / ".gitattributes").is_file()
    assert editorconfig.read_text(encoding="utf-8").startswith("root = true\n")


def test_editorconfig_exempts_fixtures_and_golden_files() -> None:
    text = (REPO_ROOT / ".editorconfig").read_text(encoding="utf-8")
    section = text.split("[{fixtures/**,tests/**/golden/**,tests/fixtures/**}]\n", 1)[1]
    settings = dict(line.split(" = ") for line in section.strip().splitlines())
    assert settings == {
        "charset": "unset",
        "end_of_line": "unset",
        "insert_final_newline": "unset",
        "trim_trailing_whitespace": "unset",
        "indent_style": "unset",
        "indent_size": "unset",
    }
    assert "[*]\ncharset = utf-8\nend_of_line = lf\n" in text
    assert "[Makefile]\nindent_style = tab\n" in text


def test_gitattributes_rules() -> None:
    lines = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "* text=auto eol=lf"
    for rule in (
        "fixtures/** -text linguist-vendored",
        "tests/**/golden/** -text",
        "tests/fixtures/** -text",
        "*.png binary",
        "*.pdf binary",
        "uv.lock linguist-generated=true",
    ):
        assert rule in lines, rule
    assert not any(line.startswith("uv.lock") and "-diff" in line for line in lines)


def test_no_tracked_file_has_crlf_outside_the_exempt_paths() -> None:
    offenders = []
    for line in git("ls-files", "--eol").splitlines():
        information, _, path = line.partition("\t")
        if information.split()[0] in BAD_INDEX_ENDINGS and not is_exempt(path):
            offenders.append(line)
    assert offenders == []


def test_text_attribute_of_exempt_and_ordinary_paths() -> None:
    output = git(
        "check-attr", "text", "--",
        "fixtures/x.py", "tests/unit/golden/x.txt", "tests/fixtures/config/x.toml",
        "fixtures/kavachbank/README.md", "src/codekavach/__init__.py",
    )  # fmt: skip
    values = dict(line.rsplit(": text: ", 1) for line in output.splitlines())
    assert values == {
        "fixtures/x.py": "unset",
        "tests/unit/golden/x.txt": "unset",
        "tests/fixtures/config/x.toml": "unset",
        "fixtures/kavachbank/README.md": "unset",
        "src/codekavach/__init__.py": "auto",
    }


def test_exemption_matches_the_precommit_exclusion() -> None:
    """The hook exclusion is ``^(fixtures/|tests/.*/golden/|tests/fixtures/)``."""
    assert is_exempt("fixtures/kavachbank/app.py")
    assert is_exempt("tests/unit/cli/golden/scan.txt")
    assert is_exempt("tests/fixtures/config/a.toml")
    assert not is_exempt("tests/unit/cli/test_scan.py")
    assert not is_exempt("src/codekavach/golden/x.py")
