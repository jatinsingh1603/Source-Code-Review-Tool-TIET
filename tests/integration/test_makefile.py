import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"
MAKE = shutil.which("make")
REQUIRED_TARGETS = (
    "help",
    "setup",
    "fmt",
    "fmt-check",
    "lint",
    "type",
    "contracts",
    "test",
    "test-unit",
    "test-integration",
    "test-e2e",
    "test-privacy",
    "cov",
    "check",
    "lock-check",
    "build",
    "adr",
    "clean",
    "hooks",
    "hooks-update",
    "prepush",
)

needs_make = pytest.mark.skipif(MAKE is None, reason="make is not on PATH")


def _make(*args: str) -> str:
    assert MAKE is not None
    result = subprocess.run(
        [MAKE, "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@needs_make
def test_help_lists_every_target() -> None:
    output = _make("help")
    for target in REQUIRED_TARGETS:
        assert re.search(rf"^\s+{re.escape(target)}\s", output, re.MULTILINE), target


@needs_make
def test_check_runs_gates_in_order() -> None:
    output = _make("-n", "check")
    gates = ["ruff format --check", "ruff check", "mypy", "lint-imports", "pytest"]
    positions = [output.index(gate) for gate in gates]
    assert positions == sorted(positions)


@needs_make
def test_prepush_shows_its_six_parts_in_the_documented_order() -> None:
    output = _make("-n", "prepush")
    parts = [
        "ruff format --check",  # check
        "pre-commit run --all-files",  # hooks
        "tools/dev/check_docs.py",  # docs-check
        "tools/dev/check_changelog_fragments.py",  # changelog-check
        "tools/dev/check_licences.py",  # licences
        "tools/dev/check_no_telemetry.py",  # telemetry-check
    ]
    positions = [output.index(part) for part in parts]
    assert positions == sorted(positions)
    assert len(set(positions)) == len(parts)
    assert output.index("pytest") < positions[1]  # check ends with the tests, hooks come after


def test_prepush_names_exactly_the_documented_targets_in_order() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    line = re.search(r"^prepush:([^#\n]*?)\s*##", text, re.MULTILINE)
    assert line is not None
    assert line.group(1).split() == [
        "check",
        "hooks",
        "docs-check",
        "changelog-check",
        "licences",
        "telemetry-check",
    ]
    assert re.search(r"^\.NOTPARALLEL:", text, re.MULTILINE)


def test_agents_md_names_prepush_in_its_checklist() -> None:
    agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    quality = next(line for line in agents.splitlines() if line.startswith("7. **Quality.**"))
    assert "make prepush" in quality


@needs_make
def test_clean_never_touches_client_data() -> None:
    output = _make("-n", "clean")
    for protected in (".venv", ".codekavach", "vault", "ledger"):
        assert protected not in output


def test_every_phony_target_is_documented() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    phony_block = re.search(r"^\.PHONY:((?:.*\\\n)*.*)$", text, re.MULTILINE)
    assert phony_block is not None
    phony = phony_block.group(1).replace("\\\n", " ").split()
    assert set(REQUIRED_TARGETS) <= set(phony)
    for target in phony:
        assert re.search(rf"^{re.escape(target)}:.*## \S", text, re.MULTILINE), target
