"""``codekavach privacy terms suggest`` over a real scan (E08-04)."""

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.support.cli import CliResult

Cli = Callable[..., CliResult]

BILLING = "".join(
    f"def accrual_rate_{i}(mandate, value):\n"
    "    accrual = value * mandate\n"
    "    return accrual + value\n\n"
    for i in range(6)
)
HANDLER = (
    "def handler(request):\n"
    "    print(request.args, request.headers)\n"
    "    return isinstance(request, dict) and len(request)\n"
) * 4


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "billing.py").write_bytes(BILLING.encode())
    (root / "handler.py").write_bytes(HANDLER.encode())
    return root


@pytest.fixture
def scanned(cli: Cli, repo: Path) -> Path:
    assert cli(["scan", str(repo), "--profile", "demo"]).exit_code == 0
    return repo


def suggestion_file(repo: Path) -> Path:
    (found,) = (repo / ".codekavach" / "suggestions").glob("domain-terms-*.txt")
    return found


def terms_in(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


def test_domain_words_are_written_to_the_state_directory_and_nothing_takes_effect(
    cli: Cli, scanned: Path
) -> None:
    result = cli(["privacy", "terms", "suggest", str(scanned)])
    assert result.exit_code == 0, result.stderr
    assert "none is in effect" in result.stdout
    assert "accrual" in result.stdout and "mandate" in result.stdout
    written = suggestion_file(scanned)
    assert {"accrual", "mandate"} <= set(terms_in(written))
    assert "do not commit" in written.read_text(encoding="utf-8")
    assert not (scanned / "codekavach.toml").exists()


def test_common_words_keywords_builtins_and_public_names_are_not_suggested(
    cli: Cli, scanned: Path
) -> None:
    cli(["privacy", "terms", "suggest", str(scanned)])
    suggested = set(terms_in(suggestion_file(scanned)))
    assert not suggested & {"request", "print", "isinstance", "return", "args", "headers", "dict"}


def test_json_output_carries_counts_and_a_path_but_no_word(cli: Cli, scanned: Path) -> None:
    result = cli(["privacy", "terms", "suggest", str(scanned), "--json"])
    assert result.exit_code == 0
    data = result.json["data"]
    assert data["applied"] is False and data["suggested"] >= 2 and data["files_examined"] == 2
    assert Path(data["file"]) == suggestion_file(scanned)
    assert "accrual" not in result.stdout and "mandate" not in result.stdout


def test_a_term_that_is_already_configured_is_not_suggested_again(cli: Cli, scanned: Path) -> None:
    (scanned / "codekavach.toml").write_text('[privacy]\ndomain_terms = ["Accrual"]\n')
    result = cli(["privacy", "terms", "suggest", str(scanned)])
    assert result.exit_code == 0, result.stderr
    suggested = set(terms_in(suggestion_file(scanned)))
    assert "accrual" not in suggested and "mandate" in suggested


def test_the_command_changes_no_setting_and_no_project_file(cli: Cli, scanned: Path) -> None:
    before = sorted(
        p.relative_to(scanned).as_posix()
        for p in scanned.rglob("*")
        if ".codekavach" not in p.parts
    )
    cli(["privacy", "terms", "suggest", str(scanned)])
    after = sorted(
        p.relative_to(scanned).as_posix()
        for p in scanned.rglob("*")
        if ".codekavach" not in p.parts
    )
    assert before == after


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_the_suggestion_file_is_private(cli: Cli, scanned: Path) -> None:
    cli(["privacy", "terms", "suggest", str(scanned)])
    mode = suggestion_file(scanned).stat().st_mode & 0o777
    assert mode & 0o077 == 0


def test_without_a_scan_the_command_asks_for_one(cli: Cli, repo: Path) -> None:
    result = cli(["privacy", "terms", "suggest", str(repo)])
    assert result.exit_code != 0
    assert "scan_not_found" in result.stderr or "no stored scan" in result.stderr


def test_a_limit_below_one_is_a_usage_error(cli: Cli, scanned: Path) -> None:
    assert cli(["privacy", "terms", "suggest", str(scanned), "--limit", "0"]).exit_code != 0


def test_the_help_says_that_nothing_is_redacted_until_a_person_copies_a_term(cli: Cli) -> None:
    text = " ".join(cli(["privacy", "terms", "suggest", "--help"]).stdout.split())
    assert "Nothing is redacted" in text and "privacy.domain_terms" in text
