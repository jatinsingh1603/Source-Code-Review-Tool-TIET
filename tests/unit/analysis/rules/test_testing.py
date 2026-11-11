"""Fixture annotations, ``run_rule_tests`` and ``codekavach rules test`` (E16-02)."""

from pathlib import Path

import pytest

from codekavach.analysis.rules.loader import default_rules_root, load_pack, scan_pack
from codekavach.analysis.rules.matcher import Matcher
from codekavach.analysis.rules.pack import RulePack
from codekavach.analysis.rules.testing import (
    annotations_of,
    comment_token,
    fixture_path,
    run_rule_tests,
    update_fixture,
)
from tests.support.cli_fixtures import Cli
from tests.support.rule_files import write_pack

RULE = "python.sqli.cursor-execute-concat"
NL = chr(10)
FIXTURE = NL.join(
    [
        "def find(owner, cur):",
        f"    # ruleid: {RULE}",
        '    cur.execute("SELECT 1 WHERE a = \'" + owner + "\'")',
        f"    # ok: {RULE}",
        '    cur.execute("SELECT 1 WHERE a = ?", (owner,))',
        "",
    ]
)


def pack_at(tmp_path: Path) -> RulePack:
    directory = write_pack(tmp_path / "rules")
    return load_pack(directory)


def write_fixture(root: Path, text: str) -> Path:
    path = fixture_path(root, "python", RULE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline=NL)
    return path


def test_annotations_refer_to_the_next_non_comment_line() -> None:
    text = NL.join(
        [
            f"# ruleid: {RULE}",
            "# a note",
            "",
            "x = 1",
            f"# ok: {RULE}",
            "y = 2",
            "# todoruleid: other",
        ]
    )
    notes = annotations_of(text, RULE)
    assert (notes.ruleid, notes.ok, notes.todo) == (frozenset({4}), frozenset({6}), frozenset())


@pytest.mark.parametrize(
    ("language", "token"), [("python", "#"), ("javascript", "//"), ("sql", "--"), ("go", "//")]
)
def test_the_comment_token_follows_the_language(language: str, token: str) -> None:
    assert comment_token(language) == token


def test_a_matching_fixture_passes(tmp_path: Path) -> None:
    write_fixture(tmp_path / "fx", FIXTURE)
    report = run_rule_tests([pack_at(tmp_path)], tmp_path / "fx")
    assert report.passed
    assert [(r.rule_id, r.language) for r in report.results] == [(RULE, "python")]


def test_a_removed_annotation_is_an_unexpected_match(tmp_path: Path) -> None:
    write_fixture(tmp_path / "fx", FIXTURE.replace(f"    # ruleid: {RULE}{NL}", ""))
    (result,) = run_rule_tests([pack_at(tmp_path)], tmp_path / "fx").results
    assert not result.passed and result.unexpected == (2,)


def test_an_expected_match_that_is_absent_is_reported(tmp_path: Path) -> None:
    text = FIXTURE + f"# ruleid: {RULE}{NL}x = 1{NL}"
    write_fixture(tmp_path / "fx", text)
    (result,) = run_rule_tests([pack_at(tmp_path)], tmp_path / "fx").results
    assert result.missing == (7,)


def test_a_todo_annotation_is_counted_and_never_fails(tmp_path: Path) -> None:
    text = FIXTURE + f"# todoruleid: {RULE}{NL}x = 1{NL}"
    write_fixture(tmp_path / "fx", text)
    report = run_rule_tests([pack_at(tmp_path)], tmp_path / "fx")
    assert report.passed and report.known_gaps == 1


def test_a_missing_fixture_fails(tmp_path: Path) -> None:
    (result,) = run_rule_tests([pack_at(tmp_path)], tmp_path / "nowhere").results
    assert not result.passed and result.problem == "no fixture"


def test_pack_and_rule_filters_select_rules(tmp_path: Path) -> None:
    packs = [pack_at(tmp_path)]
    assert run_rule_tests(packs, tmp_path, pack_id="other").results == []
    assert run_rule_tests(packs, tmp_path, rule_id="python.other.rule").results == []


def test_update_adds_missing_annotations_and_turns_stale_ones_into_todos(tmp_path: Path) -> None:
    root = tmp_path / "fx"
    stale = FIXTURE.replace(f"    # ruleid: {RULE}{NL}", "") + f"# ruleid: {RULE}{NL}x = 1{NL}"
    path = write_fixture(root, stale)
    pack = pack_at(tmp_path)
    matcher, _ = Matcher.for_packs([pack])
    assert update_fixture(matcher, pack.rules[0], "python", root) is True
    text = path.read_text(encoding="utf-8")
    assert f"    # ruleid: {RULE}" in text and f"# todoruleid: {RULE}" in text
    assert run_rule_tests([pack], root).passed
    assert update_fixture(matcher, pack.rules[0], "python", root) is False


def project_for_cli(tmp_path: Path) -> tuple[Path, list[str]]:
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    write_pack(project / "extra")
    path = (project / "extra" / "mit").as_posix()
    options = [
        "--set", f"engines.rule_paths=['{path}']", "--set", "engines.rule_packs=[]",
    ]  # fmt: skip
    return project, options


def test_the_command_exits_zero_on_good_fixtures_and_names_the_line_otherwise(
    cli: Cli, tmp_path: Path
) -> None:
    project, options = project_for_cli(tmp_path)
    root = project / "fixtures"
    path = write_fixture(root, FIXTURE)
    args = ["rules", "test", "--fixtures", str(root), *options]
    good = cli(args, cwd=project)
    assert good.exit_code == 0, good.stderr
    assert "PASS" in good.stdout
    path.write_text(FIXTURE.replace(f"    # ruleid: {RULE}{NL}", ""), encoding="utf-8")
    bad = cli(args, cwd=project)
    assert bad.exit_code != 0
    assert f"python/{RULE}.py:2: unexpected match" in bad.stdout


def test_update_is_refused_in_ci(cli: Cli, tmp_path: Path) -> None:
    project, options = project_for_cli(tmp_path)
    result = cli(["rules", "test", "--update", *options], cwd=project, env={"CI": "true"})
    assert result.exit_code == 2
    assert "update_in_ci" in result.stderr + result.stdout


def test_a_known_gap_is_reported_but_exits_zero(cli: Cli, tmp_path: Path) -> None:
    project, options = project_for_cli(tmp_path)
    root = project / "fixtures"
    write_fixture(root, FIXTURE + f"# todoruleid: {RULE}{NL}x = 1{NL}")
    result = cli(["rules", "test", "--fixtures", str(root), *options, "--json"], cwd=project)
    assert result.exit_code == 0, result.stderr
    assert result.json["data"]["known_gaps"] == 1


def test_the_shipped_fixtures_pass() -> None:
    root = default_rules_root()
    assert root is not None
    pack = scan_pack(root / "mit" / "packs" / "default", check_patterns=True)
    assert pack.pack is not None and not pack.issues
    fixtures = root.parent / "tests" / "fixtures" / "rules"
    assert run_rule_tests([pack.pack], fixtures).passed
