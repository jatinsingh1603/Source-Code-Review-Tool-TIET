"""``codekavach rules`` and the generated schemas (E16-01)."""

import json
from pathlib import Path

import pytest

from codekavach.analysis.rules import schema
from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.loader import load_pack
from codekavach.analysis.rules.pack import PackManifest
from tests.support.cli_fixtures import Cli
from tests.support.rule_files import rule_text, write_pack

ROOT = Path(__file__).resolve().parents[4]


def project_with_pack(tmp_path: Path, **pack_options: object) -> Path:
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    write_pack(project / "extra", **pack_options)  # type: ignore[arg-type]
    return project


def config_for(project: Path, *, rules: bool = True) -> list[str]:
    path = project / "extra" / "mit"
    return [
        "--set",
        f"engines.rule_paths=['{path.as_posix()}']",
        "--set",
        "engines.rule_packs=[]",
        "--set",
        f"engines.native.rules={'true' if rules else 'false'}",
    ]


def test_list_json_has_one_row_per_rule_with_pack_version_languages_and_cwe(
    cli: Cli, tmp_path: Path
) -> None:
    project = project_with_pack(tmp_path)
    result = cli(["rules", "list", "--json", *config_for(project)], cwd=project)
    assert result.exit_code == 0, result.stderr
    envelope = result.json
    assert envelope["schema_version"] == "1" and envelope["command"] == "rules list"
    (row,) = envelope["data"]["rules"]
    assert row == {
        "id": "python.sqli.cursor-execute-concat",
        "pack": "default",
        "version": "1.0.0",
        "languages": ["python"],
        "cwe": [89],
        "severity": "high",
        "confidence": "medium",
    }


def test_list_with_native_rules_off_reports_zero_rules_and_succeeds(
    cli: Cli, tmp_path: Path
) -> None:
    project = project_with_pack(tmp_path)
    result = cli(["rules", "list", "--json", *config_for(project, rules=False)], cwd=project)
    assert result.exit_code == 0, result.stderr
    assert result.json["data"] == {"rules": [], "count": 0}
    assert result.json["warnings"][0]["code"] == "native_rules_off"


def test_show_prints_the_rule_and_an_unknown_id_is_a_usage_error(cli: Cli, tmp_path: Path) -> None:
    project = project_with_pack(tmp_path)
    shown = cli(
        ["rules", "show", "python.sqli.cursor-execute-concat", "--json", *config_for(project)],
        cwd=project,
    )
    assert shown.exit_code == 0, shown.stderr
    assert shown.json["data"]["rule"]["metadata"]["cwe"] == [89]
    missing = cli(["rules", "show", "python.no.such", "--json", *config_for(project)], cwd=project)
    assert missing.exit_code == 2
    assert missing.json["errors"][0]["code"] == "rule_not_found"


def test_validate_exits_0_on_the_shipped_tree() -> None:
    assert schema.SCHEMA_DIR.is_dir()
    from tests.support.cli import run_cli  # noqa: PLC0415

    result = run_cli(["rules", "validate", str(ROOT / "rules" / "mit"), "--json"], home=ROOT)
    assert result.exit_code == 0, result.stderr
    assert result.json["data"]["packs"][0]["issues"] == 0


def test_validate_exits_2_on_a_planted_invalid_rule_and_names_path_and_code(
    cli: Cli, tmp_path: Path
) -> None:
    bad = rule_text(id="python.x.nocwe", metadata={"licence": "MIT"})
    project = project_with_pack(tmp_path, rules={"good.yaml": rule_text(), "bad.yaml": bad})
    result = cli(["rules", "validate", str(project / "extra"), "--json"], cwd=project)
    assert result.exit_code == 2
    (problem,) = result.json["data"]["problems"]
    assert problem["code"] == "CK-RULE-008" and problem["path"].endswith("bad.yaml")
    human = cli(["rules", "validate", str(project / "extra")], cwd=project)
    assert "CK-RULE-008" in human.stdout and "bad.yaml" in human.stdout


def test_validate_without_a_pack_is_a_usage_error(cli: Cli, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli(["rules", "validate", str(empty)], cwd=empty).exit_code == 2


def test_bundle_is_byte_identical_on_two_runs_and_loadable(cli: Cli, tmp_path: Path) -> None:
    project = project_with_pack(tmp_path)
    first, second = tmp_path / "a.ckrules", tmp_path / "b.ckrules"
    for out in (first, second):
        result = cli(
            ["rules", "bundle", "--out", str(out), "--json", *config_for(project)], cwd=project
        )
        assert result.exit_code == 0, result.stderr
    assert first.read_bytes() == second.read_bytes()
    listed = cli(
        [
            "rules",
            "list",
            "--json",
            "--set",
            f"engines.rule_paths=['{first.as_posix()}']",
            "--set",
            "engines.rule_packs=[]",
        ],
        cwd=project,
    )
    assert listed.json["data"]["count"] == 1


def test_bundle_with_no_pack_is_a_usage_error(cli: Cli, tmp_path: Path) -> None:
    project = tmp_path / "p"
    (project / ".git").mkdir(parents=True)
    result = cli(
        ["rules", "bundle", "--out", str(tmp_path / "x.ckrules"), "--set", "engines.rule_packs=[]"],
        cwd=project,
    )
    assert result.exit_code == 2


def test_the_group_help_lists_the_four_commands(cli: Cli, tmp_path: Path) -> None:
    result = cli(["rules", "--help"], cwd=tmp_path)
    assert result.exit_code == 0
    for name in ("list", "show", "validate", "bundle"):
        assert name in result.stdout


# --- schemas ---------------------------------------------------------------------------------


def test_the_generated_schemas_and_reference_are_current() -> None:
    assert schema.check() == []


def test_a_renamed_model_field_makes_the_drift_check_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import create_model  # noqa: PLC0415

    renamed = create_model("PackManifest", __base__=PackManifest, identifier=(str, "x"))
    monkeypatch.setitem(schema.SCHEMAS, "pack", renamed)
    assert any("pack.schema.json" in item for item in schema.check())


def test_every_model_field_has_a_note_in_the_reference() -> None:
    for model in schema.REFERENCE_MODELS:
        for name in model.model_fields:
            assert f"{model.__name__}.{name}" in schema.FIELD_NOTES, (model.__name__, name)


def test_the_published_rule_schema_validates_the_example() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    document = json.loads((schema.SCHEMA_DIR / "rule.schema.json").read_text(encoding="utf-8"))
    example = RuleDef.model_validate(__import__("yaml").safe_load(schema.EXAMPLE)).model_dump(
        mode="json"
    )
    jsonschema.validate(example, document)
    assert load_pack(ROOT / "rules" / "mit" / "packs" / "default").rules
