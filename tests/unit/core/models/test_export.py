import json
from pathlib import Path
from typing import ClassVar

import pytest

from codekavach.core.models import VersionedModel, export
from codekavach.core.models.export import (
    EXPORTED_MODELS,
    HINT,
    INDEX_FILE,
    build_schemas,
    check_schemas,
    export_schemas,
    main,
    snake_name,
)
from codekavach.core.models.location import Location
from codekavach.core.models.migrate import register_migration, temporary_registry

REPO_ROOT = Path(__file__).resolve().parents[4]
FORBIDDEN_PAYLOAD_NAMES = {"path", "original", "value"}


def test_build_is_deterministic() -> None:
    assert build_schemas() == build_schemas()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("LLMVerdict", "llm_verdict"),
        ("CodeSlice", "code_slice"),
        ("EgressRecord", "egress_record"),
        ("ScanSummary", "scan_summary"),
        ("Location", "location"),
    ],
)
def test_snake_name(name: str, expected: str) -> None:
    assert snake_name(name) == expected


def test_fourteen_schema_files_and_index() -> None:
    files = build_schemas()
    schema_files = [name for name in files if name.endswith(".schema.json")]
    assert len(schema_files) == 14
    index = json.loads(files[INDEX_FILE])["models"]
    assert [entry["name"] for entry in index] == sorted(entry["name"] for entry in index)
    assert {entry["file"] for entry in index} == set(schema_files)


def test_files_are_valid_and_described() -> None:
    for name, content in build_schemas().items():
        assert content.endswith("\n")
        data = json.loads(content)
        if name == INDEX_FILE:
            continue
        assert data["$schema"].endswith("2020-12/schema")
        assert data["$id"].startswith("urn:codekavach:schema:")
        assert data["description"], name
        assert data["x-data-classification"] in {"raw", "sanitised", "untrusted", "metadata"}


def test_id_matches_schema_version() -> None:
    files = build_schemas()
    for model in EXPORTED_MODELS:
        data = json.loads(files[f"{snake_name(model.__name__)}.schema.json"])
        version = data.get("x-schema-version", 0)
        assert data["$id"] == f"urn:codekavach:schema:{snake_name(model.__name__)}:{version}"


def test_privacy_relevant_contents() -> None:
    files = build_schemas()
    code_slice = json.loads(files["code_slice.schema.json"])
    assert code_slice["$defs"]["SliceSegment"]["properties"]["text"]["type"] == "string"
    payload = json.loads(files["sanitised_payload.schema.json"])
    assert payload["x-data-classification"] == "sanitised"
    names: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            names.update(node.get("properties", {}))
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(payload)
    assert not names & FORBIDDEN_PAYLOAD_NAMES
    assert json.loads(files["finding.schema.json"])["x-data-classification"] == "raw"


def test_no_untyped_fields() -> None:
    for name, content in build_schemas().items():
        assert ": {}" not in content, name


def test_check_states(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    assert check_schemas(tmp_path) == []
    (tmp_path / "finding.schema.json").write_text("{}\n", encoding="utf-8")
    assert "stale: finding.schema.json" in check_schemas(tmp_path)
    (tmp_path / "scan.schema.json").unlink()
    assert "missing: scan.schema.json" in check_schemas(tmp_path)
    (tmp_path / "foo.schema.json").write_text("{}\n", encoding="utf-8")
    assert "unexpected: foo.schema.json" in check_schemas(tmp_path)


def test_check_never_writes(tmp_path: Path) -> None:
    assert main(["--check", "--out", str(tmp_path / "empty")]) == 1
    assert not (tmp_path / "empty").exists()


def test_main_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--out", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["--check", "--out", str(tmp_path)]) == 0
    (tmp_path / "index.json").write_text("{}\n", encoding="utf-8")
    assert main(["--check", "--out", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "stale: index.json" in output
    assert HINT in output


def test_export_is_idempotent(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    first = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    export_schemas(tmp_path)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == first
    assert all(b"\r\n" not in content for content in first.values())


def test_repository_schemas_are_up_to_date() -> None:
    problems = check_schemas(REPO_ROOT / "docs" / "schemas")
    assert problems == [], f"{problems}; {export.HINT}"


# drift and migration checks (E02-23)


class LocationWithExtra(Location):
    extra_note: str | None = None


class Bumped(VersionedModel):
    SCHEMA_VERSION: ClassVar[int] = 2


def _swap_location(monkeypatch: pytest.MonkeyPatch) -> None:
    models = tuple(LocationWithExtra if m is Location else m for m in EXPORTED_MODELS)
    LocationWithExtra.__name__ = "Location"
    monkeypatch.setattr(export, "EXPORTED_MODELS", models)


def test_drift_with_extra_location_field(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    _swap_location(monkeypatch)
    assert main(["--check", "--out", str(REPO_ROOT / "docs" / "schemas")]) == 1
    output = capsys.readouterr().out
    assert "stale: location.schema.json" in output
    assert HINT in output
    assert "::error" not in output


def test_check_migrations_exit_codes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert main(["--check-migrations"]) == 0
    monkeypatch.setattr(export, "EXPORTED_MODELS", (*EXPORTED_MODELS, Bumped))
    assert main(["--check-migrations"]) == 1
    output = capsys.readouterr().out
    assert "Bumped: missing migration step 1 -> 2" in output
    with temporary_registry():
        register_migration(Bumped, 1)(lambda data: data)
        assert main(["--check-migrations"]) == 0


def test_both_checks_report_both_problems(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    _swap_location(monkeypatch)
    monkeypatch.setattr(export, "EXPORTED_MODELS", (*export.EXPORTED_MODELS, Bumped))
    out = str(REPO_ROOT / "docs" / "schemas")
    assert main(["--check", "--check-migrations", "--out", out]) == 1
    output = capsys.readouterr().out
    assert "location.schema.json" in output
    assert "1 -> 2" in output


def test_github_annotations(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(export, "EXPORTED_MODELS", (*EXPORTED_MODELS, Bumped))
    main(["--out", str(tmp_path)])
    capsys.readouterr()
    (tmp_path / "location.schema.json").write_text("{}\n", encoding="utf-8")
    assert main(["--check", "--check-migrations", "--out", str(tmp_path)]) == 1
    lines = capsys.readouterr().out.splitlines()
    location = f"::error file={(tmp_path / 'location.schema.json').as_posix()}::schema is stale"
    assert any(line.startswith(location) for line in lines)
    assert any(line.startswith("::error::") and "1 -> 2" in line for line in lines)
