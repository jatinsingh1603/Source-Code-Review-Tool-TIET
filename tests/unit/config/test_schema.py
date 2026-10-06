"""JSON Schemas of codekavach.toml and policy.toml (E03-38)."""

import json
import tomllib
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from codekavach.config.constants import POLICY_SCHEMA_ID, SCHEMA_ID
from codekavach.config.profiles import BUILTIN_PROFILES, load_builtin_profile
from codekavach.config.schema import (
    JSON_SCHEMA_DIALECT,
    PARTIAL_SETTINGS,
    dump_schema,
    policy_schema,
    settings_schema,
)
from codekavach.config.starter import render_starter
from tests.support.cli import run_cli

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = sorted((REPO_ROOT / "docs" / "examples").glob("policy.*.toml"))
SETTINGS = settings_schema()
POLICY = policy_schema()


def properties_without_description(schema: dict[str, Any]) -> list[str]:
    missing: list[str] = []

    def walk(node: Any, where: str) -> None:
        if isinstance(node, dict):
            for name, value in (node.get("properties") or {}).items():
                if not (isinstance(value, dict) and value.get("description")):
                    missing.append(f"{where}/{name}")
            for key, value in node.items():
                walk(value, f"{where}/{key}")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{where}/{index}")

    walk(schema, "")
    return missing


@pytest.mark.parametrize(
    ("schema", "schema_id"), [(SETTINGS, SCHEMA_ID), (POLICY, POLICY_SCHEMA_ID)]
)
def test_meta_schema_and_identity(schema: dict[str, Any], schema_id: str) -> None:
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == JSON_SCHEMA_DIALECT
    assert schema["$id"] == schema_id
    assert schema["title"]
    assert schema["description"]


@pytest.mark.parametrize("schema", [SETTINGS, POLICY], ids=["settings", "policy"])
def test_every_property_has_a_description(schema: dict[str, Any]) -> None:
    assert properties_without_description(schema) == []


def test_extension_keywords_are_kept() -> None:
    privacy = SETTINGS["$defs"]["PrivacySettings"]["properties"]
    assert privacy["domain_terms"].get("x-ck-sensitive") is True
    assert SETTINGS["properties"]["integrations"].get("x-ck-restricted") is True


def test_no_environment_settings_leak() -> None:
    text = dump_schema(SETTINGS)
    assert "env_prefix" not in text
    assert "env_nested_delimiter" not in text


def errors(schema: dict[str, Any], document: Any) -> list[str]:
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def test_valid_and_invalid_settings() -> None:
    assert errors(SETTINGS, {"privacy": {"level": "L3"}}) == []
    assert errors(SETTINGS, {"privacy": {"level": "L9"}})
    assert errors(SETTINGS, {"privacy": {"no_such_key": 1}})
    assert errors(SETTINGS, {"no_such_section": {}})


@pytest.mark.parametrize("name", sorted(BUILTIN_PROFILES))
def test_builtin_profiles_validate(name: str) -> None:
    partial = SETTINGS["$defs"][PARTIAL_SETTINGS]
    document = load_builtin_profile(name)
    assert errors({**SETTINGS, **partial}, document) == []
    assert errors(SETTINGS, {"profiles": {name: document}}) == []


def test_profiles_accept_extends_and_description_but_no_unknown_key() -> None:
    profile = {"extends": "ci", "description": "Nightly.", "scan": {"jobs": 2}}
    assert errors(SETTINGS, {"profiles": {"nightly": profile}}) == []
    assert errors(SETTINGS, {"profiles": {"nightly": {"bogus": 1}}})


@pytest.mark.parametrize(
    "variant",
    [{}, {"minimal": True}, {"profile": "demo"}],
    ids=["full", "minimal", "demo"],
)
def test_starter_variants_validate(variant: dict[str, Any]) -> None:
    document = tomllib.loads(render_starter(**variant))
    assert errors(SETTINGS, document) == []


@pytest.mark.parametrize("path", EXAMPLES, ids=[path.name for path in EXAMPLES])
def test_policy_examples_validate(path: Path) -> None:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    assert errors(POLICY, json.loads(json.dumps(document, default=str))) == []


def test_invalid_policy_fails() -> None:
    assert errors(POLICY, {"policy_version": 1, "organisation": "X", "enforcement": "sometimes"})
    assert errors(POLICY, {"organisation": "X"})  # policy_version is required


@pytest.mark.parametrize("args", [[], ["--policy"]], ids=["settings", "policy"])
def test_cli_output_and_file_are_the_same_bytes(args: list[str], tmp_path: Path) -> None:
    printed = run_cli(["config", "schema", *args])
    assert printed.exit_code == 0, printed.stderr
    target = tmp_path / "schema.json"
    written = run_cli(["config", "schema", *args, "--output", str(target)])
    assert written.exit_code == 0, written.stderr
    assert target.read_bytes() == printed.stdout.encode("utf-8")
    assert json.loads(printed.stdout)["$id"] == (POLICY_SCHEMA_ID if args else SCHEMA_ID)
