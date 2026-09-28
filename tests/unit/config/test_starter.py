import re
import tomllib
from pathlib import Path

import pytest
from pydantic import BaseModel

from codekavach.config import Settings
from codekavach.config.constants import SCHEMA_ID
from codekavach.config.introspect import iter_fields
from codekavach.config.plaintext import find_plaintext_secrets
from codekavach.config.starter import render_starter, uncomment_defaults
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).resolve().parents[2] / "golden" / "config"
REFERENCE = re.compile(r'^"(env:|keyring:|file:)')


def descriptions(model: type[BaseModel]) -> set[str]:
    """Every field description of the model tree, entry models of maps and lists included."""
    found: set[str] = set()
    for ref in iter_fields(model):
        if ref.field.description:
            found.add(ref.field.description)
    stack: list[type[BaseModel]] = [model]
    while stack:
        current = stack.pop()
        for field in current.model_fields.values():
            if field.description:
                found.add(field.description)
            stack.extend(_models(field.annotation))
    return found


def _models(annotation: object) -> list[type[BaseModel]]:
    from typing import get_args  # noqa: PLC0415

    result = []
    pending = [annotation]
    while pending:
        item = pending.pop()
        if isinstance(item, type) and issubclass(item, BaseModel):
            result.append(item)
        pending.extend(get_args(item))
    return result


@pytest.mark.parametrize(
    ("name", "kwargs"),
    [
        ("starter_full.toml", {"project_name": "payments-api"}),
        ("starter_minimal.toml", {"project_name": "payments-api", "minimal": True}),
        ("starter_profile_demo.toml", {"project_name": "payments-api", "profile": "demo"}),
    ],
)
def test_goldens(name: str, kwargs: dict[str, object]) -> None:
    assert_matches_golden(render_starter(**kwargs), GOLDEN / name)  # type: ignore[arg-type]


def _prune(value: object) -> object:
    if isinstance(value, dict):
        pruned = {k: _prune(v) for k, v in value.items()}
        return {k: v for k, v in pruned.items() if v != {}}
    return value


def test_starter_parses_and_validates() -> None:
    text = render_starter(project_name="payments-api", profile="demo")
    assert _prune(tomllib.loads(text)) == {
        "config_version": 1,
        "profile": "demo",
        "project": {"name": "payments-api"},
        "privacy": {"level": "L3"},
    }
    assert text.startswith(f"#:schema {SCHEMA_ID}\n")


def test_drift_uncommented_defaults_equal_settings() -> None:
    text = render_starter(project_name="payments-api")
    settings = Settings.model_validate(tomllib.loads(uncomment_defaults(text)))
    assert settings.project.name == "payments-api"
    assert settings.model_copy(update={"project": Settings().project}) == Settings()


def test_every_description_appears() -> None:
    text = render_starter(project_name="p")
    missing = sorted(d for d in descriptions(Settings) if d not in text)
    assert missing == []


def test_no_plaintext_secret_and_only_references() -> None:
    text = render_starter(project_name="p")
    for variant in (text, uncomment_defaults(text)):
        data = tomllib.loads(variant)
        assert find_plaintext_secrets(data, source="starter", text=variant) == []
    for line in text.split("\n"):
        match = re.match(r"^#?[?]? ?(api_key|token|passphrase) = (.*)$", line)
        if match:
            assert REFERENCE.match(match.group(2)), line


def test_minimal_has_only_active_lines() -> None:
    text = render_starter(project_name="p", minimal=True)
    body = [line for line in text.split("\n") if line and not line.startswith("#")]
    assert body == ["config_version = 1", "[project]", 'name = "p"', "[privacy]", 'level = "L3"']
