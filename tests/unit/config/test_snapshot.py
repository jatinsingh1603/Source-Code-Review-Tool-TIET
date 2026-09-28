import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import NoneType, UnionType
from typing import Annotated, Any, Literal, Union, get_args, get_origin

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.introspect import has_marker, iter_fields
from codekavach.config.merge import deep_merge
from codekavach.config.plaintext import SECRET_KEY_NAME, find_plaintext_secrets
from codekavach.config.snapshot import (
    DEFAULT_SECTIONS,
    SECRET_REFERENCE_FIELDS,
    build_snapshot,
    canonical_json,
    read_snapshot,
    settings_fingerprint,
    write_snapshot,
)
from codekavach.core.models import PrivacyLevel
from tests.support.config import ConfigSandbox
from tests.support.config_strategies import settings_dicts
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).resolve().parents[2] / "golden" / "config"
DEFAULTS = Settings().model_dump(mode="json")
FIXED_NOW = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)


class Colour(Enum):
    RED = "red"


# canonical JSON


def test_canonical_json_edge_cases() -> None:
    data = {"b": [PurePosixPath("a/b"), PureWindowsPath("c\\d")], "a": {"z": Colour.RED, "y": 1.5}}
    assert canonical_json(data) == b'{"a":{"y":1.5,"z":"red"},"b":["a/b","c/d"]}'
    assert canonical_json({"k": "é"}) == b'{"k":"\\u00e9"}'


def test_union_lists_are_order_insensitive() -> None:
    globs = DEFAULTS["privacy"]["never_send"]
    forward = Settings.model_validate({"privacy": {"never_send": globs}})
    backward = Settings.model_validate({"privacy": {"never_send": list(reversed(globs))}})
    assert settings_fingerprint(forward) == settings_fingerprint(backward)
    ordered = Settings.model_validate({"scan": {"include": ["a/**", "b/**"]}})
    reordered = Settings.model_validate({"scan": {"include": ["b/**", "a/**"]}})
    assert settings_fingerprint(ordered) != settings_fingerprint(reordered)


def test_example_from_the_issue() -> None:
    base = settings_fingerprint(Settings())
    assert settings_fingerprint(Settings.model_validate({"scan": {"jobs": 16}})) == base
    assert settings_fingerprint(Settings.model_validate({"privacy": {"level": "L4"}})) != base
    terms = Settings.model_validate({"privacy": {"domain_terms": ["kavachbank"]}})
    assert settings_fingerprint(terms) != base


def test_secret_references_do_not_count() -> None:
    one = {
        "llm": {
            "providers": {
                # pragma: allowlist nextline secret
                "p": {"kind": "anthropic", "model": "m", "api_key": "env:A"}
            }
        }
    }
    two = deep_merge(one, {"llm": {"providers": {"p": {"api_key": "env:B"}}}})
    assert settings_fingerprint(Settings.model_validate(one)) == settings_fingerprint(
        Settings.model_validate(two)
    )
    url = deep_merge(one, {"llm": {"providers": {"p": {"base_url": "https://x.example.test/v1"}}}})
    assert settings_fingerprint(Settings.model_validate(url)) != settings_fingerprint(
        Settings.model_validate(one)
    )


def test_stable_across_processes() -> None:
    code = (
        "from codekavach.config import Settings\n"
        "from codekavach.config.snapshot import settings_fingerprint\n"
        "data = {'privacy': {'domain_terms': ['b', 'a'], 'never_send': ['z/**', 'y/**']}}\n"
        "print(settings_fingerprint(Settings.model_validate(data)))\n"
    )
    outputs = set()
    for seed in ("0", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        result = subprocess.run(
            [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
        )
        outputs.add(result.stdout.strip())
    assert len(outputs) == 1


# per-field sensitivity sweep


def _strip(annotation: Any) -> Any:
    while get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]
    if get_origin(annotation) in (Union, UnionType):
        members = [m for m in get_args(annotation) if m is not NoneType]
        return _strip(members[0]) if members else annotation
    return annotation


def _choices(annotation: Any) -> list[Any]:
    stripped = _strip(annotation)
    if get_origin(stripped) is Literal:
        return list(get_args(stripped))
    if isinstance(stripped, type) and issubclass(stripped, Enum):
        return [member.value for member in stripped]
    if get_origin(stripped) is Union or get_origin(stripped) is UnionType:
        return [c for member in get_args(stripped) for c in _choices(member)]
    return []


# Fields whose valid values cannot be derived from their type alone.
EXTRA_CANDIDATES: dict[str, list[Any]] = {
    "scan.stage_timeouts": [{"parse": 60}],
    "privacy.provider_tier_levels": [{"local": "L2", "private": "L2", "public": "L3"}],
    "privacy.public_allowlist_extra": [["PublicApiName"], ["public_api_name"]],
    "llm.default_provider": ["mock"],
    "engines.enabled": [["semgrep"]],
    "engines.disabled": [["semgrep"]],
}


def _candidates(value: Any, annotation: Any) -> list[Any]:
    choices = [c for c in _choices(annotation) if c != value]
    stripped = _strip(annotation)
    if isinstance(value, bool):
        return [not value]
    if isinstance(value, int):
        return [value + 1, value - 1]
    if isinstance(value, float):
        return [value + 0.5, value - 0.5]
    if isinstance(value, list):
        item_choices = _choices(get_args(stripped)[0]) if get_args(stripped) else []
        return (
            ([value[:-1]] if value else [])
            + [[c] for c in item_choices if [c] != value]
            + [["extra/**"]]
        )
    if value is None:
        return [*choices, "extra-value", 100, 10.0, True]
    return [*choices, f"{value}-changed"] if isinstance(value, str) else choices


def _swept_keys() -> list[Any]:
    refs = []
    for ref in iter_fields(Settings):
        if "*" in ref.key or "[]" in ref.key:
            continue
        if not any(ref.key == s or ref.key.startswith(f"{s}.") for s in DEFAULT_SECTIONS):
            continue
        if ref.key.rsplit(".", 1)[-1] in SECRET_REFERENCE_FIELDS:
            continue
        refs.append(ref)
    return refs


def _with(key: str, value: Any) -> dict[str, Any]:
    head, *rest = key.split(".")
    return {head: _with(".".join(rest), value) if rest else value}


def test_every_field_is_either_volatile_or_counted() -> None:
    base = settings_fingerprint(Settings())
    checked = 0
    swept = _swept_keys()
    for ref in swept:
        current: Any = DEFAULTS
        for part in ref.key.split("."):
            current = current[part]
        candidates = EXTRA_CANDIDATES.get(ref.key, []) + _candidates(current, ref.annotation)
        for candidate in candidates:
            try:
                mutated = Settings.model_validate(deep_merge(DEFAULTS, _with(ref.key, candidate)))
            except ValidationError:
                continue
            if mutated == Settings():
                continue
            changed = settings_fingerprint(mutated) != base
            assert changed is not has_marker(Settings, ref.key, "volatile"), ref.key
            checked += 1
            break
    assert checked == len(swept)  # every field of the included sections was exercised


# snapshot


def test_snapshot_hides_terms_and_round_trips(tmp_path: Path) -> None:
    sandbox = ConfigSandbox(tmp_path / "s")
    sandbox.write_user('[privacy]\ndomain_terms = ["kavachbank", "accrual"]\n')
    loaded = sandbox.load()
    snapshot = build_snapshot(loaded, codekavach_version="0.0.0", now=FIXED_NOW)
    path = tmp_path / "snapshot.json"
    write_snapshot(snapshot, path)
    text = path.read_text(encoding="utf-8")
    assert "kavachbank" not in text
    assert "accrual" not in text
    assert read_snapshot(path) == snapshot
    assert snapshot.fingerprint == settings_fingerprint(loaded.settings)


def test_snapshot_has_no_secret_keys_or_values(tmp_path: Path) -> None:
    sandbox = ConfigSandbox(tmp_path / "s")
    sandbox.write_user(
        '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'
        # pragma: allowlist nextline secret
        'api_key = "env:ANTHROPIC_API_KEY"\n'
    )
    snapshot = build_snapshot(sandbox.load(), codekavach_version="0.0.0", now=FIXED_NOW)
    dumped = snapshot.model_dump(mode="json")

    def keys(value: Any) -> list[str]:
        if isinstance(value, dict):
            return [k for key, item in value.items() for k in (str(key), *keys(item))]
        if isinstance(value, list):
            return [k for item in value for k in keys(item)]
        return []

    assert not [key for key in keys(dumped["settings"]) if SECRET_KEY_NAME.search(key)]
    assert not [key for key in dumped["origins"] if key.endswith(".api_key")]
    assert find_plaintext_secrets(dumped, source="snapshot", text=None) == []
    assert "ANTHROPIC_API_KEY" not in json.dumps(dumped)


def test_golden_demo_snapshot(tmp_path: Path) -> None:
    sandbox = ConfigSandbox(tmp_path / "s")
    sandbox.write_project('[project]\nname = "demo-project"\n')
    loaded = sandbox.load(profile="demo")
    snapshot = build_snapshot(loaded, codekavach_version="0.0.0-test", now=FIXED_NOW)
    text = json.dumps(snapshot.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    for spelling in {str(sandbox.root), str(sandbox.root.resolve())}:
        text = text.replace(json.dumps(spelling)[1:-1], "/repo")
    text = text.replace("\\\\", "/")
    assert_matches_golden(text, GOLDEN / "snapshot_demo.json")


# properties


@given(settings_dicts())
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_equal_settings_equal_fingerprints(data: dict[str, Any]) -> None:
    assert settings_fingerprint(Settings.model_validate(data)) == settings_fingerprint(
        Settings.model_validate(json.loads(json.dumps(data)))
    )


_terms = st.lists(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=10).map(lambda w: "zq" + w),
    min_size=1,
    max_size=4,
)


@given(_terms)
@settings(max_examples=40, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_sensitive_strings_never_serialised(
    tmp_path_factory: pytest.TempPathFactory, terms: list[str]
) -> None:
    sandbox = ConfigSandbox(tmp_path_factory.mktemp("s"))
    sandbox.write_user(f"[privacy]\ndomain_terms = {json.dumps(terms)}\n")
    snapshot = build_snapshot(sandbox.load(), codekavach_version="0", now=FIXED_NOW)
    text = json.dumps(snapshot.model_dump(mode="json"))
    for term in terms:
        assert term not in text


def test_levels_are_values() -> None:
    assert b'"L4"' in canonical_json({"level": PrivacyLevel.L4})
