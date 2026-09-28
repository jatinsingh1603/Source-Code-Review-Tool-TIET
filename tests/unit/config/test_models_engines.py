from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.config.models.engines import (
    MAX_ARG_LENGTH,
    MAX_ARGS,
    EngineOptions,
    EnginesSettings,
)
from codekavach.config.models.root import Settings


def fails(data: dict[str, Any], code: str) -> None:
    with pytest.raises(ValidationError, match=rf"\[{code}\]"):
        Settings.model_validate({"engines": data})


def test_defaults() -> None:
    engines = Settings().engines
    assert engines.enabled == []
    assert engines.disabled == []
    assert engines.timeout_seconds == 600
    assert engines.rule_packs == ["default"]
    assert engines.rule_paths == []
    native = engines.native
    assert (native.rules, native.taint, native.secrets, native.sca, native.iac) == (True,) * 5
    assert engines.options == {}
    options = EngineOptions()
    assert options.enabled is None
    assert options.executable is None
    assert (options.args, options.env_passthrough, options.options) == ([], [], {})
    assert options.timeout_seconds is None


def test_example_input() -> None:
    settings = Settings.model_validate(
        {"engines": {"disabled": ["semgrep"], "options": {"bandit": {"timeout_seconds": 120}}}}
    )
    assert settings.engines.disabled == ["semgrep"]
    assert settings.engines.options["bandit"].timeout_seconds == 120


def test_comma_separated_lists() -> None:
    engines = EnginesSettings.model_validate({"enabled": "semgrep, bandit", "rule_packs": "a,b"})
    assert engines.enabled == ["semgrep", "bandit"]
    assert engines.rule_packs == ["a", "b"]


def test_enabled_and_disabled_overlap() -> None:
    fails({"enabled": ["x"], "disabled": ["x"]}, "CK-CFG-035")


@pytest.mark.parametrize("timeout", [5, 9, 86_401])
def test_timeout_range(timeout: int) -> None:
    fails({"timeout_seconds": timeout}, "CK-CFG-003")
    fails({"options": {"bandit": {"timeout_seconds": timeout}}}, "CK-CFG-003")


@pytest.mark.parametrize("timeout", [10, 86_400])
def test_timeout_bounds_accepted(timeout: int) -> None:
    Settings.model_validate({"engines": {"timeout_seconds": timeout}})


BAD_IDS = ["Semgrep", "a b", "a" * 33, "", "1abc", "sem_grep"]


@pytest.mark.parametrize("engine_id", BAD_IDS)
def test_engine_id_syntax_everywhere(engine_id: str) -> None:
    fails({"enabled": [engine_id]}, "CK-CFG-003")
    fails({"disabled": [engine_id]}, "CK-CFG-003")
    fails({"options": {engine_id: {}}}, "CK-CFG-003")


def test_valid_engine_id_everywhere() -> None:
    engines = EnginesSettings.model_validate(
        {"enabled": ["sem-grep2"], "disabled": ["a" * 32], "options": {"sem-grep2": {}}}
    )
    assert "sem-grep2" in engines.options


@pytest.mark.parametrize("name", ["1ABC", "A-B", "a b", "", "A" * 129])
def test_env_passthrough_syntax(name: str) -> None:
    fails({"options": {"x": {"env_passthrough": [name]}}}, "CK-CFG-003")


def test_env_passthrough_accepts_names() -> None:
    options = EngineOptions.model_validate({"env_passthrough": "PATH, _X1, " + "A" * 128})
    assert options.env_passthrough == ["PATH", "_X1", "A" * 128]


@pytest.mark.parametrize(
    "args",
    [["a"] * (MAX_ARGS + 1), ["x" * (MAX_ARG_LENGTH + 1)], ["bad\x00arg"]],
    ids=["too_many", "too_long", "nul"],
)
def test_args_limits(args: list[str]) -> None:
    fails({"options": {"x": {"args": args}}}, "CK-CFG-003")


def test_args_at_the_limits() -> None:
    args = ["x" * MAX_ARG_LENGTH] * MAX_ARGS
    assert EngineOptions(args=args).args == args


def test_error_does_not_echo_input() -> None:
    with pytest.raises(ValidationError) as info:
        EnginesSettings.model_validate({"enabled": ["SECRET_LOOKING_ID"]})
    assert "SECRET_LOOKING_ID" not in str(info.value)


def test_schema_markers() -> None:
    schema = Settings.model_json_schema()
    defs = schema["$defs"]
    options = defs["EngineOptions"]["properties"]
    for key in ("executable", "args", "env_passthrough"):
        assert options[key].get("x-ck-restricted") is True, key
    assert options["timeout_seconds"].get("x-ck-volatile") is True
    assert defs["EnginesSettings"]["properties"]["timeout_seconds"].get("x-ck-volatile") is True
    assert "x-ck-restricted" not in options["enabled"]


NATIVE = ("rules", "taint", "secrets", "sca", "iac")
_ids = st.from_regex(r"[a-z][a-z0-9-]{0,31}", fullmatch=True)
_env = st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,20}", fullmatch=True)
_options = st.fixed_dictionaries(
    {},
    optional={
        "enabled": st.none() | st.booleans(),
        "executable": st.none() | st.just("/usr/bin/semgrep"),
        "args": st.lists(st.text("abc-=", max_size=10), max_size=4),
        "env_passthrough": st.lists(_env, max_size=3),
        "timeout_seconds": st.none() | st.integers(10, 86_400),
        "options": st.dictionaries(
            st.text("abc", min_size=1, max_size=5),
            st.integers() | st.booleans() | st.text("xyz", max_size=5),
            max_size=3,
        ),
    },
)


@st.composite
def sections(draw: st.DrawFn) -> dict[str, Any]:
    ids = draw(st.lists(_ids, max_size=6, unique=True))
    split = draw(st.integers(0, len(ids)))
    return {
        "enabled": ids[:split],
        "disabled": ids[split:],
        "timeout_seconds": draw(st.integers(10, 86_400)),
        "rule_packs": draw(st.lists(st.sampled_from(["default", "owasp", "bank"]), max_size=3)),
        "rule_paths": draw(st.lists(st.sampled_from(["rules/extra", "/opt/rules"]), max_size=2)),
        "native": {name: draw(st.booleans()) for name in NATIVE},
        "options": draw(st.dictionaries(_ids, _options, max_size=3)),
    }


@given(sections())
def test_round_trip(data: dict[str, Any]) -> None:
    engines = EnginesSettings.model_validate(data)
    again = EnginesSettings.model_validate(engines.model_dump(mode="json"))
    assert again == engines
    assert all(isinstance(path, Path) for path in again.rule_paths)
