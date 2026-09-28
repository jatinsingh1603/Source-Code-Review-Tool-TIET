from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import ConfigError, Settings
from codekavach.config.env_source import (
    RESERVED_ENV,
    coerce_env_value,
    env_layer,
    env_var_name,
)
from codekavach.config.introspect import iter_fields, resolve_field
from codekavach.config.models.base import StrList
from codekavach.config.models.reporting import ReportFormat
from codekavach.core.models import PrivacyLevel
from tests.support.config import ConfigSandbox

GOLDEN_RESERVED = {
    "CODEKAVACH_CONFIG",
    "CODEKAVACH_PROFILE",
    "CODEKAVACH_HOME",
    "CODEKAVACH_NO_USER_CONFIG",
    "CODEKAVACH_ORG_POLICY",
    "CODEKAVACH_ORG_POLICY_SHA256",
    "CODEKAVACH_ORG_POLICY_PUBKEY",
    "CODEKAVACH_TRUST_PROJECT_CONFIG",
    "CODEKAVACH_PRIVACY_LEVEL",
    "CODEKAVACH_PROVIDER",
    "CODEKAVACH_MODEL",
    "CODEKAVACH_OFFLINE",
    "CODEKAVACH_JSON",
    "CODEKAVACH_QUIET",
    "CODEKAVACH_VERBOSE",
    "CODEKAVACH_DEBUG",
    "CODEKAVACH_NO_COLOR",
    "CODEKAVACH_ACCEPT_EGRESS",
    "CODEKAVACH_LOG_LEVEL",
    "CODEKAVACH_LOG_FORMAT",
    "CODEKAVACH_LOG_THIRD_PARTY",
    "CODEKAVACH_PERF_FACTOR",
    "CODEKAVACH_TEST_NETWORK",
    "CODEKAVACH_UPDATE_GOLDEN",
    "CODEKAVACH_SKIP_PERF",
    "CODEKAVACH_UPDATE_SNAPSHOTS",
}


def error_of(env: dict[str, str]) -> ConfigError:
    with pytest.raises(ConfigError) as info:
        env_layer(env)
    return info.value


def test_reserved_golden() -> None:
    assert set(RESERVED_ENV) == GOLDEN_RESERVED


def test_env_var_name() -> None:
    assert env_var_name("llm.providers.lab.base_url") == "CODEKAVACH_LLM__PROVIDERS__LAB__BASE_URL"
    assert env_var_name("scan.jobs") == "CODEKAVACH_SCAN__JOBS"


def test_scalar_and_origin() -> None:
    layer, warnings = env_layer({"CODEKAVACH_SCAN__JOBS": "8", "PATH": "/bin"})
    assert warnings == []
    assert layer is not None
    assert layer.name == "env"
    assert layer.data == {"scan": {"jobs": 8}}
    assert layer.key_sources["scan.jobs"] == "CODEKAVACH_SCAN__JOBS"


def test_unknown_settings_variable_suggests_and_hides_value() -> None:
    error = error_of({"CODEKAVACH_PRIVACY__LEVLE": "L4"})
    issue = error.issues[0]
    assert issue.code.value == "CK-CFG-060"
    assert issue.hint is not None
    assert "CODEKAVACH_PRIVACY__LEVEL" in issue.hint
    assert "L4" not in str(error).replace("CODEKAVACH_PRIVACY__LEVLE", "")


def test_malformed_value_is_not_printed() -> None:
    error = error_of({"CODEKAVACH_SCAN__JOBS": "many"})
    assert error.issues[0].code.value == "CK-CFG-060"
    assert "integer" in error.issues[0].message
    assert "many" not in str(error)


def test_malformed_name() -> None:
    assert error_of({"CODEKAVACH_SCAN____JOBS": "1"}).issues[0].code.value == "CK-CFG-060"


def test_empty_value_is_ignored() -> None:
    assert env_layer({"CODEKAVACH_SCAN__JOBS": ""}) == (None, [])


def test_unknown_process_variable_warns_with_hint() -> None:
    _, warnings = env_layer({"CODEKAVACH_ORG_POLCY": "/x"})
    assert len(warnings) == 1
    assert warnings[0].severity == "warning"
    assert warnings[0].code.value == "CK-CFG-060"
    assert warnings[0].hint is not None
    assert "CODEKAVACH_ORG_POLICY" in warnings[0].hint


def test_misspelt_cli_variable_hint_names_both_forms() -> None:
    _, warnings = env_layer({"CODEKAVACH_PROVIDR": "mock"})
    hint = warnings[0].hint or ""
    assert "CODEKAVACH_PROVIDER" in hint
    assert "CODEKAVACH_<SECTION>__<KEY>" in hint


def test_unknown_process_variable_without_close_match() -> None:
    _, warnings = env_layer({"CODEKAVACH_ZZZ": "1"})
    assert warnings[0].hint is not None
    assert "did you mean" not in warnings[0].hint


def test_reserved_names_do_not_warn_or_set_values() -> None:
    env = dict.fromkeys(RESERVED_ENV, "1")
    layer, warnings = env_layer(env)
    assert layer is None
    assert warnings == []


def test_provider_variable_does_not_set_default_provider(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.env["CODEKAVACH_PROVIDER"] = "mock"
    loaded = config_sandbox.load()
    assert loaded.settings.llm.default_provider == "auto"
    assert loaded.warnings == ()


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        (
            "CODEKAVACH_LLM__PROVIDERS__LAB__MODEL",
            "qwen",
            {"llm": {"providers": {"lab": {"model": "qwen"}}}},
        ),
        (
            "CODEKAVACH_ENGINES__OPTIONS__SEMGREP__ENABLED",
            "false",
            {"engines": {"options": {"semgrep": {"enabled": False}}}},
        ),
    ],
)
def test_mapping_paths(name: str, value: str, expected: dict[str, Any]) -> None:
    layer, _ = env_layer({name: value})
    assert layer is not None
    assert layer.data == expected


def test_mapping_id_violation_is_rejected_on_load(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.env["CODEKAVACH_LLM__PROVIDERS__1BAD__KIND"] = "mock"
    with pytest.raises(ConfigError):
        config_sandbox.load()


# coercion


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(v, True) for v in ("1", "true", "TRUE", "yes", "On")]
    + [(v, False) for v in ("0", "false", "No", "off", "OFF")],
)
def test_bool(raw: str, expected: bool) -> None:
    assert coerce_env_value(raw, bool) is expected


@pytest.mark.parametrize("raw", ["2", "maybe", ""])
def test_bool_rejects(raw: str) -> None:
    with pytest.raises(ValueError, match="boolean"):
        coerce_env_value(raw, bool)


def test_numbers_and_strings() -> None:
    assert coerce_env_value("8", int) == 8
    assert coerce_env_value("0.5", float) == 0.5
    assert coerce_env_value("L3", PrivacyLevel) == "L3"
    assert coerce_env_value("x/y", Path) == "x/y"
    assert coerce_env_value("abc", str | None) == "abc"
    with pytest.raises(ValueError, match="number"):
        coerce_env_value("x", float)


def test_lists() -> None:
    assert coerce_env_value("html, pdf", list[ReportFormat]) == ["html", "pdf"]
    assert coerce_env_value('["a,b", "c"]', StrList) == ["a,b", "c"]
    assert coerce_env_value("", StrList) == []
    with pytest.raises(ValueError, match="JSON array"):
        coerce_env_value("[broken", StrList)


def test_dicts_need_json() -> None:
    assert coerce_env_value('{"parse": 60}', dict[str, int]) == {"parse": 60}
    with pytest.raises(ValueError, match="JSON object"):
        coerce_env_value("parse=60", dict[str, int])


# properties

_PLAIN_KEYS = [
    ref.key for ref in iter_fields(Settings) if "*" not in ref.key and "[" not in ref.key
]


@given(st.sampled_from(_PLAIN_KEYS))
def test_key_and_variable_round_trip(key: str) -> None:
    name = env_var_name(key)
    derived = ".".join(part.lower() for part in name.removeprefix("CODEKAVACH_").split("__"))
    assert resolve_field(Settings, derived) is not None


_INT_KEYS = ["CODEKAVACH_SCAN__JOBS", "CODEKAVACH_SCAN__MAX_FILES", "CODEKAVACH_LLM__MAX_RETRIES"]


@given(
    st.sampled_from(_INT_KEYS),
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz!@#%", min_size=4, max_size=30),
)
def test_failing_values_never_appear_in_messages(name: str, value: str) -> None:
    error = error_of({name: value})
    for issue in error.issues:
        assert value not in (issue.message + (issue.hint or ""))
