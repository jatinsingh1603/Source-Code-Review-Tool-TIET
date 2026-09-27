import tomllib
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, ValidationError

from codekavach.config import Settings
from codekavach.core.models import Language


def test_defaults_without_arguments() -> None:
    assert Settings() == Settings.model_validate({})
    settings = Settings()
    assert settings.config_version == 1
    assert settings.profile is None
    assert settings.profiles == {}
    assert settings.logging.level == "info"
    assert settings.logging.format == "console"


def test_environment_is_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEKAVACH_SCAN__JOBS", "9")
    assert Settings().scan.jobs == 0


def test_unknown_key_rejected_without_echo() -> None:
    with pytest.raises(ValidationError) as info:
        Settings.model_validate({"scan": {"max_file_sizekb": 1}})
    assert info.value.errors()[0]["type"] == "extra_forbidden"
    assert "max_file_sizekb" in str(info.value)
    assert "input_value" not in str(info.value)


def test_hidden_input_for_string_field() -> None:
    canary = "CANARY_9f3a"
    with pytest.raises(ValidationError) as info:
        Settings.model_validate({"scan": {"max_files": canary}})
    assert canary not in str(info.value)


def test_frozen() -> None:
    settings = Settings()
    with pytest.raises(ValidationError):
        settings.profile = "x"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        settings.scan.jobs = 3  # type: ignore[misc]


def test_config_version_two_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({"config_version": 2})


def test_logging_level() -> None:
    with pytest.raises(ValidationError) as info:
        Settings.model_validate({"logging": {"level": "verbose"}})
    message = str(info.value)
    for level in ("debug", "info", "warning", "error"):
        assert level in message


def test_toml_example() -> None:
    settings = Settings.model_validate(
        tomllib.loads('[scan]\nmax_file_size_kb = 256\nexclude = ["docs/**"]')
    )
    assert settings.scan.max_file_size_kb == 256
    assert settings.scan.exclude == ["docs/**"]
    assert settings.scan.include == ["**/*"]


def test_volatile_and_restricted_markers() -> None:
    defs = Settings.model_json_schema()["$defs"]
    scan = defs["ScanSettings"]["properties"]
    for key in ("stage_timeout_seconds", "stage_timeouts", "cache_max_size_mb", "cache_keep_scans"):
        assert scan[key]["x-ck-volatile"] is True
    assert "x-ck-volatile" not in scan["include"]


def _walk(model: type[BaseModel], path: str = "") -> list[str]:
    problems: list[str] = []
    for name, field in model.model_fields.items():
        where = f"{path}{name}"
        if field.is_required():
            problems.append(f"{where}: no default")
        if not field.description or not field.description.endswith("."):
            problems.append(f"{where}: description missing or without full stop")
        annotation = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            problems.extend(_walk(annotation, f"{where}."))
    return problems


def test_every_field_has_default_and_description() -> None:
    assert _walk(Settings) == []


_names = st.text(alphabet="abcdefghij ", min_size=1, max_size=20).map(str.strip).filter(bool)
_timeouts = st.dictionaries(st.sampled_from(["parse", "analyse"]), st.integers(10, 86_400))
_globs = st.lists(st.from_regex(r"[a-z*]{1,10}(/[a-z*]{1,10}){0,2}", fullmatch=True), max_size=4)


@given(
    st.fixed_dictionaries(
        {
            "name": st.none()
            | st.text(alphabet="abcdefghij ", min_size=1, max_size=20).map(str.strip).filter(bool),
            "languages": st.lists(st.sampled_from(Language), max_size=3, unique=True),
        }
    ),
    st.fixed_dictionaries(
        {
            "include": _globs.filter(bool),
            "exclude": _globs,
            "jobs": st.integers(0, 256),
            "max_file_size_kb": st.integers(1, 102_400),
            "fail_on": st.sampled_from(["critical", "high", "medium", "low", "info", "none"]),
            "stage_timeouts": st.dictionaries(
                st.sampled_from(["parse", "analyse"]), st.integers(10, 86_400)
            ),
        }
    ),
)
def test_round_trip(project: dict[str, Any], scan: dict[str, Any]) -> None:
    settings = Settings.model_validate({"project": project, "scan": scan})
    assert Settings.model_validate(settings.model_dump(mode="json")) == settings
