from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import load_settings, overrides
from codekavach.config.errors import ConfigError, ConfigErrorCode
from codekavach.config.overrides import (
    FLAG_TO_KEY,
    CliOverrides,
    cli_layer,
    combine,
    overrides_from_flags,
    parse_set_options,
)
from codekavach.core.models import PrivacyLevel

ROWS: list[tuple[str, Any, dict[str, Any]]] = [
    ("privacy_level", "L2", {"privacy": {"level": "L2"}}),
    ("provider", "mock", {"llm": {"default_provider": "mock"}}),
    ("model", "m-1", {"llm": {"model": "m-1"}}),
    ("no_llm", True, {"llm": {"enabled": False}}),
    ("fail_on", "high", {"scan": {"fail_on": "high"}}),
    ("include", ("src/**", "lib/**"), {"scan": {"include": ["src/**", "lib/**"]}}),
    ("exclude", ("legacy/**",), {"scan": {"exclude": ["legacy/**"]}}),
    ("formats", ("sarif",), {"reporting": {"formats": ["sarif"]}}),
    ("output_dir", "out", {"reporting": {"output_dir": "out"}}),
    ("jobs", 4, {"scan": {"jobs": 4}}),
    ("log_level", "debug", {"logging": {"level": "debug"}}),
    ("log_format", "json", {"logging": {"format": "json"}}),
]


def code(call: Any) -> ConfigErrorCode:
    with pytest.raises(ConfigError) as error:
        call()
    return error.value.code


@pytest.mark.parametrize(("name", "value", "expected"), ROWS)
def test_flag_rows(name: str, value: Any, expected: dict[str, Any]) -> None:
    overrides = overrides_from_flags(**{name: value})
    assert overrides.data == expected
    assert set(overrides.key_sources.values()) == {FLAG_TO_KEY[name].flag}


def test_offline() -> None:
    overrides = overrides_from_flags(offline=True, privacy_level="L3")
    assert overrides.data["llm"] == {"allow_remote": False}
    assert overrides.data["privacy"] == {"level": "L3"}
    assert overrides.key_sources["llm.allow_remote"] == "--offline"
    assert overrides_from_flags(offline=False).data == {}


def test_ignored_values() -> None:
    assert overrides_from_flags(no_llm=False, provider=None, include=()).data == {}


def test_unknown_keyword_and_unavailable_key(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(TypeError, match="unknown flag"):
        overrides_from_flags(nope=1)
    table = {**overrides.FLAG_TO_KEY, "future": overrides.Flag("--future", ("nosuch.key",))}
    monkeypatch.setattr(overrides, "FLAG_TO_KEY", table)
    assert code(lambda: overrides_from_flags(future="x")) is ConfigErrorCode.CK_CFG_061


def test_engine_flags_map_to_the_engines_section() -> None:
    result = overrides_from_flags(engine=("semgrep",), skip_engine=("bandit",))
    assert result.data == {"engines": {"enabled": ["semgrep"], "disabled": ["bandit"]}}


def test_parse_set_options() -> None:
    overrides = parse_set_options(
        ["scan.jobs=4", "privacy.level=L2", 'reporting.formats=["html","pdf"]']
    )
    assert overrides.data == {
        "scan": {"jobs": 4},
        "privacy": {"level": "L2"},
        "reporting": {"formats": ["html", "pdf"]},
    }
    assert overrides.key_sources["scan.jobs"] == "--set scan.jobs"


@pytest.mark.parametrize(
    ("item", "value"),
    [
        ("scan.jobs=4", 4),
        ("llm.enabled=false", False),
        ('project.name="bank app"', "bank app"),
        ("privacy.level=L2", "L2"),
        ("scan.exclude=['a', 'b']", ["a", "b"]),
        ("llm.providers.lab={kind = 'mock'}", {"kind": "mock"}),
        ("llm.providers.lab.options.seed=7", 7),
    ],
)
def test_set_values(item: str, value: Any) -> None:
    key = item.partition("=")[0]
    data: Any = parse_set_options([item]).data
    for part in key.split("."):
        data = data[part]
    assert data == value


@pytest.mark.parametrize(
    "items", [["novalue"], ["=x"], ["scan.nope=1"], ["scan.jobs=1", "scan.jobs=2"]]
)
def test_set_errors(items: list[str]) -> None:
    assert code(lambda: parse_set_options(items)) is ConfigErrorCode.CK_CFG_061


def test_set_hint() -> None:
    with pytest.raises(ConfigError) as error:
        parse_set_options(["scan.job=1"])
    assert error.value.issues[0].hint == "did you mean scan.jobs?"


def test_combine_conflict() -> None:
    assert (
        code(
            lambda: combine(
                overrides_from_flags(privacy_level="L4"), parse_set_options(["privacy.level=L2"])
            )
        )
        is ConfigErrorCode.CK_CFG_061
    )
    merged = combine(overrides_from_flags(jobs=2), parse_set_options(["privacy.level=L4"]))
    assert merged.data == {"scan": {"jobs": 2}, "privacy": {"level": "L4"}}
    assert merged.key_sources == {"scan.jobs": "--jobs", "privacy.level": "--set privacy.level"}


def test_plain_mapping_layer() -> None:
    layer = cli_layer({"scan": {"jobs": 3}})
    assert (layer.name, layer.source) == ("cli", "cli")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    return root


def test_precedence_with_origins(repo: Path) -> None:
    home = repo.parent / "home"
    home.mkdir()
    (home / "config.toml").write_text('[scan]\njobs = 2\nexclude = ["u/**"]\n')
    (repo / "codekavach.toml").write_text('[scan]\njobs = 3\nexclude = ["p/**"]\n')
    overrides = overrides_from_flags(jobs=5, exclude=("c/**",))
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(home)}, cli_overrides=overrides)
    assert loaded.settings.scan.jobs == 5
    assert loaded.settings.scan.exclude == ["c/**"]
    assert (loaded.origins["scan.jobs"].layer, loaded.origins["scan.jobs"].source) == (
        "cli",
        "--jobs",
    )
    assert loaded.origins["scan.exclude"].source == "--exclude"
    plain = load_settings(
        target=repo, env={"CODEKAVACH_HOME": str(home)}, cli_overrides={"scan": {"jobs": 7}}
    )
    assert (plain.origins["scan.jobs"].layer, plain.origins["scan.jobs"].source) == ("cli", "cli")


def test_flag_cannot_go_below_floor(repo: Path) -> None:
    (repo / "codekavach.toml").write_text('[privacy]\nlevel = "L4"\nmin_level = "L3"\n')
    env = {"CODEKAVACH_HOME": str(repo.parent / "home")}
    with pytest.raises(ConfigError):
        load_settings(target=repo, env=env, cli_overrides=overrides_from_flags(privacy_level="L1"))
    loaded = load_settings(
        target=repo, env=env, cli_overrides=overrides_from_flags(privacy_level="L4")
    )
    assert loaded.settings.privacy.level is PrivacyLevel.L4


@given(st.text(alphabet="!@#$%^&*()ZQXV", min_size=4, max_size=20))
def test_property_values_are_not_echoed(value: str) -> None:
    with pytest.raises(ConfigError) as error:
        parse_set_options([f"scan.nope={value}"])
    assert value not in str(error.value)


def test_cli_overrides_dataclass_defaults() -> None:
    assert CliOverrides().data == {}
