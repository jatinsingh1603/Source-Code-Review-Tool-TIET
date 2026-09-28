import itertools
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import Settings, load_settings
from codekavach.config.errors import ConfigErrorCode, ProfileError
from codekavach.config.merge import deep_merge
from codekavach.config.models.reporting import ReportFormat
from codekavach.config.profiles import (
    BUILTIN_PROFILES,
    PROFILE_DESCRIPTIONS,
    ProfileInfo,
    build_profile_layer,
    list_profiles,
    load_builtin_profile,
    resolve_profile,
    select_profile_name,
)
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).resolve().parents[2] / "golden" / "config"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    directory = tmp_path / "home"
    directory.mkdir()
    return directory


def env_for(home: Path, **extra: str) -> dict[str, str]:
    return {"CODEKAVACH_HOME": str(home), **extra}


@pytest.mark.parametrize("name", BUILTIN_PROFILES)
def test_builtin_profiles_validate(name: str) -> None:
    overlay = load_builtin_profile(name)
    Settings.model_validate(deep_merge(Settings().model_dump(mode="json"), overlay))


@pytest.mark.parametrize("name", BUILTIN_PROFILES)
def test_builtin_resources_are_packaged(name: str) -> None:
    resource = files("codekavach.config").joinpath("builtin_profiles", f"{name}.toml")
    assert resource.is_file()


@pytest.mark.parametrize("name", BUILTIN_PROFILES)
def test_golden_effective_settings(name: str, tmp_path: Path, home: Path) -> None:
    loaded = load_settings(target=tmp_path, profile=name, env=env_for(home))
    dumped = loaded.settings.model_dump(mode="json", exclude={"project": {"state_dir"}})
    text = json.dumps(dumped, indent=2, sort_keys=True) + "\n"
    assert_matches_golden(text, GOLDEN / f"profile_{name.replace('-', '_')}.json")


def test_demo_profile(tmp_path: Path, home: Path) -> None:
    loaded = load_settings(target=tmp_path, profile="demo", env=env_for(home))
    settings = loaded.settings
    assert settings.llm.default_provider == "mock"
    assert settings.llm.allow_remote is False
    assert settings.reporting.formats[:2] == [ReportFormat.html, ReportFormat.pdf]
    assert settings.profile == "demo"
    assert loaded.profile == "demo"
    assert loaded.profile_origin is not None
    assert loaded.profile_origin.layer == "cli"
    origin = loaded.origins["llm.default_provider"]
    assert (origin.layer, origin.source) == ("profile", "builtin:demo")
    assert [layer.name for layer in loaded.layers] == ["profile"]


SOURCES = ("cli", "env", "project", "user")


@pytest.mark.parametrize(
    "present", [combo for n in range(5) for combo in itertools.combinations(SOURCES, n)]
)
def test_selection_order_matrix(present: tuple[str, ...]) -> None:
    name, origin = select_profile_name(
        "from-cli" if "cli" in present else None,
        {"CODEKAVACH_PROFILE": "from-env"} if "env" in present else {},
        {"profile": "from-project"} if "project" in present else {},
        {"profile": "from-user"} if "user" in present else None,
    )
    expected = next((source for source in SOURCES if source in present), None)
    if expected is None:
        assert (name, origin.layer) == (None, "default")
    else:
        assert (name, origin.layer) == (f"from-{expected}", expected)


def test_empty_string_means_no_profile() -> None:
    assert select_profile_name("", {"CODEKAVACH_PROFILE": "ci"}, None, None)[0] is None
    assert (
        select_profile_name(None, {"CODEKAVACH_PROFILE": " "}, {"profile": "ci"}, None)[0] is None
    )


def test_selection_from_project_file_has_line(tmp_path: Path, home: Path) -> None:
    (tmp_path / ".git").mkdir()
    project = tmp_path / "codekavach.toml"
    project.write_text('# x\nprofile = "ci"\n')
    loaded = load_settings(target=tmp_path, env=env_for(home))
    assert loaded.profile == "ci"
    assert loaded.profile_origin is not None
    assert (loaded.profile_origin.layer, loaded.profile_origin.line) == ("project", 2)
    assert loaded.settings.llm.budget.max_requests == 200


USER_DEFINED: dict[str, dict[str, Any]] = {
    "nightly": {
        "extends": "ci",
        "scan": {"fail_on": "medium"},
        "llm": {"budget": {"max_requests": 1000}},
    },
    "weekly": {
        "extends": "nightly",
        "description": "Weekly run",
        "reporting": {"formats": ["pdf"]},
    },
    "monthly": {"extends": "weekly", "scan": {"jobs": 2}},
}


def test_extends_chain_depth_three() -> None:
    overlay = resolve_profile("monthly", USER_DEFINED)
    assert overlay["scan"] == {"fail_on": "medium", "jobs": 2}
    assert overlay["llm"] == {"max_retries": 1, "budget": {"max_requests": 1000}}
    assert overlay["reporting"] == {"formats": ["pdf"]}
    assert "extends" not in overlay
    assert "description" not in overlay


def test_user_defined_layer_source() -> None:
    layer = build_profile_layer("nightly", USER_DEFINED, sources={"nightly": "/u/config.toml"})
    assert layer.source == "/u/config.toml#profiles.nightly"
    assert layer.name == "profile"


def code_of(call: Any) -> ConfigErrorCode:
    with pytest.raises(ProfileError) as error:
        call()
    return error.value.code


def test_cycle_and_unknown_parent() -> None:
    cycle = {"a": {"extends": "b"}, "b": {"extends": "a"}}
    assert code_of(lambda: resolve_profile("a", cycle)) is ConfigErrorCode.CK_CFG_021
    assert code_of(lambda: resolve_profile("a", {"a": {"extends": "a"}})) is (
        ConfigErrorCode.CK_CFG_021
    )
    orphan = {"a": {"extends": "missing"}}
    assert code_of(lambda: resolve_profile("a", orphan)) is ConfigErrorCode.CK_CFG_021


def test_unknown_selected_profile_lists_names(tmp_path: Path, home: Path) -> None:
    with pytest.raises(ProfileError) as error:
        load_settings(target=tmp_path, profile="demmo", env=env_for(home))
    assert error.value.code is ConfigErrorCode.CK_CFG_020
    assert "ci, demo" in str(error.value)
    assert error.value.issues[0].hint == "did you mean demo?"


@pytest.mark.parametrize("where", ["user", "project"])
def test_shadowing_builtin_is_refused(tmp_path: Path, home: Path, where: str) -> None:
    (tmp_path / ".git").mkdir()
    target = home / "config.toml" if where == "user" else tmp_path / "codekavach.toml"
    target.write_text("[profiles.demo]\n[profiles.demo.llm]\nallow_remote = true\n")
    with pytest.raises(ProfileError) as error:
        load_settings(target=tmp_path, env=env_for(home))
    assert error.value.code is ConfigErrorCode.CK_CFG_022


@pytest.mark.parametrize(
    "table",
    [
        {"x": {"profile": "ci"}},
        {"x": {"profiles": {}}},
        {"x": {"config_version": 1}},
        {"Bad_Name": {}},
        {"x": {"extends": 3}},
        {"x": "not a table"},
    ],
)
def test_forbidden_keys_and_bad_shapes(table: dict[str, Any]) -> None:
    assert code_of(lambda: build_profile_layer("ci", table)) is ConfigErrorCode.CK_CFG_003


def test_invalid_overlay_is_attributed_to_profile(tmp_path: Path, home: Path) -> None:
    (home / "config.toml").write_text('[profiles.broken.scan]\njobs = "lots"\n')
    with pytest.raises(ProfileError) as error:
        load_settings(target=tmp_path, profile="broken", env=env_for(home))
    issue = error.value.issues[0]
    assert issue.code is ConfigErrorCode.CK_CFG_003
    assert issue.source == f"{home / 'config.toml'}#profiles.broken"
    assert "lots" not in str(error.value)


def test_profiles_table_is_combined_and_reported(tmp_path: Path, home: Path) -> None:
    (tmp_path / ".git").mkdir()
    (home / "config.toml").write_text('[profiles.mine]\nextends = "ci"\n[profiles.shared]\n')
    (tmp_path / "codekavach.toml").write_text('[profiles.shared]\ndescription = "project"\n')
    loaded = load_settings(target=tmp_path, env=env_for(home))
    assert loaded.settings.profile is None
    assert loaded.settings.profiles == {
        "mine": {"extends": "ci"},
        "shared": {"description": "project"},
    }


def test_list_profiles() -> None:
    infos = list_profiles(USER_DEFINED, sources={"weekly": "/u/config.toml"})
    assert [info.name for info in infos[:4]] == ["airgapped", "bank-strict", "ci", "demo"]
    assert infos[2] == ProfileInfo(
        "ci", "built-in", "builtin:ci", description=PROFILE_DESCRIPTIONS["ci"]
    )
    assert all(info.description for info in infos[:4])
    weekly = next(info for info in infos if info.name == "weekly")
    assert weekly == ProfileInfo(
        "weekly", "user-defined", "/u/config.toml", "nightly", "Weekly run"
    )
