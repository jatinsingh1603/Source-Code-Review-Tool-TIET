from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, Field, ValidationError

from codekavach.config import LoadedConfig, Origin, Settings, load_settings
from codekavach.config import loader as loader_module
from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigValidationError
from codekavach.config.loader import convert_validation_error, union_keys_of
from codekavach.config.models.base import union_merge


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """An isolated user directory; no test reads the real home."""
    directory = tmp_path / "home"
    directory.mkdir()
    return directory


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "src").mkdir()
    return root


def env_for(home: Path, **extra: str) -> dict[str, str]:
    return {"CODEKAVACH_HOME": str(home), **extra}


def test_no_files_gives_defaults(tmp_path: Path, home: Path) -> None:
    target = tmp_path / "empty"
    target.mkdir()
    loaded = load_settings(target=target, env=env_for(home))
    assert loaded.settings == Settings()
    assert loaded.layers == ()
    assert loaded.project_config is None
    assert loaded.user_config is None
    assert loaded.project_trust == "not-needed"
    assert {origin.layer for origin in loaded.origins.values()} == {"default"}


def test_user_and_project_example(repo: Path, home: Path) -> None:
    (home / "config.toml").write_text('[scan]\njobs = 4\nexclude = ["legacy/**"]\n')
    project = repo / "codekavach.toml"
    project.write_text("# project\n[scan]\njobs = 2\n")
    loaded = load_settings(target=repo / "src", env=env_for(home))
    assert loaded.settings.scan.jobs == 2
    assert loaded.settings.scan.exclude == ["legacy/**"]
    assert loaded.origins["scan.jobs"] == Origin("project", str(project.resolve()), 3)
    assert loaded.origins["scan.exclude"] == Origin("user", str(home / "config.toml"), 3)
    others = {
        key: origin
        for key, origin in loaded.origins.items()
        if key not in {"scan.jobs", "scan.exclude"}
    }
    assert {origin.layer for origin in others.values()} == {"default"}
    assert loaded.project_root == repo.resolve()
    assert loaded.project_config == project.resolve()
    assert loaded.user_config == home / "config.toml"
    assert [layer.name for layer in loaded.layers] == ["user", "project"]


def test_user_only(tmp_path: Path, home: Path) -> None:
    (home / "config.toml").write_text("[scan]\njobs = 3\n")
    loaded = load_settings(target=tmp_path, env=env_for(home))
    assert loaded.settings.scan.jobs == 3
    assert loaded.project_config is None


def test_user_config_can_be_disabled(repo: Path, home: Path) -> None:
    (home / "config.toml").write_text("[scan]\njobs = 3\n")
    assert load_settings(target=repo, env=env_for(home), use_user_config=False).user_config is None
    disabled = env_for(home, CODEKAVACH_NO_USER_CONFIG="true")
    assert load_settings(target=repo, env=disabled).settings.scan.jobs == Settings().scan.jobs


def test_validation_errors_are_collected(repo: Path, home: Path) -> None:
    project = repo / "codekavach.toml"
    project.write_text('[scna]\nfoo = 1\n\n[scan]\njobs = "many"\n')
    with pytest.raises(ConfigValidationError) as error:
        load_settings(target=repo, env=env_for(home))
    issues = sorted(error.value.issues, key=lambda issue: issue.code)
    assert [issue.code for issue in issues] == [
        ConfigErrorCode.CK_CFG_002,
        ConfigErrorCode.CK_CFG_003,
    ]
    assert [issue.key for issue in issues] == ["scna", "scan.jobs"]
    assert [issue.line for issue in issues] == [1, 5]
    assert {issue.source for issue in issues} == {str(project.resolve())}
    assert "many" not in str(error.value)


def test_explicit_missing_file(repo: Path, home: Path) -> None:
    with pytest.raises(ConfigError) as error:
        load_settings(target=repo, config_file=repo / "nope.toml", env=env_for(home))
    assert error.value.code is ConfigErrorCode.CK_CFG_005


def test_explicit_file_inside_root(repo: Path, home: Path) -> None:
    explicit = repo / "conf" / "ck.toml"
    explicit.parent.mkdir()
    explicit.write_text("[scan]\njobs = 7\n")
    loaded = load_settings(target=repo / "src", config_file=explicit, env=env_for(home))
    assert loaded.settings.scan.jobs == 7
    assert loaded.project_trust == "not-needed"
    assert loaded.project_config == explicit


def test_explicit_file_outside_root_and_env_switch(repo: Path, home: Path, tmp_path: Path) -> None:
    outside = tmp_path / "ops" / "ck.toml"
    outside.parent.mkdir()
    outside.write_text("[scan]\njobs = 9\n")
    (repo / "codekavach.toml").write_text("[scan]\njobs = 1\n")
    loaded = load_settings(target=repo / "src", env=env_for(home, CODEKAVACH_CONFIG=str(outside)))
    assert loaded.settings.scan.jobs == 9
    assert loaded.project_trust == "external-config"
    assert loaded.project_root == repo.resolve()
    assert loaded.project_config == outside


def test_resolve_path(tmp_path: Path, home: Path) -> None:
    loaded = load_settings(target=tmp_path, env=env_for(home))
    assert loaded.resolve_path(Path("out")) == loaded.project_root / "out"
    absolute = (tmp_path / "abs").resolve()
    assert loaded.resolve_path(absolute) == absolute


def test_cli_overrides_form_the_top_layer(repo: Path, home: Path) -> None:
    (repo / "codekavach.toml").write_text("[scan]\njobs = 2\n")
    loaded = load_settings(target=repo, env=env_for(home), cli_overrides={"scan": {"jobs": 5}})
    assert loaded.settings.scan.jobs == 5
    assert loaded.origins["scan.jobs"].layer == "cli"


def test_union_keys_of_settings() -> None:
    assert union_keys_of(Settings) >= {"privacy.never_send", "privacy.domain_terms"}


def test_union_merge_across_layers(repo: Path, home: Path) -> None:
    (home / "config.toml").write_text('[privacy]\ndomain_terms = ["alpha"]\n')
    (repo / "codekavach.toml").write_text('[privacy]\ndomain_terms = ["beta", "alpha"]\n')
    loaded = load_settings(target=repo, env=env_for(home))
    assert loaded.settings.privacy.domain_terms == ["alpha", "beta"]
    assert loaded.origins["privacy.domain_terms"].contributors == ("user", "project")


def test_extension_points_called_in_order(
    repo: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def recorder(name: str, result: Any) -> Any:
        def record(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            return result(*args, **kwargs)

        return record

    monkeypatch.setattr(loader_module, "_discover_org_policies", recorder("org", lambda **_: ()))
    monkeypatch.setattr(
        loader_module,
        "_select_profile",
        recorder("profile", lambda layers, **kwargs: (layers, None, None, {})),
    )
    monkeypatch.setattr(
        loader_module, "_extra_layers", recorder("extra", lambda layers, **_: (layers, []))
    )
    monkeypatch.setattr(loader_module, "_expand_layer", recorder("expand", lambda layer: layer))
    monkeypatch.setattr(loader_module, "_check_layers", recorder("check", lambda *a, **k: ()))
    monkeypatch.setattr(
        loader_module,
        "_apply_org_policy",
        recorder("policy", lambda settings, *a: (settings, frozenset(), ())),
    )
    monkeypatch.setattr(loader_module, "_semantic_checks", recorder("semantic", lambda *a: ()))
    (repo / "codekavach.toml").write_text("[scan]\njobs = 2\n")
    load_settings(target=repo, env=env_for(home))
    assert calls == ["org", "profile", "extra", "expand", "check", "policy", "semantic"]


class Entry(BaseModel):
    level: int = 0


class Model(BaseModel):
    model_config = {"extra": "forbid", "hide_input_in_errors": True}
    config_version: int = 1
    paths: list[Entry] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list, json_schema_extra=union_merge())
    ranged: int = 0

    @classmethod
    def check(cls, data: dict[str, Any]) -> ValidationError:
        try:
            cls.model_validate(data)
        except ValidationError as error:
            return error
        raise AssertionError("expected a validation error")


def origins_of(key: str) -> Origin:
    return Origin("project", "/repo/codekavach.toml", len(key))


def test_error_conversion_table() -> None:
    error = Model.check(
        {"paths": [{"level": 1}, {"level": "SECRETVALUE"}], "unknown": 1, "config_version": "x"}
    )
    issues = {issue.key: issue for issue in convert_validation_error(error, origins_of)}
    assert issues["paths[1].level"].code is ConfigErrorCode.CK_CFG_003
    assert issues["paths[1].level"].line == len("paths[1].level")
    assert issues["unknown"].code is ConfigErrorCode.CK_CFG_002
    assert issues["config_version"].code is ConfigErrorCode.CK_CFG_004
    assert all(issue.source == "/repo/codekavach.toml" for issue in issues.values())
    assert "SECRETVALUE" not in repr(tuple(issues.values()))
    assert union_keys_of(Model) == {"tags"}


def test_coded_messages_keep_their_code() -> None:
    with pytest.raises(ValidationError) as error:
        Settings.model_validate({"llm": {"default_provider": "nope"}})
    (issue,) = convert_validation_error(error.value, origins_of)
    assert issue.code is ConfigErrorCode.CK_CFG_030
    assert issue.key == "llm"
    assert not issue.message.startswith("[")


def test_loaded_config_is_frozen(tmp_path: Path, home: Path) -> None:
    loaded = load_settings(target=tmp_path, env=env_for(home))
    assert isinstance(loaded, LoadedConfig)
    with pytest.raises(AttributeError):
        loaded.profile = "x"  # type: ignore[misc]
