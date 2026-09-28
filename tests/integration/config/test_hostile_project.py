"""A hostile repository cannot re-point egress, run code or redirect findings (E03-25)."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings

from codekavach.config import ConfigError
from codekavach.config.errors import ProjectTrustError
from tests.support.config import ConfigSandbox, isolate_config_env, to_toml
from tests.support.config_strategies import layer_sets

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "config" / "hostile_project"


def test_hostile_fixture_lists_every_violation(tmp_path: Path) -> None:
    manifest = json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))
    sandbox = ConfigSandbox(tmp_path / "sandbox")
    shutil.copyfile(FIXTURE / "codekavach.toml", sandbox.root / "codekavach.toml")
    with pytest.raises(ProjectTrustError) as info:
        sandbox.load()
    assert sorted(issue.key or "" for issue in info.value.issues) == sorted(manifest["violations"])
    assert {issue.code.value for issue in info.value.issues} == {"CK-CFG-040"}
    rendered = str(info.value) + repr(info.value)
    for value in manifest["planted_values"]:
        assert value not in rendered, value


def _effective(sandbox: ConfigSandbox) -> tuple[Any, Any, Any]:
    s = sandbox.load().settings
    executables = {name: opts.executable for name, opts in s.engines.options.items()}
    return (
        s.model_dump(mode="json")["llm"]["providers"],
        s.integrations.model_dump(mode="json"),
        executables,
    )


@given(layer_sets())
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_untrusted_project_cannot_change_restricted_settings(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    layers: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    user, project = layers
    with_project = ConfigSandbox(tmp_path_factory.mktemp("with"))
    without = ConfigSandbox(tmp_path_factory.mktemp("without"))
    isolate_config_env(monkeypatch, with_project.home)
    for sandbox in (with_project, without):
        if user:
            sandbox.write_user(to_toml(user))
    if project:
        with_project.write_project(to_toml(project))
    try:
        accepted = _effective(with_project)
    except ConfigError:
        return
    assert accepted == _effective(without)
