"""The plugin allow-list and disable-list against really installed (fake) distributions (E04-11).

A plugin that the settings do not allow must never be imported: loading means running its module,
so the decision is made from metadata alone. These tests install distributions into a temporary
site directory, build the registry the way the CLI does, and look at ``sys.modules``.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.config.errors import ConfigError, ConfigErrorCode
from codekavach.core.pipeline import runner
from codekavach.core.plugins.registry import registry_from_environment
from tests.support.config import ConfigSandbox
from tests.support.pipeline import write_fake_distribution

STAGES = "codekavach.stages"
DETECTORS = "codekavach.detectors"
PROVIDERS = "codekavach.providers"

STAGE_MODULE = """
class SampleStage:
    name = "sample"
    requires = frozenset({"files"})
    provides = frozenset({"sample.out"})
    category = None

    def run(self, ctx):
        ctx.artefacts.put("sample.out", {"ok": True})
"""
DETECTOR_MODULE = "class Foo:\n    pass\n"


def settings(**plugins: Any) -> Settings:
    return Settings.model_validate({"plugins": plugins})


@pytest.fixture
def installed(fake_site: Path) -> Path:
    """An unrelated stage plugin, a third-party detector and a differently written distribution."""
    write_fake_distribution(
        fake_site,
        "ck-sample",
        "1.0",
        {STAGES: {"sample": "ck_sample:SampleStage"}},
        {"ck_sample.py": STAGE_MODULE},
    )
    write_fake_distribution(
        fake_site,
        "evil-plugin",
        "6.6.6",
        {DETECTORS: {"foo": "evil_plugin:Foo"}, PROVIDERS: {"mock2": "evil_plugin:Foo"}},
        {"evil_plugin.py": DETECTOR_MODULE},
    )
    write_fake_distribution(
        fake_site,
        "Foo_Bar.plugin",
        "1.0",
        {DETECTORS: {"bar": "foo_bar_plugin:Foo"}},
        {"foo_bar_plugin.py": DETECTOR_MODULE},
    )
    return fake_site


def statuses(registry: Any) -> dict[tuple[str, str], str]:
    return {(row.dist, row.name): row.status for row in registry.rows()}


# --- a disallowed distribution is never imported -------------------------------------------------


def test_a_distribution_outside_the_allow_list_is_never_imported(installed: Path) -> None:
    registry = registry_from_environment(settings(allow_distributions=["codekavach"]))
    rows = statuses(registry)
    assert "evil_plugin" not in sys.modules
    assert "ck_sample" not in sys.modules
    assert rows[("evil-plugin", "foo")] == "disabled"
    assert rows[("evil-plugin", "mock2")] == "disabled"
    assert rows[("ck-sample", "sample")] == "disabled"
    assert registry.detectors() == {}
    assert "evil_plugin" not in sys.modules


def test_without_settings_the_same_plugin_is_imported(installed: Path) -> None:
    # The control: it proves that the check above looks at a module that would have been loaded.
    registry = registry_from_environment()
    assert statuses(registry)[("evil-plugin", "foo")] == "ok"
    assert "evil_plugin" in sys.modules


def test_an_empty_allow_list_allows_every_distribution(installed: Path) -> None:
    registry = registry_from_environment(settings())
    assert statuses(registry)[("evil-plugin", "foo")] == "ok"
    assert "evil_plugin" in sys.modules


def test_an_allowed_distribution_loads_and_the_others_stay_out(installed: Path) -> None:
    registry = registry_from_environment(settings(allow_distributions=["ck-sample"]))
    assert list(registry.stages()) == ["sample"]
    assert "ck_sample" in sys.modules
    assert "evil_plugin" not in sys.modules
    assert statuses(registry)[("evil-plugin", "foo")] == "disabled"


def test_distribution_names_are_normalised(installed: Path) -> None:
    registry = registry_from_environment(settings(allow_distributions=["foo-bar-plugin"]))
    assert statuses(registry)[("Foo_Bar.plugin", "bar")] == "ok"
    assert "foo_bar_plugin" in sys.modules
    other = registry_from_environment(settings(allow_distributions=["FOO_BAR.PLUGIN"]))
    assert statuses(other)[("Foo_Bar.plugin", "bar")] == "ok"


# --- the disable-list ---------------------------------------------------------------------------


def test_a_disabled_stage_is_not_in_the_registry_and_not_imported(installed: Path) -> None:
    registry = registry_from_environment(settings(disable=["stage:sample"]))
    assert registry.stages() == {}
    assert "ck_sample" not in sys.modules
    assert statuses(registry)[("ck-sample", "sample")] == "disabled"
    row = next(row for row in registry.rows() if row.name == "sample")
    assert (row.kind, row.group, row.status, row.category) == ("stage", STAGES, "disabled", None)


def test_the_kind_is_part_of_the_disable_entry(installed: Path) -> None:
    registry = registry_from_environment(settings(disable=["detector:sample"]))
    assert list(registry.stages()) == ["sample"]


def test_disabling_does_not_touch_other_plugins(installed: Path) -> None:
    registry = registry_from_environment(settings(disable=["detector:foo"]))
    rows = statuses(registry)
    assert rows[("evil-plugin", "foo")] == "disabled"
    assert rows[("evil-plugin", "mock2")] == "ok"


# --- the settings that carry the policy ----------------------------------------------------------


def test_the_privacy_stages_cannot_be_disabled(config_sandbox: ConfigSandbox) -> None:
    for stage in ("stage:privacy-prepare", "stage:restore"):
        config_sandbox.write_user(f'[plugins]\ndisable = ["{stage}"]\n')
        with pytest.raises(ConfigError) as info:
            config_sandbox.load()
        assert [issue.code for issue in info.value.issues] == [ConfigErrorCode.CK_CFG_003]
        assert "llm.enabled = false" in str(info.value.issues[0].message)


def test_both_keys_are_restricted_in_the_schema() -> None:
    schema = Settings.model_json_schema()
    properties = schema["$defs"]["PluginsSettings"]["properties"]
    assert properties["allow_distributions"]["x-ck-restricted"] is True
    assert properties["disable"]["x-ck-restricted"] is True


@pytest.mark.parametrize(
    "body",
    ['allow_distributions = ["evil-plugin"]', 'disable = ["detector:secrets"]'],
    ids=["allow", "disable"],
)
def test_an_untrusted_project_cannot_change_the_plugin_policy(
    body: str, config_sandbox: ConfigSandbox
) -> None:
    config_sandbox.write_project(f"[plugins]\n{body}\n")
    with pytest.raises(ConfigError) as info:
        config_sandbox.load()
    assert [issue.code for issue in info.value.issues] == [ConfigErrorCode.CK_CFG_040]
    loaded = config_sandbox.load(trust_project_config=True)
    assert loaded.settings.plugins.model_dump()  # a trusted project may set it


def test_the_user_file_sets_the_policy_that_reaches_the_registry(
    installed: Path, config_sandbox: ConfigSandbox
) -> None:
    config_sandbox.write_user('[plugins]\nallow_distributions = ["codekavach"]\n')
    loaded = config_sandbox.load()
    registry = registry_from_environment(loaded.settings)
    assert statuses(registry)[("evil-plugin", "foo")] == "disabled"
    assert "evil_plugin" not in sys.modules


# --- the runner builds its registry from the same settings ---------------------------------------


def test_the_runner_applies_the_settings_when_it_builds_the_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[object] = []
    plan: Any = SimpleNamespace(infos={})

    def fake_registry(*args: object) -> str:
        received.extend(args)
        return "registry"

    monkeypatch.setattr(runner, "registry_from_environment", fake_registry)
    monkeypatch.setattr(runner, "build_plan", lambda *args, **kwargs: plan)
    chosen = settings(allow_distributions=["codekavach"])
    assert runner._checked_plan(None, chosen, (), None, ()) is plan
    assert received == [chosen]
