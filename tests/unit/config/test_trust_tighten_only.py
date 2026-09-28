from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings

from codekavach.config import ConfigError, Settings
from codekavach.config.errors import ProjectTrustError
from codekavach.config.merge import deep_merge
from codekavach.config.trust import TIGHTEN_ONLY, check_tighten_only
from codekavach.core.models import PrivacyLevel
from tests.support.config import ConfigSandbox, isolate_config_env, to_toml
from tests.support.config_strategies import layer_sets

DEFAULTS = Settings().model_dump(mode="json")


def baseline(**sections: Any) -> dict[str, Any]:
    return deep_merge(DEFAULTS, sections)


def keys(candidate: dict[str, Any], base: dict[str, Any], prefix: str = "") -> list[str | None]:
    return [
        issue.key
        for issue in check_tighten_only(candidate, base, source="p.toml", text=None, prefix=prefix)
    ]


# (key, baseline sections, looser candidate, tighter-or-equal candidate)
MATRIX: list[tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]] = [
    (
        "privacy.level",
        {"privacy": {"level": "L3"}},
        {"privacy": {"level": "L2"}},
        {"privacy": {"level": "L0"}},
    ),
    (
        "privacy.min_level",
        {"privacy": {"min_level": "L2"}},
        {"privacy": {"min_level": "L1"}},
        {"privacy": {"min_level": "L4"}},
    ),
    (
        "privacy.provider_tier_levels.public",
        {},
        {"privacy": {"provider_tier_levels": {"public": "L2"}}},
        {"privacy": {"provider_tier_levels": {"public": "L4"}}},
    ),
    (
        "privacy.paths[0].level",
        {"privacy": {"level": "L3"}},
        {"privacy": {"paths": [{"pattern": "src/**", "level": "L1"}]}},
        {"privacy": {"paths": [{"pattern": "src/**", "level": "L4"}]}},
    ),
    (
        "llm.allow_remote",
        {"llm": {"allow_remote": False}},
        {"llm": {"allow_remote": True}},
        {"llm": {"allow_remote": False}},
    ),
    (
        "llm.enabled",
        {"llm": {"enabled": False}},
        {"llm": {"enabled": True}},
        {"llm": {"enabled": False}},
    ),
    (
        "scan.follow_symlinks",
        {"scan": {"follow_symlinks": False}},
        {"scan": {"follow_symlinks": True}},
        {"scan": {"follow_symlinks": False}},
    ),
    (
        "scan.skip_stages",
        {},
        {"scan": {"skip_stages": ["rate"]}},
        {"scan": {"skip_stages": ["sync", "report"]}},
    ),
]


def test_table_covers_the_documented_keys() -> None:
    assert set(TIGHTEN_ONLY) == {
        "privacy.level",
        "privacy.min_level",
        "privacy.provider_tier_levels.*",
        "llm.allow_remote",
        "llm.enabled",
        "scan.follow_symlinks",
        "scan.skip_stages",
    }


@pytest.mark.parametrize(("key", "base", "looser", "tighter"), MATRIX, ids=[m[0] for m in MATRIX])
@pytest.mark.parametrize("prefix", ["", "profiles.x."])
def test_matrix(
    key: str, base: dict[str, Any], looser: dict[str, Any], tighter: dict[str, Any], prefix: str
) -> None:
    assert keys(looser, baseline(**base), prefix) == [prefix + key]
    assert keys(tighter, baseline(**base), prefix) == []


@pytest.mark.parametrize("stage", ["privacy-prepare", "restore", "aggregate", "rate"])
def test_each_protected_stage(stage: str) -> None:
    assert keys({"scan": {"skip_stages": [stage]}}, baseline()) == ["scan.skip_stages"]
    already = baseline(scan={"skip_stages": [stage]})
    assert keys({"scan": {"skip_stages": [stage]}}, already) == []


def test_message_names_levels_and_baseline_origin() -> None:
    issue = check_tighten_only(
        {"privacy": {"level": "L2"}},
        baseline(),
        source="p.toml",
        text='[privacy]\nlevel = "L2"\n',
        baseline_origin=lambda key: "the built-in defaults",
    )[0]
    assert issue.code.value == "CK-CFG-041"
    assert issue.line == 2
    assert issue.message == (
        "an untrusted project configuration would lower privacy.level from L3 to L2; "
        "baseline from the built-in defaults"
    )


# path rules

NEVER = {"pattern": "fees/**", "never_send": True}
STRICT = {"pattern": "core/**", "level": "L4"}


@pytest.mark.parametrize(
    ("project_rules", "dropped"),
    [
        ([{"pattern": "other/**", "level": "L4"}], True),
        ([NEVER, {"pattern": "other/**", "level": "L4"}], True),  # STRICT dropped
        ([NEVER, STRICT], False),
        ([NEVER, {"pattern": "core/**", "never_send": True}], False),
        ([{"pattern": "fees/**", "level": "L4"}, STRICT], True),  # never_send downgraded
        ([NEVER, {"pattern": "core/**", "level": "L3"}], True),
    ],
)
def test_path_rules_dropping(project_rules: list[dict[str, Any]], dropped: bool) -> None:
    base = baseline(privacy={"paths": [NEVER, STRICT]})
    found = keys({"privacy": {"paths": project_rules}}, base)
    assert ("privacy.paths" in found) is dropped


def test_strict_project_level_covers_a_level_rule() -> None:
    base = baseline(privacy={"paths": [{"pattern": "core/**", "level": "L4"}]})
    assert keys({"privacy": {"level": "L0", "paths": []}}, base) == []


# loader


def load_error(sandbox: ConfigSandbox, **kwargs: Any) -> list[tuple[str, str | None]]:
    with pytest.raises(ProjectTrustError) as info:
        sandbox.load(**kwargs)
    return [(issue.code.value, issue.key) for issue in info.value.issues]


def test_level_below_baseline(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project('[privacy]\nlevel = "L2"\n')
    assert load_error(config_sandbox) == [("CK-CFG-041", "privacy.level")]
    for level in ("L2", "L1"):
        config_sandbox.write_user(f'[privacy]\nlevel = "{level}"\n')
        assert config_sandbox.load().settings.privacy.level is PrivacyLevel.L2


@pytest.mark.parametrize(
    "text",
    [
        '[privacy]\nlevel = "L4"\n',
        '[privacy]\nlevel = "L0"\n',
        '[privacy.provider_tier_levels]\npublic = "L4"\n',
        '[[privacy.paths]]\npattern = "fees/**"\nlevel = "L4"\n',
    ],
)
def test_tighter_values_need_no_trust(config_sandbox: ConfigSandbox, text: str) -> None:
    config_sandbox.write_project(text)
    assert config_sandbox.load().project_trust == "not-needed"


def test_project_selected_builtin_profile(config_sandbox: ConfigSandbox) -> None:
    user = config_sandbox.write_user('[privacy]\nlevel = "L4"\n')
    project = config_sandbox.write_project('# demo\nprofile = "demo"\n')
    with pytest.raises(ProjectTrustError) as info:
        config_sandbox.load()
    issue = info.value.issues[0]
    assert (issue.code.value, issue.source, issue.line) == ("CK-CFG-041", str(project), 2)
    assert issue.message == (
        "profile 'demo', selected by the project configuration, would lower privacy.level "
        f"from L4 to L3; baseline from {user}:2"
    )
    assert issue.hint == (
        "select the profile yourself (--profile demo or CODEKAVACH_PROFILE=demo), "
        "or trust this project."
    )
    assert config_sandbox.load(profile="demo").settings.privacy.level is PrivacyLevel.L3
    config_sandbox.env["CODEKAVACH_PROFILE"] = "demo"
    assert config_sandbox.load().settings.privacy.level is PrivacyLevel.L3


def test_project_selected_user_defined_profile(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user('[privacy]\nlevel = "L4"\n\n[profiles.quick.privacy]\nlevel = "L2"\n')
    config_sandbox.write_project('profile = "quick"\n')
    assert load_error(config_sandbox) == [("CK-CFG-041", "privacy.level")]


def test_no_profile_and_harmless_project_profile(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project('profile = "ci"\n')
    assert config_sandbox.load().profile == "ci"


def test_project_defined_profile_table(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project('[profiles.loose.privacy]\nlevel = "L1"\n')
    assert load_error(config_sandbox) == [("CK-CFG-041", "profiles.loose.privacy.level")]


def test_dropped_never_send_rule(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user('[[privacy.paths]]\npattern = "fees/**"\nnever_send = true\n')
    config_sandbox.write_project('[[privacy.paths]]\npattern = "docs/**"\nlevel = "L4"\n')
    assert load_error(config_sandbox) == [("CK-CFG-041", "privacy.paths")]


def test_allow_remote_and_skip_stages(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user("[llm]\nallow_remote = false\n")
    config_sandbox.write_project(
        '[llm]\nallow_remote = true\n\n[scan]\nskip_stages = ["privacy-prepare"]\n'
    )
    codes = load_error(config_sandbox)
    assert ("CK-CFG-041", "llm.allow_remote") in codes
    assert ("CK-CFG-041", "scan.skip_stages") in codes


@pytest.mark.parametrize(
    ("user", "project"),
    [
        ("", '[privacy]\nlevel = "L2"\n'),
        ('[privacy]\nlevel = "L4"\n', 'profile = "demo"\n'),
        ('[[privacy.paths]]\npattern = "f/**"\nnever_send = true\n', "[privacy]\npaths = []\n"),
        ("[llm]\nallow_remote = false\n", "[llm]\nallow_remote = true\n"),
        ("[llm]\nenabled = false\n", '[scan]\nskip_stages = ["rate"]\n'),
    ],
)
def test_trust_lifts_every_case(config_sandbox: ConfigSandbox, user: str, project: str) -> None:
    config_sandbox.write_user(user)
    config_sandbox.write_project(project)
    assert config_sandbox.load(trust_project_config=True).project_trust == "flag"


# property


@given(layer_sets())
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_accepted_project_layers_are_monotone(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    layers: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    user, project = layers
    both = ConfigSandbox(tmp_path_factory.mktemp("both"))
    user_only = ConfigSandbox(tmp_path_factory.mktemp("user"))
    isolate_config_env(monkeypatch, both.home)
    for sandbox in (both, user_only):
        if user:
            sandbox.write_user(to_toml(user))
    if project:
        both.write_project(to_toml(project))
    try:
        effective = both.load().settings
    except ConfigError:
        return
    base = user_only.load().settings
    assert effective.privacy.level.at_least(base.privacy.level)
    assert effective.privacy.min_level.at_least(base.privacy.min_level)
    for tier, level in base.privacy.provider_tier_levels.items():
        assert effective.privacy.provider_tier_levels[tier].at_least(level)
    assert effective.llm.allow_remote <= base.llm.allow_remote
