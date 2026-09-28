from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from pydantic import BaseModel

from codekavach.config import Settings
from codekavach.config.errors import ConfigValidationError
from codekavach.config.merge import deep_merge
from codekavach.config.provenance import Origin
from codekavach.config.validate import (
    STAGE_NAMES,
    UNSKIPPABLE_WITH_LLM,
    semantic_checks,
)
from codekavach.core.models import PrivacyLevel, TrustTier
from tests.support.config import ConfigSandbox
from tests.support.config_strategies import settings_dicts

ROOT = Path("/work/repo")
CLOUD = {"kind": "anthropic", "model": "m"}
LOCAL = {"kind": "ollama", "model": "m"}


def build(data: dict[str, Any]) -> Settings:
    return Settings.model_validate(data)


def patch(model: BaseModel, path: str, value: Any) -> Any:
    """A copy with one nested field replaced, bypassing validation (for re-checked rules)."""
    head, _, rest = path.partition(".")
    if not rest:
        return model.model_copy(update={head: value})
    return model.model_copy(update={head: patch(getattr(model, head), rest, value)})


def codes(s: Settings, root: Path = ROOT) -> list[str]:
    return [issue.code.value for issue in semantic_checks(s, {}, project_root=root)]


# llm rules


def test_030_disabled_default_provider() -> None:
    s = build({"llm": {"providers": {"p": {**LOCAL, "enabled": False}}}})
    assert codes(s) == []
    s = patch(s, "llm.default_provider", "p")
    assert codes(s) == ["CK-CFG-030"]


def test_031_remote_while_forbidden() -> None:
    data = {"llm": {"allow_remote": False, "default_provider": "p", "providers": {"p": CLOUD}}}
    assert codes(build(data)) == ["CK-CFG-031"]
    data["llm"]["providers"] = {"p": LOCAL}
    assert codes(build(data)) == []
    auto = {"llm": {"allow_remote": False, "providers": {"p": CLOUD}}}
    assert codes(build(auto)) == []


def test_032_l0_with_remote_provider() -> None:
    data: dict[str, Any] = {
        "privacy": {"level": "L0"},
        "llm": {"default_provider": "primary", "providers": {"primary": CLOUD}},
    }
    issues = semantic_checks(build(data), {}, project_root=ROOT)
    assert [issue.code.value for issue in issues] == ["CK-CFG-032"]
    assert issues[0].message == (
        "privacy.level is L0 (nothing leaves) but llm.default_provider 'primary' is a remote "
        "provider"
    )
    assert issues[0].hint == (
        "choose a local provider, set llm.enabled = false, or use a level from L1 to L4."
    )
    assert codes(build(deep_merge(data, {"llm": {"enabled": False}}))) == []
    assert codes(build(deep_merge(data, {"llm": {"default_provider": "auto"}}))) == []
    local = {
        "privacy": {"level": "L0"},
        "llm": {"default_provider": "x", "providers": {"x": LOCAL}},
    }
    assert codes(build(local)) == []


# privacy rules


def test_037_level_and_path_below_floor() -> None:
    s = build({"privacy": {"min_level": "L3", "paths": [{"pattern": "a/**", "level": "L4"}]}})
    assert codes(s) == []
    weak = patch(s, "privacy.level", PrivacyLevel.L2)
    assert codes(weak) == ["CK-CFG-037"]
    rule = s.privacy.paths[0].model_copy(update={"level": PrivacyLevel.L1})
    issues = semantic_checks(patch(s, "privacy.paths", [rule]), {}, project_root=ROOT)
    assert [(i.code.value, i.key) for i in issues] == [("CK-CFG-037", "privacy.paths[0].level")]


def test_038_public_tier_warning() -> None:
    s = build({"privacy": {"min_level": "L1", "provider_tier_levels": {"public": "L2"}}})
    issues = semantic_checks(s, {}, project_root=ROOT)
    assert [(i.code.value, i.severity) for i in issues] == [("CK-CFG-038", "warning")]
    ok = build({"privacy": {"provider_tier_levels": {TrustTier.PUBLIC.value: "L4"}}})
    assert codes(ok) == []


# path rules


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({}, []),
        ({"reporting": {"output_dir": "."}}, ["CK-CFG-070"]),
        ({"reporting": {"output_dir": ".codekavach/reports"}}, ["CK-CFG-070"]),
        ({"project": {"state_dir": "."}, "reporting": {"output_dir": "out"}}, ["CK-CFG-070"] * 2),
        ({"project": {"state_dir": "state"}, "reporting": {"output_dir": "state"}}, ["CK-CFG-070"]),
        ({"reporting": {"output_dir": "sub/../.codekavach"}}, ["CK-CFG-070"]),
    ],
)
def test_070_relative_paths(data: dict[str, Any], expected: list[str], tmp_path: Path) -> None:
    assert codes(build(data), tmp_path) == expected


def test_070_absolute_paths(tmp_path: Path) -> None:
    state = tmp_path / "elsewhere"
    s = build(
        {
            "project": {"state_dir": state.as_posix()},
            "reporting": {"output_dir": (state / "r").as_posix()},
        }
    )
    assert codes(s, tmp_path / "repo") == ["CK-CFG-070"]
    s = build({"reporting": {"output_dir": (tmp_path / "repo").as_posix()}})
    assert codes(s, tmp_path / "repo") == ["CK-CFG-070"]


def test_070_symlinked_output_into_state(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".codekavach").mkdir(parents=True)
    try:
        (root / "reports").symlink_to(root / ".codekavach", target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    assert codes(build({"reporting": {"output_dir": "reports"}}), root) == ["CK-CFG-070"]


# stage rules


def test_stage_names_match_pipeline() -> None:
    keys = pytest.importorskip("codekavach.core.pipeline.keys")
    assert keys.DEFAULT_STAGE_ORDER == STAGE_NAMES
    assert set(UNSKIPPABLE_WITH_LLM) <= set(STAGE_NAMES)


def test_unknown_stage_lists_valid_names() -> None:
    issues = semantic_checks(
        build({"scan": {"skip_stages": ["privcy-prepare"]}}), {}, project_root=ROOT
    )
    assert [i.code.value for i in issues] == ["CK-CFG-003"]
    assert issues[0].hint is not None
    for name in STAGE_NAMES:
        assert name in issues[0].hint
    assert codes(build({"scan": {"skip_stages": ["sync", "report"]}})) == []


@pytest.mark.parametrize("stage", UNSKIPPABLE_WITH_LLM)
def test_privacy_stages_unskippable_with_llm(stage: str) -> None:
    assert codes(build({"scan": {"skip_stages": [stage]}})) == ["CK-CFG-003"]
    assert codes(build({"scan": {"skip_stages": [stage]}, "llm": {"enabled": False}})) == []
    assert codes(build({"scan": {"skip_stages": [stage, "llm-review"]}})) == []


# collection and origins


def test_three_rules_in_one_error(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project(
        '[privacy]\nlevel = "L0"\n\n[scan]\nskip_stages = ["restore"]\n\n'
        '[reporting]\noutput_dir = "."\n\n'
        '[llm]\ndefault_provider = "primary"\n\n[llm.providers.primary]\n'
        'kind = "anthropic"\nmodel = "m"\n'
    )
    with pytest.raises(ConfigValidationError) as info:
        config_sandbox.load(use_user_config=False)
    found = [(i.code.value, i.key, i.line) for i in info.value.issues]
    assert found == [
        ("CK-CFG-032", "privacy.level", 2),
        ("CK-CFG-070", "reporting.output_dir", 8),
        ("CK-CFG-003", "scan.skip_stages", 5),
    ]


def test_warning_reaches_loaded_config(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project('[privacy.provider_tier_levels]\npublic = "L2"\n')
    loaded = config_sandbox.load(use_user_config=False)
    assert [(w.code.value, w.line) for w in loaded.warnings] == [("CK-CFG-038", 2)]


def test_origins_are_used() -> None:
    s = build({"scan": {"skip_stages": ["nope"]}})
    origin = Origin(layer="env", source="CODEKAVACH_SCAN__SKIP_STAGES")
    issues = semantic_checks(s, {"scan.skip_stages": origin}, project_root=ROOT)
    assert issues[0].source == "CODEKAVACH_SCAN__SKIP_STAGES"


# properties


@given(settings_dicts())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_generated_settings(data: dict[str, Any]) -> None:
    s = build(data)
    issues = semantic_checks(s, {}, project_root=ROOT)
    default = s.llm.default_provider
    if default == "auto" or not s.llm.providers[default].is_remote:
        assert not {"CK-CFG-031", "CK-CFG-032"} & {issue.code.value for issue in issues}
