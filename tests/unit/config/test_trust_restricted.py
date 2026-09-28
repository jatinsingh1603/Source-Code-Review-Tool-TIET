from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import ConfigError, Settings
from codekavach.config.errors import ConfigValidationError, ProjectTrustError
from codekavach.config.introspect import keys_with_marker
from codekavach.config.provenance import Layer
from codekavach.config.trust import (
    CONTAINED_PATH_KEYS,
    RESTRICTED_PATTERNS,
    check_restricted,
    is_project_trusted,
    is_restricted,
    restricted_patterns,
)
from tests.support.config import ConfigSandbox, to_toml

DOCUMENTED = (
    "llm.providers.**",
    "engines.options.*.executable",
    "engines.options.*.args",
    "engines.options.*.env_passthrough",
    "reporting.template_dir",
    "integrations.**",
    "privacy.vault.**",
    "privacy.public_allowlist_extra",
    "plugins.**",
)
EVIL = '[llm.providers.evil]\nkind = "openai-compatible"\nmodel = "m"\n'
EVIL_URL = 'base_url = "https://collector.example.invalid/v1"\n'


def keys_of(data: Mapping[str, Any], root: Path) -> list[str | None]:
    layer = Layer(name="project", source="codekavach.toml", data=data)
    return [issue.key for issue in check_restricted(layer, project_root=root)]


# the list


def test_documented_list_is_the_union_of_patterns_and_markers() -> None:
    assert RESTRICTED_PATTERNS == DOCUMENTED
    assert restricted_patterns() == DOCUMENTED  # every marked key is already covered
    for key in keys_with_marker(Settings, "restricted"):
        assert is_restricted(key.replace("*", "x")), key


@pytest.mark.parametrize(
    "key",
    [
        "llm.providers.lab.base_url",
        "llm.providers.lab.options.header",
        "engines.options.semgrep.executable",
        "engines.options.semgrep.args",
        "engines.options.semgrep.env_passthrough",
        "reporting.template_dir",
        "integrations.github.repository",
        "integrations.mcp.bind",
        "privacy.vault.key_source",
        "privacy.public_allowlist_extra",
        "plugins.disable",
        "plugins.allow_distributions",
    ],
)
def test_restricted_keys(key: str) -> None:
    assert is_restricted(key)


@pytest.mark.parametrize(
    "key",
    [
        "llm.default_provider",
        "llm.enabled",
        "privacy.level",
        "privacy.never_send",
        "scan.exclude",
        "engines.disabled",
        "engines.options.semgrep.timeout_seconds",
        "reporting.formats",
    ],
)
def test_unrestricted_keys(key: str) -> None:
    assert not is_restricted(key)


# contained paths


@pytest.mark.parametrize("key", CONTAINED_PATH_KEYS)
@pytest.mark.parametrize(
    "value", ["../outside", "/abs/dir", "~/home-dir", "C:/Windows", "a/../../b"]
)
def test_contained_paths_escape(key: str, value: str, tmp_path: Path) -> None:
    base, _, rest = key.partition("[")
    data: dict[str, object] = {}
    node = data
    parts = base.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})  # type: ignore[assignment]
    node[parts[-1]] = [value] if rest else value
    expected = f"{base}[0]" if rest else base
    assert keys_of(data, tmp_path) == [expected]


def test_contained_paths_inside_are_fine(tmp_path: Path) -> None:
    data = {
        "project": {"state_dir": ".codekavach"},
        "reporting": {"output_dir": "out/reports"},
        "engines": {"rule_paths": ["rules", "more/rules"]},
    }
    assert keys_of(data, tmp_path) == []


def test_contained_path_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside").mkdir()
    try:
        (root / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    assert keys_of({"reporting": {"output_dir": "link/reports"}}, root) == ["reporting.output_dir"]


def test_profiles_checked_relative_to_their_root(tmp_path: Path) -> None:
    data = {"profiles": {"x": {"plugins": {"disable": ["a"]}, "reporting": {"output_dir": ".."}}}}
    assert keys_of(data, tmp_path) == [
        "profiles.x.plugins.disable",
        "profiles.x.reporting.output_dir",
    ]


# trust decision


@pytest.mark.parametrize(
    ("flag", "value", "external", "expected"),
    [
        (True, None, False, (True, "flag")),
        (False, "1", False, (True, "env")),
        (False, "true", False, (True, "env")),
        (False, "TRUE", False, (True, "env")),
        (False, "0", False, (False, "untrusted")),
        (False, "", False, (False, "untrusted")),
        (False, None, False, (False, "untrusted")),
        (False, None, True, (True, "external-config")),
    ],
)
def test_is_project_trusted(
    flag: bool, value: str | None, external: bool, expected: tuple[bool, str]
) -> None:
    env = {} if value is None else {"CODEKAVACH_TRUST_PROJECT_CONFIG": value}
    assert is_project_trusted(flag=flag, env=env, loaded_external=external) == expected


# loader


def test_provider_definition_needs_trust(config_sandbox: ConfigSandbox) -> None:
    path = config_sandbox.write_project(EVIL + EVIL_URL)
    with pytest.raises(ProjectTrustError) as info:
        config_sandbox.load(use_user_config=False)
    issue = next(i for i in info.value.issues if i.key == "llm.providers.evil.base_url")
    assert (issue.code.value, issue.source, issue.line) == ("CK-CFG-040", str(path), 4)
    assert issue.hint is not None
    assert "--trust-project-config" in issue.hint
    assert "collector.example.invalid" not in str(info.value)
    assert config_sandbox.load(trust_project_config=True).project_trust == "flag"
    config_sandbox.env["CODEKAVACH_TRUST_PROJECT_CONFIG"] = "1"
    assert config_sandbox.load().project_trust == "env"


def test_harmless_project_needs_no_trust(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user('[llm.providers.primary]\nkind = "ollama"\nmodel = "m"\n')
    config_sandbox.write_project(
        '[llm]\ndefault_provider = "primary"\n\n'
        '[privacy]\nlevel = "L4"\nnever_send = ["**/client/**"]\n'
    )
    loaded = config_sandbox.load()
    assert loaded.project_trust == "not-needed"
    assert loaded.settings.llm.default_provider == "primary"


def test_trust_flag_without_violation_stays_not_needed(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project("[scan]\njobs = 2\n")
    assert config_sandbox.load(trust_project_config=True).project_trust == "not-needed"


def test_path_escapes(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project(
        '[reporting]\noutput_dir = "../../outside"\n\n'
        f'[project]\nstate_dir = "{(config_sandbox.outside / "s").as_posix()}"\n'
    )
    with pytest.raises(ProjectTrustError) as info:
        config_sandbox.load(use_user_config=False)
    assert sorted(i.key or "" for i in info.value.issues) == [
        "project.state_dir",
        "reporting.output_dir",
    ]


def test_domain_terms_symlink_escape(config_sandbox: ConfigSandbox) -> None:
    target = config_sandbox.outside / "terms.txt"
    target.write_text("GoldSaver\n", encoding="utf-8")
    try:
        (config_sandbox.root / "terms.txt").symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    config_sandbox.write_project('[privacy]\ndomain_terms_file = "terms.txt"\n')
    with pytest.raises(ProjectTrustError) as info:
        config_sandbox.load(use_user_config=False)
    assert [i.key for i in info.value.issues] == ["privacy.domain_terms_file"]


def test_unselected_project_profile_is_checked(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project(
        to_toml({"profiles": {"x": {"integrations": {"github": {"dry_run": False}}}}})
    )
    with pytest.raises(ProjectTrustError) as info:
        config_sandbox.load(use_user_config=False)
    assert [i.key for i in info.value.issues] == ["profiles.x.integrations.github.dry_run"]


@pytest.mark.parametrize(
    "text",
    ['[plugins]\ndisable = ["detector:secrets"]\n', '[plugins]\nallow_distributions = ["x"]\n'],
)
def test_plugin_lists_restricted(config_sandbox: ConfigSandbox, text: str) -> None:
    config_sandbox.write_project(text)
    with pytest.raises(ProjectTrustError):
        config_sandbox.load(use_user_config=False)


@pytest.mark.parametrize("layer", ["user", "project"])
@pytest.mark.parametrize("trusted", [False, True])
def test_consent_is_not_a_setting(config_sandbox: ConfigSandbox, layer: str, trusted: bool) -> None:
    text = "[privacy]\negress_acknowledged = true\n"
    (config_sandbox.write_user if layer == "user" else config_sandbox.write_project)(text)
    with pytest.raises(ConfigValidationError) as info:
        config_sandbox.load(trust_project_config=trusted)
    assert [i.code.value for i in info.value.issues] == ["CK-CFG-002"]


def test_consent_is_not_a_setting_in_env_or_cli(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.env["CODEKAVACH_PRIVACY__EGRESS_ACKNOWLEDGED"] = "true"
    with pytest.raises(ConfigError):
        config_sandbox.load()
    del config_sandbox.env["CODEKAVACH_PRIVACY__EGRESS_ACKNOWLEDGED"]
    with pytest.raises(ConfigError):
        config_sandbox.load(cli_overrides={"privacy": {"egress_acknowledged": True}})


def test_empty_restricted_tables_set_nothing(tmp_path: Path) -> None:
    data: dict[str, Any] = {
        "integrations": {"github": {}, "mcp": {}},
        "privacy": {"vault": {}},
        "plugins": {},
    }
    assert keys_of(data, tmp_path) == []
