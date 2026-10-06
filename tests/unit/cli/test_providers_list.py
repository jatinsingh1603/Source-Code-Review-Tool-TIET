from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codekavach.cli import backends
from codekavach.config import keys as keys_module
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden" / "providers_list.txt"
TRUST = "--trust-project-config"
REGISTRY = "codekavach.core.plugins.registry.registry_from_environment"
RESOLVER = "codekavach.llm.selection.resolve_default_provider"
KEY_VARIABLE = "CK_TEST_PRIMARY_KEY"
PLANTED_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
THREE = f"""
[llm.providers.primary]
kind = "anthropic"
model = "claude-test"
api_key = "env:{KEY_VARIABLE}"  # pragma: allowlist secret (a reference, not a key)

[llm.providers.lab]
kind = "ollama"
model = "qwen2.5-coder:7b"

[llm.providers.gateway]
kind = "openai-compatible"
model = "gw-1"
base_url = "https://llm.internal.example:8443/v1"
enabled = false
"""  # pragma: allowlist secret


@dataclass(frozen=True)
class FakeCapabilities:
    structured_output: bool = True
    tool_calling: bool = False
    context_window: int | None = 200_000
    batch: bool = False
    local: bool = False


def registry(**kinds: FakeCapabilities) -> Callable[..., Any]:
    adapters = {kind: SimpleNamespace(capabilities=value) for kind, value in kinds.items()}
    return lambda *_settings: SimpleNamespace(providers=lambda: adapters)


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    (project_dir / "codekavach.toml").write_text(THREE, encoding="utf-8")
    return project_dir


@pytest.fixture
def adapters_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_backend(
        monkeypatch,
        REGISTRY,
        registry(
            mock=FakeCapabilities(local=True, context_window=None), anthropic=FakeCapabilities()
        ),
    )


def listing(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["providers", "list", TRUST, *args], cwd=project, **kwargs)


def by_id(result: CliResult) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in result.json["data"]["providers"]}


def test_table_matches_the_golden_file(cli: Cli, project: Path, adapters_installed: None) -> None:
    result = listing(cli, project)
    assert result.exit_code == 0, result.stderr
    assert_matches_golden(result.stdout, GOLDEN)
    lines = result.stdout.splitlines()
    assert [line.split()[1] for line in lines if line.startswith("*")] == ["mock"]
    assert lines[-1] == 'default: mock (llm.default_provider = "auto")'
    assert "warning[auto_resolution_unavailable]" in result.stderr
    assert "gateway" not in result.stdout  # disabled providers need --all


def test_json_has_the_same_fields(cli: Cli, project: Path, adapters_installed: None) -> None:
    result = listing(cli, project, "--json")
    data = result.json["data"]
    assert set(data) == {"default", "llm_enabled", "allow_remote", "providers"}
    assert (data["default"], data["llm_enabled"], data["allow_remote"]) == ("mock", True, True)
    rows = by_id(result)
    assert list(rows) == ["mock", "primary", "lab"]
    assert rows["primary"] == {
        "id": "primary",
        "kind": "anthropic",
        "model": "claude-test",
        "enabled": True,
        "blocked": False,
        "locality": "remote",
        "host": None,
        "trust_tier": "public",
        "min_level": "L3",
        "credential": "unchecked",
        "credential_refs": [f"env:{KEY_VARIABLE}"],
        "adapter": "available",
        "capabilities": {
            "structured_output": True,
            "tool_calling": False,
            "context_window": 200_000,
            "batch": False,
            "local": False,
        },
        "default": False,
    }
    assert (rows["mock"]["default"], rows["mock"]["credential"]) == (True, "not-required")
    assert (rows["lab"]["locality"], rows["lab"]["adapter"]) == ("local", "missing")
    assert rows["lab"]["capabilities"] is None
    assert [warning["code"] for warning in result.json["warnings"]] == [
        "auto_resolution_unavailable"
    ]


def test_default_marking(
    cli: Cli, project: Path, adapters_installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend(monkeypatch, RESOLVER, lambda _settings: "lab")
    resolved = listing(cli, project, "--json")
    assert resolved.json["data"]["default"] == "lab"
    assert resolved.json["warnings"] == []
    assert by_id(resolved)["lab"]["default"] is True
    monkeypatch.delitem(
        backends._OVERRIDES, ("codekavach.llm.selection", "resolve_default_provider")
    )
    concrete = listing(cli, project, "--set", 'llm.default_provider="primary"', "--json")
    assert concrete.json["data"]["default"] == "primary"
    assert concrete.json["warnings"] == []
    human = listing(cli, project, "--set", 'llm.default_provider="primary"')
    assert human.stdout.splitlines()[-1] == 'default: primary (llm.default_provider = "primary")'


def test_secrets_are_not_checked_by_default(
    cli: Cli, project: Path, adapters_installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("no credential lookup without --check-secrets")

    monkeypatch.setattr(keys_module, "secret_status", forbidden)
    monkeypatch.setattr(keys_module, "open_keyring", forbidden)
    result = listing(cli, project, "--json", env={KEY_VARIABLE: PLANTED_KEY})
    assert result.exit_code == 0, result.stderr
    assert by_id(result)["primary"]["credential"] == "unchecked"
    assert PLANTED_KEY not in result.stdout + result.stderr


def test_check_secrets_reports_the_state_and_no_value(
    cli: Cli, project: Path, adapters_installed: None
) -> None:
    unset = listing(cli, project, "--check-secrets", "--json")
    assert by_id(unset)["primary"]["credential"] == "not-set"
    for arguments in (("--json",), ()):
        provided = listing(
            cli, project, "--check-secrets", *arguments, env={KEY_VARIABLE: PLANTED_KEY}
        )
        assert provided.exit_code == 0, provided.stderr
        assert PLANTED_KEY not in provided.stdout + provided.stderr
    assert (
        by_id(listing(cli, project, "--check-secrets", "--json", env={KEY_VARIABLE: PLANTED_KEY}))[
            "primary"
        ]["credential"]
        == "set"
    )


def test_offline_and_disallowed_remote_are_shown_as_blocked(
    cli: Cli, project: Path, adapters_installed: None
) -> None:
    offline = listing(cli, project, "--offline")
    assert offline.exit_code == 0, offline.stderr
    assert "blocked (remote not allowed)" in " ".join(offline.stdout.split())
    rows = by_id(listing(cli, project, "--offline", "--json"))
    assert (rows["primary"]["blocked"], rows["lab"]["blocked"]) == (True, False)
    configured = listing(cli, project, "--set", "llm.allow_remote=false", "--json")
    assert configured.json["data"]["allow_remote"] is False
    assert by_id(configured)["primary"]["blocked"] is True


def test_llm_disabled_and_all(cli: Cli, project: Path, adapters_installed: None) -> None:
    disabled = listing(cli, project, "--no-user-config", "--set", "llm.enabled=false")
    assert disabled.stdout.splitlines()[0] == "LLM review is disabled (llm.enabled = false)"
    assert "default:" not in disabled.stdout
    machine = listing(cli, project, "--set", "llm.enabled=false", "--json")
    assert (machine.json["data"]["default"], machine.json["data"]["llm_enabled"]) == (None, False)
    everything = by_id(listing(cli, project, "--all", "--json"))
    assert list(everything) == ["mock", "primary", "lab", "gateway"]
    gateway = everything["gateway"]
    assert (gateway["enabled"], gateway["host"]) == (False, "llm.internal.example")
    shown = listing(cli, project, "--all")
    assert "llm.internal.example" in shown.stdout
    assert "8443" not in shown.stdout
    assert "/v1" not in shown.stdout
    assert "https://" not in shown.stdout + listing(cli, project, "--all", "--json").stdout


def test_kinds(
    cli: Cli, project: Path, adapters_installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = cli(["providers", "list", "--kinds", "--json"], cwd=project)
    kinds = result.json["data"]["kinds"]
    assert [item["kind"] for item in kinds] == ["anthropic", "mock"]
    assert kinds[1]["capabilities"] == {
        "structured_output": True,
        "tool_calling": False,
        "context_window": None,
        "batch": False,
        "local": True,
    }
    human = cli(["providers", "list", "--kinds"], cwd=project)
    assert "anthropic" in human.stdout
    assert "200000" in human.stdout
    fake_backend(monkeypatch, REGISTRY, registry())
    empty = cli(["providers", "list", "--kinds"], cwd=project)
    assert "no provider adapter is installed in this build" in empty.stdout


def recording_registry(received: list[Any]) -> Callable[..., Any]:
    def build(*args: Any) -> Any:
        received.extend(args)
        return SimpleNamespace(providers=dict)

    return build


def test_kinds_are_listed_under_the_plugin_settings(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A valid configuration: the registry is built from its settings, so [plugins] applies.
    (project / "codekavach.toml").write_text("", encoding="utf-8")
    (isolated_home / "config.toml").write_text(
        '[plugins]\nallow_distributions = ["acme-rules"]\n', encoding="utf-8"
    )
    received: list[Any] = []
    fake_backend(monkeypatch, REGISTRY, recording_registry(received))
    assert cli(["providers", "list", "--kinds"], cwd=project).exit_code == 0
    assert len(received) == 1
    assert received[0].plugins.allow_distributions == ["acme-rules"]


def test_kinds_with_an_invalid_configuration_load_only_the_core_distribution(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Listing kinds does not need a valid configuration, but it must not import a third-party
    # plugin that the unreadable settings might have excluded.
    (project / "codekavach.toml").write_text('[privacy]\nlevel = "L9"\n', encoding="utf-8")
    received: list[Any] = []
    fake_backend(monkeypatch, REGISTRY, recording_registry(received))
    assert cli(["providers", "list", "--kinds"], cwd=project).exit_code == 0
    assert len(received) == 1
    assert received[0].plugins.allow_distributions == ["codekavach"]


def test_real_registry_without_adapters(cli: Cli, project: Path) -> None:
    rows = by_id(listing(cli, project, "--json"))
    assert {row["adapter"] for row in rows.values()} == {"missing"}
