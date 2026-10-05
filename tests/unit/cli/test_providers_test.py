import ast
import importlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codekavach.cli import providers as providers_module
from codekavach.cli.providers import REASON_HINTS, probe_data, probe_lines
from codekavach.core.pipeline.context import ConsentDecision
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden" / "providers_test.txt"
TRUST = "--trust-project-config"
REGISTRY = "codekavach.core.plugins.registry.registry_from_environment"
PROBE = "codekavach.llm.providers.probe_provider"
RAW_ERROR = (
    "401 Unauthorized: invalid x-api-key sk-test-PLANTEDKEYVALUE0000"  # pragma: allowlist secret
)
CONFIG = """
[llm.providers.primary]
kind = "anthropic"
model = "claude-test"

[llm.providers.lab]
kind = "ollama"
model = "qwen2.5-coder:7b"

[llm.providers.spare]
kind = "openai"
model = "gpt-test"
enabled = false

[llm.providers.exotic]
kind = "gemini"
model = "g-test"
"""


@dataclass
class FakeProbe:
    """A scripted ``probe_provider``; ``failures`` maps a provider id to a reason code."""

    failures: dict[str, str] = field(default_factory=dict)
    structured_state: str = "passed"
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, provider_id: str, settings: Any, **options: Any) -> Any:
        self.calls.append({"provider_id": provider_id, "settings": settings, **options})
        provider = settings.llm.providers[provider_id]
        reason = self.failures.get(provider_id)
        return SimpleNamespace(
            ok=reason is None,
            provider_id=provider_id,
            kind=str(provider.kind),
            model=options["model"] or provider.model or "mock-1",
            latency_ms=412,
            prompt_tokens=9,
            completion_tokens=2,
            structured_output=self.structured_state if options["structured"] else "not-tested",
            ledger_seq=None if reason else 43,
            reason_code=reason,
            raw_error=RAW_ERROR if reason else None,
            response_headers={"x-request-id": "planted-request-id"},
        )


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    (project_dir / "codekavach.toml").write_text(CONFIG, encoding="utf-8")
    return project_dir


@pytest.fixture
def probe(monkeypatch: pytest.MonkeyPatch) -> FakeProbe:
    kinds = {kind: SimpleNamespace(capabilities=None) for kind in ("mock", "anthropic", "ollama")}
    fake_backend(monkeypatch, REGISTRY, lambda: SimpleNamespace(providers=lambda: kinds))
    fake = FakeProbe()
    fake_backend(monkeypatch, PROBE, fake)
    return fake


def run(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["providers", "test", TRUST, *args], cwd=project, **kwargs)


# success


def test_mock_is_a_local_test_double(cli: Cli, project: Path, probe: FakeProbe) -> None:
    result = run(cli, project, "mock")
    assert result.exit_code == 0, result.stderr
    assert "local test double: no network request was made" in result.stdout
    assert "provider mock (mock, mock-1): OK in 412 ms, 9 prompt + 2 completion tokens" in (
        result.stdout
    )
    assert "recorded in ledger as seq 43" in result.stdout
    (call,) = probe.calls
    assert call["provider_id"] == "mock"
    assert (call["consent"], call["timeout"], call["structured"]) == (None, 30.0, False)
    default = run(cli, project)
    assert default.exit_code == 0
    assert probe.calls[1]["provider_id"] == "mock"  # auto resolves to mock until E22 lands


def test_local_provider_output_and_json(cli: Cli, project: Path, probe: FakeProbe) -> None:
    human = run(cli, project, "lab")
    assert human.exit_code == 0, human.stderr
    assert_matches_golden(human.stdout, GOLDEN)
    machine = run(cli, project, "lab", "--json")
    assert machine.json["data"] == {
        "results": [
            {
                "ok": True,
                "provider_id": "lab",
                "kind": "ollama",
                "model": "qwen2.5-coder:7b",
                "latency_ms": 412,
                "prompt_tokens": 9,
                "completion_tokens": 2,
                "structured_output": "not-tested",
                "ledger_seq": 43,
                "reason_code": None,
                "hint": None,
            }
        ]
    }


def test_structured_and_model_options(cli: Cli, project: Path, probe: FakeProbe) -> None:
    result = run(cli, project, "lab", "--structured", "--model", "other-model", "--timeout", "5")
    assert "structured output: passed" in result.stdout
    assert "(ollama, other-model)" in result.stdout
    (call,) = probe.calls
    assert (call["model"], call["structured"], call["timeout"]) == ("other-model", True, 5.0)
    probe.structured_state = "failed"
    failed = run(cli, project, "lab", "--structured", "--json")
    assert failed.json["data"]["results"][0]["structured_output"] == "failed"
    plain = run(cli, project, "lab", "--json")
    assert plain.json["data"]["results"][0]["structured_output"] == "not-tested"


# pre-flight


def test_unknown_disabled_and_adapterless_providers_exit_2(
    cli: Cli, project: Path, probe: FakeProbe
) -> None:
    unknown = run(cli, project, "nope")
    assert unknown.exit_code == 2
    assert "error[unknown_provider]" in unknown.stderr
    assert "exotic, lab, mock, primary, spare" in unknown.stderr
    disabled = run(cli, project, "spare")
    assert (disabled.exit_code, "error[provider_disabled]" in disabled.stderr) == (2, True)
    missing = run(cli, project, "exotic", "--accept-egress")
    assert (missing.exit_code, "error[backend_unavailable]" in missing.stderr) == (2, True)
    both = run(cli, project, "lab", "--all")
    assert both.exit_code == 2
    assert probe.calls == []


def test_remote_provider_is_refused_offline(cli: Cli, project: Path, probe: FakeProbe) -> None:
    offline = run(cli, project, "primary", "--offline", "--accept-egress")
    assert offline.exit_code == 3
    assert "error[remote_not_allowed]" in offline.stderr
    configured = run(cli, project, "primary", "--set", "llm.allow_remote=false", "--accept-egress")
    assert (configured.exit_code, "remote_not_allowed" in configured.stderr) == (3, True)
    assert probe.calls == []
    assert run(cli, project, "lab", "--offline").exit_code == 0  # a local provider still works


def test_remote_provider_needs_consent(cli: Cli, project: Path, probe: FakeProbe) -> None:
    refused = run(cli, project, "primary")
    assert refused.exit_code == 3
    assert "error[consent_required]: remote provider 'primary' has not been approved" in (
        refused.stderr
    )
    assert probe.calls == []
    accepted = run(cli, project, "primary", "--accept-egress")
    assert accepted.exit_code == 0, accepted.stderr
    (call,) = probe.calls
    assert call["consent"] == ConsentDecision(granted=True, source="flag")
    assert "remote egress to primary accepted via flag" in accepted.stderr
    assert "local test double" not in accepted.stdout


def test_preflight_order(cli: Cli, project: Path, probe: FakeProbe) -> None:
    """Disabled beats missing adapter beats remote-not-allowed beats consent."""
    (project / "codekavach.toml").write_text(
        CONFIG.replace('model = "g-test"', 'model = "g-test"\nenabled = false'), encoding="utf-8"
    )
    assert "provider_disabled" in run(cli, project, "exotic", "--offline").stderr
    (project / "codekavach.toml").write_text(CONFIG, encoding="utf-8")
    assert "backend_unavailable" in run(cli, project, "exotic", "--offline").stderr
    assert "remote_not_allowed" in run(cli, project, "primary", "--offline").stderr
    assert "consent_required" in run(cli, project, "primary").stderr
    assert probe.calls == []


# failures


@pytest.mark.parametrize("reason", sorted(REASON_HINTS))
def test_each_failure_reason_exits_1_with_its_hint(
    cli: Cli, project: Path, probe: FakeProbe, reason: str
) -> None:
    probe.failures["lab"] = reason
    result = run(cli, project, "lab")
    assert result.exit_code == 1
    assert f"provider lab (ollama, qwen2.5-coder:7b): FAILED ({reason})" in result.stdout
    assert f"hint: {REASON_HINTS[reason]}" in " ".join(result.stdout.split())
    machine = run(cli, project, "lab", "--json")
    entry = machine.json["data"]["results"][0]
    assert (machine.json["exit_code"], entry["ok"], entry["reason_code"]) == (1, False, reason)
    assert entry["hint"] == REASON_HINTS[reason]


@pytest.mark.parametrize("flags", [(), ("-v",), ("-vv",), ("-vvv",), ("--debug",), ("--json",)])
def test_raw_error_body_is_never_shown(
    cli: Cli, project: Path, probe: FakeProbe, flags: tuple[str, ...]
) -> None:
    probe.failures["lab"] = "unauthorised"
    result = run(cli, project, "lab", *flags)
    assert result.exit_code == 1
    combined = result.stdout + result.stderr
    for planted in ("PLANTEDKEYVALUE", "401 Unauthorized", "planted-request-id", "x-api-key"):
        assert planted not in combined


def test_unknown_reason_becomes_bad_response() -> None:
    odd = SimpleNamespace(ok=False, reason_code=RAW_ERROR, model=None, latency_ms=True)
    data = probe_data(odd, provider_id="lab", kind="ollama")
    assert (data["reason_code"], data["latency_ms"], data["model"]) == ("bad_response", None, None)
    assert probe_lines(data)[0] == "provider lab (ollama, default model): FAILED (bad_response)"
    truthy = SimpleNamespace(ok="yes")
    assert probe_data(truthy, provider_id="lab", kind="ollama")["ok"] is False


# --all


def test_all_tests_every_enabled_provider_and_then_decides(
    cli: Cli, project: Path, probe: FakeProbe, monkeypatch: pytest.MonkeyPatch
) -> None:
    kinds = {name: SimpleNamespace() for name in ("mock", "anthropic", "ollama", "gemini")}
    fake_backend(monkeypatch, REGISTRY, lambda: SimpleNamespace(providers=lambda: kinds))
    probe.failures["lab"] = "unreachable"
    result = run(cli, project, "--all", "--accept-egress", "--json")
    assert result.exit_code == 1
    results = result.json["data"]["results"]
    assert [entry["provider_id"] for entry in results] == ["mock", "primary", "lab", "exotic"]
    assert [entry["ok"] for entry in results] == [True, True, False, True]
    assert [call["provider_id"] for call in probe.calls] == ["mock", "primary", "lab", "exotic"]
    probe.calls.clear()
    refused = run(cli, project, "--all")
    assert refused.exit_code == 3  # no consent for the remote ones: nothing at all is sent
    assert probe.calls == []
    probe.failures.clear()
    assert run(cli, project, "--all", "--accept-egress").exit_code == 0


# the module


def test_module_imports_no_network_client_and_no_transport() -> None:
    source = Path(providers_module.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)
    forbidden = ("httpx", "requests", "urllib.request", "socket", "codekavach.privacy.egress")
    assert not [name for name in imported if name.startswith(forbidden)]
    assert "open(" not in source  # no project file is read here


def probe_in_this_build() -> bool:
    """Whether E22 has delivered ``probe_provider`` (the package itself exists since E01)."""
    try:
        module = importlib.import_module("codekavach.llm.providers")
    except ImportError:
        return False
    return hasattr(module, "probe_provider")


@pytest.mark.skipif(
    not probe_in_this_build(),
    reason="needs the provider adapters (E22) and the egress ledger (E12)",
)
def test_mock_probe_writes_a_ledger_entry(cli: Cli, project: Path) -> None:
    result = run(cli, project, "mock", "--json")
    assert result.exit_code == 0, result.stderr
    assert result.json["data"]["results"][0]["ledger_seq"] is not None
    shown = cli(["privacy", "ledger", "show", "--json"], cwd=project)
    assert "probe" in shown.stdout
