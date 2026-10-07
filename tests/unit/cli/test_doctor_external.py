"""The settings-driven checks of ``codekavach doctor``: engines, providers, reports (E05-21)."""

import itertools
import platform
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

import pytest

from codekavach.cli import doctor, doctor_checks
from codekavach.cli.consent import ConsentGrant, ConsentStore
from codekavach.cli.errors import BackendUnavailableError
from codekavach.cli.providers import REASON_HINTS
from codekavach.config import Settings
from codekavach.config.keys import SecretStatus
from codekavach.core.models import PrivacyLevel
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.core.plugins.discovery import PluginSpec
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend

Cli = Callable[..., CliResult]
TRUST = "--trust-project-config"
REGISTRY = "codekavach.core.plugins.registry.registry_from_environment"
PROBE = "codekavach.llm.providers.probe_provider"
PDF_PROBE = "codekavach.report.render.pdf.probe_pdf_prerequisites"
FONT_PROBE = "codekavach.report.render.fonts.find_fonts"
RAW_ERROR = "503 upstream said: secret-looking-transport-text-0000"  # a planted transport message
SECRET = "sk-test-PLANTEDSECRETVALUE1234"  # pragma: allowlist secret
CONFIG = """
[llm.providers.primary]
kind = "anthropic"
model = "claude-test"

[llm.providers.lab]
kind = "ollama"
model = "qwen-test"

[llm.providers.spare]
kind = "openai"
model = "gpt-test"
enabled = false

[engines]
enabled = ["semgrep", "gitleaks", "ghost"]
disabled = ["bandit"]

[engines.options.trivy]
enabled = false

[reporting]
formats = ["html", "pdf"]
"""
REMOTE_PROVIDER = "provider:primary:reachable"
LOCAL_PROVIDER = "provider:lab:reachable"


@dataclass
class FakeProbe:
    """A scripted ``probe_provider``."""

    reason: str | None = None
    raises: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, provider_id: str, settings: Any, **options: Any) -> Any:
        self.calls.append({"provider_id": provider_id, **options})
        if self.raises is not None:
            raise self.raises
        return SimpleNamespace(
            ok=self.reason is None,
            reason_code=self.reason,
            latency_ms=412,
            raw_error=RAW_ERROR if self.reason else None,
        )


def engine_adapter(*, available: bool, **fields: Any) -> Any:
    """An engine adapter whose probe reports the given result."""
    result = SimpleNamespace(available=available, **fields)
    return SimpleNamespace(probe=lambda settings: result)


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    (project_dir / "codekavach.toml").write_text(CONFIG, encoding="utf-8")
    return project_dir


@pytest.fixture(autouse=True)
def no_engine_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    """No installed engine plugin: the candidates come from the settings alone."""
    monkeypatch.setattr(doctor_checks, "discover", lambda groups: [])


@pytest.fixture
def engines(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The engine adapters of a fake registry; the test fills the dictionary."""
    adapters: dict[str, Any] = {}
    fake_backend(monkeypatch, REGISTRY, lambda *_s: SimpleNamespace(engines=lambda: adapters))
    return adapters


@pytest.fixture
def probe(monkeypatch: pytest.MonkeyPatch) -> FakeProbe:
    fake = FakeProbe()
    fake_backend(monkeypatch, PROBE, fake)
    return fake


def run(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["doctor", TRUST, "--json", *args], cwd=project, **kwargs)


def rows(result: CliResult) -> dict[str, dict[str, Any]]:
    assert result.exit_code in {0, 1}, result.stderr
    return {entry["name"]: entry for entry in result.json["data"]["checks"]}


def only(cli: Cli, project: Path, name: str, *args: str, **kwargs: Any) -> dict[str, Any]:
    result = run(cli, project, "--check", name, *args, **kwargs)
    (entry,) = rows(result).values()
    return entry


def settings(**sections: Any) -> Settings:
    return Settings.model_validate(sections)


# which checks exist


def test_the_checks_follow_the_settings(cli: Cli, project: Path, engines: dict[str, Any]) -> None:
    listed = run(cli, project, "--list").json["data"]["checks"]
    names = [entry["name"] for entry in listed]
    external = [name for name in names if name.split(":")[0] in {"engine", "provider", "report"}]
    assert external == [
        "engine:bandit",
        "engine:ghost",
        "engine:gitleaks",
        "engine:semgrep",
        "engine:trivy",
        "provider:lab:configured",
        "provider:lab:reachable",
        "provider:mock:configured",
        "provider:mock:reachable",
        "provider:primary:configured",
        "provider:primary:reachable",
        "report:pdf",
        "report:fonts",
    ]
    assert "provider:spare:configured" not in names  # a disabled provider has no checks
    assert names.index("plugins:pipeline") < names.index("engine:bandit")  # local checks first


def test_without_pdf_there_are_no_report_checks(cli: Cli, project_dir: Path) -> None:
    (project_dir / ".git").mkdir()
    names = [e["name"] for e in run(cli, project_dir, "--list").json["data"]["checks"]]
    assert not [name for name in names if name.startswith("report:")]
    assert "provider:mock:configured" in names  # mock is always present


def test_every_external_check_is_optional_and_the_categories_agree() -> None:
    assert set(doctor_checks.CATEGORIES) == set(doctor.EXTERNAL_CATEGORIES)
    sample = settings(
        llm={"providers": {"p": {"kind": "anthropic", "model": "m"}}},
        engines={"enabled": ["e"]},
        reporting={"formats": ["pdf"]},
    )
    checks = doctor_checks.external_checks(sample)
    assert len(checks) == 1 + 4 + 2  # one engine, mock and p with two checks each, two reports
    assert not any(check.required for check in checks)


def test_category_and_check_filters_reach_the_new_checks(
    cli: Cli, project: Path, engines: dict[str, Any]
) -> None:
    selected = rows(run(cli, project, "--category", "engines"))
    assert set(selected) == {
        f"engine:{n}" for n in ("bandit", "ghost", "gitleaks", "semgrep", "trivy")
    }
    assert set(rows(run(cli, project, "--category", "report"))) == {"report:pdf", "report:fonts"}
    bad = run(cli, project, "--check", "engine:nonexistent")
    assert bad.exit_code == 2
    assert "unknown check: engine:nonexistent" in bad.json["errors"][0]["message"]


def test_the_categories_are_completed(cli: Cli, project: Path) -> None:
    assert doctor._complete_category(None, [], "e") == ["engines"]
    assert doctor._complete_category(None, [], "p") == ["parsing", "plugins", "providers"]


# engines


def test_an_available_engine_passes_with_its_version_and_location(
    cli: Cli, project: Path, engines: dict[str, Any]
) -> None:
    engines["semgrep"] = engine_adapter(available=True, version="1.9.0", path="/usr/bin/semgrep")
    engines["gitleaks"] = engine_adapter(available=True, version="8.1", image="ghcr.io/x/gl:8.1")
    semgrep = only(cli, project, "engine:semgrep")
    assert (semgrep["status"], semgrep["summary"]) == ("pass", "1.9.0 at /usr/bin/semgrep")
    assert semgrep["details"] == {"adapter": True, "version": "1.9.0", "path": "/usr/bin/semgrep"}
    gitleaks = only(cli, project, "engine:gitleaks")
    assert gitleaks["summary"] == "8.1 at ghcr.io/x/gl:8.1"
    assert gitleaks["details"]["image"] == "ghcr.io/x/gl:8.1"


def test_an_enabled_but_missing_engine_warns_and_the_exit_code_stays_zero(
    cli: Cli, project: Path, engines: dict[str, Any]
) -> None:
    engines["semgrep"] = engine_adapter(
        available=False, install_hint="pipx install semgrep\x1b[31m\nthen retry"
    )
    result = run(cli, project, "--category", "engines")
    found = rows(result)
    assert result.exit_code == 0
    semgrep = found["engine:semgrep"]
    assert (semgrep["status"], semgrep["summary"]) == ("warn", "enabled, but not installed")
    assert semgrep["remediation"] == "pipx install semgrep [31m then retry"  # one line
    assert "\x1b" not in result.stdout
    assert found["engine:gitleaks"]["summary"] == "enabled, but no adapter for it is installed"
    assert found["engine:ghost"]["status"] == "warn"
    assert found["engine:ghost"]["remediation"] == doctor_checks.ENGINE_MISSING_HINT


def test_a_probe_without_an_install_hint_gets_the_generic_one(
    cli: Cli, project: Path, engines: dict[str, Any]
) -> None:
    engines["semgrep"] = engine_adapter(available=False)
    entry = only(cli, project, "engine:semgrep")
    assert entry["remediation"] == doctor_checks.ENGINE_NOT_FOUND_HINT


def test_disabled_engines_are_skipped_and_never_probed(
    cli: Cli, project: Path, engines: dict[str, Any]
) -> None:
    def boom(_settings: object) -> object:
        raise AssertionError("a disabled engine must not be probed")

    engines["bandit"] = SimpleNamespace(probe=boom)
    engines["trivy"] = SimpleNamespace(probe=boom)
    found = rows(run(cli, project, "--category", "engines"))
    assert (found["engine:bandit"]["status"], found["engine:bandit"]["summary"]) == (
        "skip",
        "disabled",
    )
    assert found["engine:trivy"]["status"] == "skip"  # options.trivy.enabled = false


def test_an_engine_missing_from_the_enabled_list_is_not_selected(cli: Cli, project: Path) -> None:
    assert doctor_checks._engine_mode(settings(engines={"enabled": ["a"]}), "b") == "unselected"
    assert doctor_checks._engine_mode(settings(engines={"enabled": ["a"]}), "a") == "enabled"
    assert doctor_checks._engine_mode(settings(), "b") == "implicit"
    off = settings(engines={"enabled": ["a"], "options": {"a": {"enabled": False}}})
    assert doctor_checks._engine_mode(off, "a") == "disabled"
    on = settings(engines={"disabled": ["a"], "options": {"a": {"enabled": True}}})
    assert doctor_checks._engine_mode(on, "a") == "enabled"  # options beat the lists


def test_installed_engines_are_candidates_when_nothing_is_enabled(
    cli: Cli, project_dir: Path, engines: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    (project_dir / ".git").mkdir()
    specs = [
        PluginSpec("codekavach.engines", name, "pkg:Adapter", "codekavach-extra", "1.0")
        for name in ("alpha", "beta", "gamma")
    ]
    monkeypatch.setattr(doctor_checks, "discover", lambda groups: specs)
    engines["alpha"] = engine_adapter(available=True, version="2.0")
    engines["beta"] = engine_adapter(available=False)  # installed adapter, absent engine
    found = rows(run(cli, project_dir, "--category", "engines"))
    assert found["engine:alpha"]["status"] == "pass"
    assert (found["engine:beta"]["status"], found["engine:beta"]["summary"]) == (
        "skip",
        "not installed",
    )
    assert found["engine:gamma"]["summary"] == "its adapter is not available"  # failed to load


def test_the_plugin_policy_decides_which_engines_are_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    specs = [
        PluginSpec("codekavach.engines", "inside", "pkg:A", "codekavach-extra", "1"),
        PluginSpec("codekavach.engines", "outside", "pkg:B", "somebody-else", "1"),
    ]
    monkeypatch.setattr(doctor_checks, "discover", lambda groups: specs)
    allowed = settings(plugins={"allow_distributions": ["codekavach-extra"]})
    assert doctor_checks._installed_engine_names(allowed) == {"inside"}
    assert doctor_checks._installed_engine_names(settings()) == {"inside", "outside"}


def test_an_adapter_without_a_probe_and_a_crashing_probe(
    cli: Cli, project: Path, engines: dict[str, Any]
) -> None:
    engines["semgrep"] = SimpleNamespace()  # no probe attribute
    assert only(cli, project, "engine:semgrep")["status"] == "warn"

    def crash(_settings: object) -> object:
        raise RuntimeError(f"traceback with {SECRET}")

    engines["semgrep"] = SimpleNamespace(probe=crash)
    result = run(cli, project, "--check", "engine:semgrep")
    assert rows(result)["engine:semgrep"]["summary"] == "check crashed: RuntimeError"
    assert SECRET not in result.stdout + result.stderr


def test_a_missing_registry_skips_every_engine_check(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args: object) -> object:
        raise BackendUnavailableError("no registry")

    fake_backend(monkeypatch, REGISTRY, unavailable)
    entry = only(cli, project, "engine:semgrep")
    assert (entry["status"], entry["summary"]) == ("skip", doctor.NOT_IN_BUILD)


def test_adapter_text_is_one_short_line() -> None:
    assert doctor_checks._text("a\x00b\r\nc\x9fd") == "a b c d"
    assert doctor_checks._text("x" * 500) == "x" * 119 + "…"
    assert doctor_checks._text("   ") is None
    assert doctor_checks._text(None) is None
    assert doctor_checks._text(["not", "a", "string"]) is None


# providers: configured


def configured(cli: Cli, project: Path, provider: str, **kwargs: Any) -> dict[str, Any]:
    return only(cli, project, f"provider:{provider}:configured", **kwargs)


def test_mock_and_a_local_server_need_no_credential(cli: Cli, project: Path) -> None:
    mock = configured(cli, project, "mock")
    assert (mock["status"], mock["summary"]) == ("pass", "kind mock")
    lab = configured(cli, project, "lab")
    assert (lab["status"], lab["summary"]) == ("pass", "kind ollama, no credential needed")
    assert lab["details"]["remote"] is False


def test_a_remote_provider_with_its_key_available_passes(cli: Cli, project: Path) -> None:
    result = run(
        cli, project, "--check", "provider:primary:configured", env={"ANTHROPIC_API_KEY": SECRET}
    )
    (entry,) = rows(result).values()
    assert (entry["status"], entry["summary"]) == ("pass", "kind anthropic, credential available")
    assert entry["details"]["references"] == ["env:ANTHROPIC_API_KEY"]
    assert SECRET not in result.stdout + result.stderr


def test_an_unset_reference_warns_by_name_and_shows_nothing_of_a_value(
    cli: Cli, project: Path
) -> None:
    result = run(
        cli, project, "--check", "provider:primary:configured", env={"OPENAI_API_KEY": SECRET}
    )
    (entry,) = rows(result).values()
    assert (entry["status"], entry["summary"]) == ("warn", "env:ANTHROPIC_API_KEY is not set")
    assert entry["remediation"] == doctor_checks.KEY_HINT
    assert entry["details"]["credential"] == "not-set"
    assert result.exit_code == 0
    assert SECRET not in result.stdout + result.stderr
    assert SECRET[:6] not in result.stdout  # no prefix either
    assert str(len(SECRET)) not in result.stdout  # nor a length


def test_a_keyring_reference_without_a_backend_is_a_warning(
    cli: Cli, project_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (project_dir / ".git").mkdir()
    (project_dir / "codekavach.toml").write_text(
        '[llm.providers.vault]\nkind = "openai"\nmodel = "m"\n'
        'api_key = "keyring:codekavach/vault"\n',  # pragma: allowlist secret
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codekavach.config.keys.secret_status",
        lambda ref, **_k: SecretStatus(ref, "backend-unavailable", "hint"),
    )
    entry = only(cli, project_dir, "provider:vault:configured")
    assert (entry["status"], entry["summary"]) == ("warn", "the keyring backend is unavailable")
    assert entry["remediation"] == doctor_checks.KEYRING_HINT


def test_several_references_are_all_named(cli: Cli, project_dir: Path) -> None:
    (project_dir / ".git").mkdir()
    (project_dir / "codekavach.toml").write_text(
        '[llm.providers.gem]\nkind = "gemini"\nmodel = "m"\n', encoding="utf-8"
    )
    entry = only(cli, project_dir, "provider:gem:configured")
    assert entry["summary"] == "none of env:GEMINI_API_KEY, env:GOOGLE_API_KEY is set"
    other = only(cli, project_dir, "provider:gem:configured", env={"GOOGLE_API_KEY": SECRET})
    assert other["status"] == "pass"  # any one of the references is enough


def test_configured_checks_are_skipped_when_the_llm_is_disabled(cli: Cli, project: Path) -> None:
    entry = configured(cli, project, "primary", env={"CODEKAVACH_LLM__ENABLED": "false"})
    assert (entry["status"], entry["summary"]) == (
        "skip",
        "LLM review is disabled (llm.enabled = false)",
    )


# providers: reachable


def stored_grant(home: Path, level: PrivacyLevel = PrivacyLevel.L3) -> None:
    provider = settings(llm={"providers": {"primary": {"kind": "anthropic", "model": "m"}}})
    tier = provider.llm.providers["primary"].effective_trust_tier.value
    grant = ConsentGrant(
        provider_id="primary",
        kind="anthropic",
        host=None,
        trust_tier=tier,
        level=level,
        granted_at=datetime(2026, 10, 1, tzinfo=UTC),
        codekavach_version="0.1.0",
    )
    ConsentStore.load({"CODEKAVACH_HOME": str(home)}).with_grant(grant).save()


def arrange(consent: str, home: Path) -> tuple[list[str], dict[str, str]]:
    args: list[str] = []
    env: dict[str, str] = {}
    if consent == "stored":
        stored_grant(home)
    elif consent == "flag":
        args.append("--accept-egress")
    elif consent == "env":
        env["CODEKAVACH_ACCEPT_EGRESS"] = "1"
    return args, env


def expected(flag: bool, remote: bool, consent: str, offline: bool) -> tuple[str, str, int]:
    """The oracle of the matrix: status, summary and number of probe calls."""
    if remote and offline:  # the runner skips a network check before it runs
        return "skip", "offline", 0
    if not flag:
        return "skip", "use --probe-providers", 0
    if remote and consent == "none":
        return "skip", "consent required", 0
    return "pass", "answered in 412 ms", 1


MATRIX = list(
    itertools.product(
        [False, True], [True, False], ["stored", "flag", "env", "none"], [False, True]
    )
)


@pytest.mark.parametrize(("flag", "remote", "consent", "offline"), MATRIX)
def test_reachability_matrix(
    cli: Cli,
    project: Path,
    isolated_home: Path,
    probe: FakeProbe,
    *,
    flag: bool,
    remote: bool,
    consent: str,
    offline: bool,
) -> None:
    extra, env = arrange(consent, isolated_home)
    args = ["--probe-providers"] if flag else []
    args += ["--offline"] if offline else []
    name = REMOTE_PROVIDER if remote else LOCAL_PROVIDER
    entry = only(cli, project, name, *args, *extra, env=env)
    status, summary, calls = expected(flag, remote, consent, offline)
    assert (entry["status"], entry["summary"]) == (status, summary)
    assert len(probe.calls) == calls
    if calls:
        (call,) = probe.calls
        assert call["provider_id"] == ("primary" if remote else "lab")
        assert (call["model"], call["structured"]) == (None, False)
        assert call["timeout"] == pytest.approx(8.0)  # 80 % of the 10 s default


Source = Literal["user-file", "flag", "env"]


@pytest.mark.parametrize(
    ("consent", "source"), [("stored", "user-file"), ("flag", "flag"), ("env", "env")]
)
def test_the_probe_receives_the_consent_decision(
    cli: Cli, project: Path, isolated_home: Path, probe: FakeProbe, *, consent: str, source: Source
) -> None:
    extra, env = arrange(consent, isolated_home)
    only(cli, project, REMOTE_PROVIDER, "--probe-providers", *extra, env=env)
    (call,) = probe.calls
    assert call["consent"] == ConsentDecision(granted=True, source=source)


def test_a_local_provider_is_probed_without_a_consent_decision(
    cli: Cli, project: Path, probe: FakeProbe
) -> None:
    only(cli, project, LOCAL_PROVIDER, "--probe-providers", "--offline")
    (call,) = probe.calls
    assert call["consent"] is None


def test_the_probe_timeout_follows_the_command_option(
    cli: Cli, project: Path, probe: FakeProbe
) -> None:
    only(cli, project, LOCAL_PROVIDER, "--probe-providers", "--timeout", "5")
    assert probe.calls[0]["timeout"] == pytest.approx(4.0)


def test_doctor_never_asks_for_consent_and_stores_nothing(
    cli: Cli, project: Path, isolated_home: Path, probe: FakeProbe
) -> None:
    result = cli(
        ["doctor", TRUST, "--check", REMOTE_PROVIDER, "--probe-providers"],
        cwd=project,
        tty=True,
        input="y\n",
    )
    assert result.exit_code == 0, result.stderr
    assert "SKIP  provider:primary:reachable  consent required" in result.stdout
    assert (
        "hint  provider:primary:reachable  run `codekavach privacy consent grant" in result.stdout
    )
    assert "Send sanitised payloads" not in result.stderr + result.stdout
    assert probe.calls == []
    assert not (isolated_home / "consent.json").exists()


def test_a_grant_for_a_stricter_level_does_not_cover_a_looser_run(
    cli: Cli, project: Path, isolated_home: Path, probe: FakeProbe
) -> None:
    stored_grant(isolated_home, PrivacyLevel.L4)
    entry = only(cli, project, REMOTE_PROVIDER, "--probe-providers", "--privacy-level", "L3")
    assert entry["summary"] == "consent required"  # an L4 grant is stricter than L3
    assert probe.calls == []


def test_remote_providers_are_not_probed_when_remote_use_is_off(
    cli: Cli, project: Path, probe: FakeProbe
) -> None:
    entry = only(
        cli, project, REMOTE_PROVIDER, "--probe-providers", "--accept-egress",
        env={"CODEKAVACH_LLM__ALLOW_REMOTE": "false"},
    )  # fmt: skip
    assert (entry["status"], entry["summary"]) == ("skip", "remote providers are not allowed")
    assert probe.calls == []


def test_remote_providers_are_not_probed_at_level_l0(
    cli: Cli, project: Path, probe: FakeProbe
) -> None:
    entry = only(
        cli,
        project,
        REMOTE_PROVIDER,
        "--probe-providers",
        "--accept-egress",
        "--privacy-level",
        "L0",
    )
    assert (entry["status"], entry["summary"]) == ("skip", "privacy level L0 sends nothing")
    assert probe.calls == []
    local = only(cli, project, LOCAL_PROVIDER, "--probe-providers", "--privacy-level", "L0")
    assert local["status"] == "pass"  # a local provider sends nothing off the machine


def test_nothing_is_probed_when_the_llm_is_disabled(
    cli: Cli, project: Path, probe: FakeProbe
) -> None:
    entry = only(
        cli, project, LOCAL_PROVIDER, "--probe-providers", env={"CODEKAVACH_LLM__ENABLED": "false"}
    )
    assert entry["status"] == "skip"
    assert probe.calls == []


def test_test_doubles_pass_without_a_probe_call(cli: Cli, project: Path, probe: FakeProbe) -> None:
    entry = only(cli, project, "provider:mock:reachable", "--probe-providers", "--offline")
    assert (entry["status"], entry["summary"]) == ("pass", "local mock provider; nothing was sent")
    assert probe.calls == []


@pytest.mark.parametrize("reason", sorted(REASON_HINTS))
def test_every_failure_reason_renders_as_fail_with_its_code_only(
    cli: Cli, project: Path, probe: FakeProbe, reason: str
) -> None:
    probe.reason = reason
    result = run(cli, project, "--check", LOCAL_PROVIDER, "--probe-providers")
    (entry,) = rows(result).values()
    assert (entry["status"], entry["summary"]) == ("fail", f"probe failed: {reason}")
    assert entry["remediation"] == REASON_HINTS[reason]
    assert entry["details"]["reason"] == reason
    assert RAW_ERROR not in result.stdout + result.stderr
    assert result.exit_code == 0  # optional: a failed probe is reported, not an exit code
    strict = run(cli, project, "--check", LOCAL_PROVIDER, "--probe-providers", "--strict")
    assert strict.exit_code == 1


def test_an_unknown_reason_is_a_bad_response(cli: Cli, project: Path, probe: FakeProbe) -> None:
    probe.reason = "something-new"
    entry = only(cli, project, LOCAL_PROVIDER, "--probe-providers")
    assert entry["summary"] == "probe failed: bad_response"


def test_a_crashing_probe_is_reported_by_its_class_only(
    cli: Cli, project: Path, probe: FakeProbe
) -> None:
    probe.raises = ConnectionError(RAW_ERROR)
    result = run(cli, project, "--check", LOCAL_PROVIDER, "--probe-providers")
    assert rows(result)[LOCAL_PROVIDER]["summary"] == "check crashed: ConnectionError"
    assert RAW_ERROR not in result.stdout + result.stderr


def test_without_the_adapters_the_probe_is_skipped_as_not_in_this_build(
    cli: Cli, project: Path
) -> None:
    entry = only(cli, project, LOCAL_PROVIDER, "--probe-providers")
    assert (entry["status"], entry["summary"]) == ("skip", doctor.NOT_IN_BUILD)


def test_the_reachable_check_is_a_network_check_for_remote_providers_only() -> None:
    sample = settings(llm={"providers": {"p": {"kind": "anthropic", "model": "m"}}})
    by_name = {check.name: check for check in doctor_checks.provider_checks(sample)}
    assert by_name["provider:p:reachable"].needs_network is True
    assert by_name["provider:mock:reachable"].needs_network is False
    assert by_name["provider:p:configured"].needs_network is False


def test_the_remote_probe_check_needs_a_context_for_the_consent_gate(
    cli: Cli, project: Path, probe: FakeProbe
) -> None:
    sample = settings(llm={"providers": {"p": {"kind": "anthropic", "model": "m"}}})
    plan = doctor_checks.ProbePlan(ctx=None, enabled=True, accept=True)
    (check,) = (
        c for c in doctor_checks.provider_checks(sample, plan) if c.name.endswith("p:reachable")
    )
    outcome = check.run(SimpleNamespace(settings=sample))  # type: ignore[arg-type]
    assert (outcome.status.value, outcome.summary) == ("skip", "consent required")
    assert probe.calls == []


# reports


def test_pdf_and_font_checks_pass_when_the_probes_do(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend(monkeypatch, PDF_PROBE, lambda: SimpleNamespace(ok=True))
    fake_backend(
        monkeypatch, FONT_PROBE, lambda script: ["Noto Sans Devanagari", "Mangal", "Mangal"]
    )
    found = rows(run(cli, project, "--category", "report"))
    assert found["report:pdf"]["status"] == "pass"
    fonts = found["report:fonts"]
    assert (fonts["status"], fonts["summary"]) == ("pass", "2 font(s) cover Devanagari")
    assert fonts["details"] == {"script": "devanagari", "fonts": ["Mangal", "Noto Sans Devanagari"]}


@pytest.mark.parametrize(
    ("system", "needle"),
    [
        ("Linux", "apt install libpango"),
        ("Darwin", "brew install pango"),
        ("Windows", "GTK runtime"),
        ("Plan9", "Pango and HarfBuzz"),
    ],
)
def test_missing_pdf_prerequisites_warn_with_a_platform_hint(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch, system: str, needle: str
) -> None:
    fake_backend(monkeypatch, PDF_PROBE, lambda: SimpleNamespace(ok=False, detail=RAW_ERROR))
    monkeypatch.setattr(platform, "system", lambda: system)
    result = run(cli, project, "--check", "report:pdf")
    (entry,) = rows(result).values()
    assert entry["status"] == "warn"
    assert needle in entry["remediation"]
    assert RAW_ERROR not in result.stdout
    assert result.exit_code == 0


def test_no_devanagari_font_is_a_warning_that_lists_what_was_found(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend(monkeypatch, FONT_PROBE, lambda script: [])
    entry = only(cli, project, "report:fonts")
    assert (entry["status"], entry["summary"]) == ("warn", "no font covers Devanagari")
    assert entry["details"]["fonts"] == []
    assert entry["remediation"] == doctor_checks.FONT_HINT


def test_report_checks_are_skipped_until_the_report_epic_lands(cli: Cli, project: Path) -> None:
    found = rows(run(cli, project, "--category", "report"))
    assert {entry["summary"] for entry in found.values()} == {doctor.NOT_IN_BUILD}


# an unreadable configuration


def test_an_invalid_configuration_leaves_one_skipped_row_per_category(
    cli: Cli, project_dir: Path
) -> None:
    (project_dir / ".git").mkdir()
    (project_dir / "codekavach.toml").write_text('[llm]\ntemperature = "hot"\n', encoding="utf-8")
    result = run(cli, project_dir, "--category", "providers", "--category", "engines")
    found = rows(result)
    assert set(found) == {"providers:settings", "engines:settings"}
    assert all(entry["status"] == "skip" for entry in found.values())
    assert "see config:valid" in found["engines:settings"]["summary"]
    full = rows(run(cli, project_dir))
    assert full["config:valid"]["status"] == "fail"
    assert {"engines:settings", "providers:settings", "report:settings"} <= set(full)


# hygiene


def test_importing_the_doctor_modules_pulls_in_no_network_library_or_adapter() -> None:
    code = (
        "import sys\n"
        "import codekavach.cli.doctor, codekavach.cli.doctor_checks\n"
        "banned = ('httpx', 'requests', 'urllib3', 'aiohttp', 'anthropic', 'openai', 'boto3',\n"
        "          'litellm', 'google.generativeai', 'codekavach.llm.providers',\n"
        "          'codekavach.privacy.egress.transport')\n"
        "hits = sorted(\n"
        "    m for m in sys.modules if any(m == b or m.startswith(b + '.') for b in banned)\n"
        ")\n"
        "print(hits)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_the_module_follows_the_layout_rules() -> None:
    text = Path(doctor_checks.__file__).read_text(encoding="utf-8")
    assert "Owning epic: E05." in text.split('"""')[1]
    assert "logging.getLogger" not in text


def test_the_engine_plugins_are_loaded_once_for_all_engine_checks(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loads: list[object] = []

    def registry(settings: object) -> object:
        loads.append(settings)
        return SimpleNamespace(engines=dict)

    fake_backend(monkeypatch, REGISTRY, registry)
    found = rows(run(cli, project, "--category", "engines"))
    assert len(found) == 5  # bandit and trivy are off; ghost, gitleaks and semgrep were probed
    assert len(loads) == 1
