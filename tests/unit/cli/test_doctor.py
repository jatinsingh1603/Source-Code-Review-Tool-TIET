import importlib.metadata
import io
import json
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codekavach.cli import doctor
from codekavach.cli.context import CliContext
from codekavach.cli.doctor import (
    CheckResult,
    CheckStatus,
    LocalCheck,
    Outcome,
    all_checks,
    has_failed,
    register_check,
    render_lines,
    run_check,
    select_checks,
    totals,
)
from codekavach.cli.errors import BackendUnavailableError, UsageError
from codekavach.config import keys as keys_module
from codekavach.config.keys import KeyringUnavailableError
from codekavach.core.plugins import registry as registry_module
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginFailure
from codekavach.core.store.db import init_db
from codekavach.core.store.layout import StateLayout
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden"
LOCAL_NAMES = [
    "runtime:python",
    "runtime:package",
    "runtime:platform",
    "config:valid",
    "storage:state-dir",
    "storage:artefacts",
    "storage:database",
    "parsing:grammar:python",
    "parsing:grammar:javascript",
    "secrets:keyring",
    "plugins:load",
]


def fake(
    name: str,
    status: CheckStatus = CheckStatus.PASS,
    *,
    required: bool = False,
    needs_network: bool = False,
    summary: str = "fine",
    error: BaseException | None = None,
    sleep: float = 0.0,
) -> LocalCheck:
    def probe(_ctx: CliContext) -> Outcome:
        if sleep:
            time.sleep(sleep)
        if error is not None:
            raise error
        return Outcome(status, summary, {"n": 1})

    return LocalCheck(
        name,
        name.split(":", maxsplit=1)[0],
        probe,
        required=required,
        needs_network=needs_network,
        remediation=f"fix {name}",
    )


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """An empty check registry for this test."""
    checks: dict[str, Any] = {}
    monkeypatch.setattr(doctor, "_REGISTRY", checks)
    return checks


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def one(cli: Cli, project: Path, name: str, **kwargs: Any) -> dict[str, Any]:
    """Run one registered check through the command and return its JSON result."""
    result = cli(["doctor", "--check", name, "--json"], cwd=project, **kwargs)
    (entry,) = result.json["data"]["checks"]
    assert isinstance(entry, dict)
    return entry


# registry


def test_local_checks_are_registered_in_order() -> None:
    assert [check.name for check in all_checks()] == LOCAL_NAMES
    required = {check.name for check in all_checks() if check.required}
    assert required == {
        "runtime:python",
        "runtime:package",
        "config:valid",
        "storage:state-dir",
        "parsing:grammar:python",
        "parsing:grammar:javascript",
    }
    assert not any(check.needs_network for check in all_checks())


def test_register_replaces_a_check_of_the_same_name(registry: dict[str, Any]) -> None:
    register_check(fake("a:one"))
    register_check(fake("b:two"))
    register_check(fake("a:one", CheckStatus.WARN))
    assert [check.name for check in all_checks()] == ["a:one", "b:two"]
    assert run_check(all_checks()[0], CliContext(), timeout=5).status is CheckStatus.WARN


# runner


@pytest.mark.parametrize("status", list(CheckStatus))
def test_runner_reports_the_status_of_the_check(status: CheckStatus) -> None:
    result = run_check(fake("a:one", status, required=True), CliContext(), timeout=5)
    assert (result.name, result.category, result.status) == ("a:one", "a", status)
    assert (result.summary, result.required, dict(result.details)) == ("fine", True, {"n": 1})
    hinted = status in {CheckStatus.WARN, CheckStatus.FAIL}
    assert result.remediation == ("fix a:one" if hinted else None)
    assert result.duration_ms >= 0


def test_crash_is_reported_by_class_name_only() -> None:
    crashing = fake("a:crash", error=RuntimeError("secret=abc"))
    result = run_check(crashing, CliContext(), timeout=5)
    assert (result.status, result.summary) == (CheckStatus.FAIL, "check crashed: RuntimeError")
    assert "abc" not in json.dumps(result.to_json())


def test_timeout_fails_the_check_and_the_runner_returns() -> None:
    started = time.monotonic()
    result = run_check(fake("a:slow", sleep=30.0), CliContext(), timeout=0.2)
    assert time.monotonic() - started < 10
    assert (result.status, result.summary) == (CheckStatus.FAIL, "timed out")


def test_missing_back_end_and_offline_are_skips() -> None:
    missing = fake("a:missing", error=BackendUnavailableError("x is not available"))
    result = run_check(missing, CliContext(), timeout=5)
    assert (result.status, result.summary) == (CheckStatus.SKIP, "not available in this build")
    online = fake("a:net", needs_network=True, error=AssertionError("must not run"))
    offline = run_check(online, CliContext(offline=True), timeout=5)
    assert (offline.status, offline.summary) == (CheckStatus.SKIP, "offline")
    assert run_check(online, CliContext(), timeout=5).status is CheckStatus.FAIL


# exit codes


@pytest.mark.parametrize("required", [True, False])
@pytest.mark.parametrize("status", list(CheckStatus))
@pytest.mark.parametrize("strict", [True, False])
def test_exit_code_table(
    cli: Cli, registry: dict[str, Any], required: bool, status: CheckStatus, strict: bool
) -> None:
    register_check(fake("a:ok"))
    register_check(fake("b:probe", status, required=required))
    if strict:
        failing = status in {CheckStatus.FAIL, CheckStatus.WARN}
    else:
        failing = required and status is CheckStatus.FAIL
    results = [run_check(check, CliContext(), timeout=5) for check in all_checks()]
    assert has_failed(results, strict=strict) is failing
    result = cli(["doctor", "--strict"] if strict else ["doctor"])
    assert result.exit_code == (1 if failing else 0)
    assert f"{status.value.upper():<4}  b:probe" in result.stdout
    machine = cli(["doctor", "--json", *(["--strict"] if strict else [])])
    assert machine.json["exit_code"] == (1 if failing else 0)


# output


def fixed_results() -> list[CheckResult]:
    return [
        CheckResult("runtime:python", "runtime", CheckStatus.PASS, "3.12.6", required=True),
        CheckResult("config:valid", "config", CheckStatus.PASS, "profile demo, 0 warning(s)"),
        CheckResult(
            "secrets:keyring",
            "secrets",
            CheckStatus.WARN,
            "no keyring backend; passphrase mode will be used",
            remediation="install a keyring backend or use passphrase mode",
        ),
        CheckResult(
            "parsing:grammar:python",
            "parsing",
            CheckStatus.FAIL,
            "grammar could not be loaded",
            remediation="uv sync --all-extras",
            details={"language": "python"},
            duration_ms=12,
            required=True,
        ),
        CheckResult(
            "storage:artefacts", "storage", CheckStatus.SKIP, "not available in this build"
        ),
    ]


def test_human_and_json_output_match_the_golden_files() -> None:
    results = fixed_results()
    assert_matches_golden("\n".join(render_lines(results)) + "\n", GOLDEN / "doctor_table.txt")
    document = {"checks": [result.to_json() for result in results], "totals": totals(results)}
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    assert_matches_golden(text, GOLDEN / "doctor.json")
    assert totals(results) == {"passed": 2, "warnings": 1, "failed": 1, "skipped": 1}
    assert render_lines(results)[-1] == "2 passed, 1 warning, 1 failed, 1 skipped"


def test_command_output(cli: Cli, registry: dict[str, Any]) -> None:
    register_check(fake("a:ok", summary="all good"))
    register_check(fake("b:warn", CheckStatus.WARN, summary="could be better"))
    register_check(fake("c:crash", required=True, error=RuntimeError("secret=abc")))
    result = cli(["doctor"])
    assert result.exit_code == 1
    assert result.stdout.splitlines() == [
        "PASS  a:ok     all good",
        "WARN  b:warn   could be better",
        "FAIL  c:crash  check crashed: RuntimeError",
        "hint  b:warn   fix b:warn",
        "1 passed, 1 warning, 1 failed, 0 skipped",
    ]
    assert "abc" not in result.stdout + result.stderr
    machine = cli(["doctor", "--json"])
    data = machine.json["data"]
    assert data["totals"] == {"passed": 1, "warnings": 1, "failed": 1, "skipped": 0}
    assert set(data["checks"][0]) == {
        "name", "category", "status", "summary", "remediation", "details", "duration_ms",
        "required",
    }  # fmt: skip
    assert [entry["status"] for entry in data["checks"]] == ["pass", "warn", "fail"]
    assert "abc" not in machine.stdout


def test_slow_check_times_out_and_the_command_finishes(cli: Cli, registry: dict[str, Any]) -> None:
    register_check(fake("a:slow", required=True, sleep=30.0))
    register_check(fake("b:after"))
    started = time.monotonic()
    result = cli(["doctor", "--timeout", "1"])
    assert time.monotonic() - started < 15
    assert result.exit_code == 1
    assert "FAIL  a:slow   timed out" in result.stdout
    assert "PASS  b:after  fine" in result.stdout


# filters


def test_filters(cli: Cli, registry: dict[str, Any]) -> None:
    boom = AssertionError("must not run")
    register_check(fake("runtime:python"))
    register_check(fake("parsing:grammar:python"))
    register_check(fake("parsing:grammar:go", error=boom))
    by_category = cli(["doctor", "--category", "runtime"])
    assert by_category.stdout.splitlines()[0].startswith("PASS  runtime:python")
    assert "parsing" not in by_category.stdout
    by_name = cli(["doctor", "--check", "parsing:grammar:python", "--check", "runtime:python"])
    assert [line.split()[1] for line in by_name.stdout.splitlines()[:2]] == [
        "runtime:python",
        "parsing:grammar:python",
    ]
    listed = cli(["doctor", "--list"])
    assert listed.exit_code == 0
    assert listed.stdout.splitlines() == [
        "runtime:python  (runtime)",
        "parsing:grammar:python  (parsing)",
        "parsing:grammar:go  (parsing)",
    ]
    parsing_only = cli(["doctor", "--list", "--category", "parsing", "--json"])
    assert [entry["name"] for entry in parsing_only.json["data"]["checks"]] == [
        "parsing:grammar:python",
        "parsing:grammar:go",
    ]
    for arguments in (["--check", "nope"], ["--category", "nope"]):
        unknown = cli(["doctor", *arguments])
        assert unknown.exit_code == 2
    with pytest.raises(UsageError):
        select_checks(all_checks(), categories=(), names=("nope",))


# the local checks


def test_everything_passes_or_is_skipped_on_a_clean_machine(cli: Cli, project: Path) -> None:
    result = cli(["doctor"], cwd=project)
    assert result.exit_code == 0, result.stdout
    statuses = {line.split()[1]: line.split()[0] for line in result.stdout.splitlines()[:-1]}
    assert list(statuses) == LOCAL_NAMES
    assert statuses["storage:artefacts"] == "SKIP"
    assert statuses["parsing:grammar:python"] == "SKIP"
    assert "not available in this build" in result.stdout
    assert {statuses[name] for name in ("runtime:python", "runtime:package", "config:valid")} == {
        "PASS"
    }
    assert not (project / ".codekavach").exists()


def test_runtime_checks(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    python = one(cli, project, "runtime:python")
    assert (python["status"], python["summary"]) == ("pass", python["details"]["version"])
    package = one(cli, project, "runtime:package")
    assert package["status"] == "pass"
    assert set(package["details"]) == {"version", "location"}
    monkeypatch.setattr(doctor, "MINIMUM_PYTHON", (99, 0))
    old = one(cli, project, "runtime:python")
    assert (old["status"], old["remediation"]) == ("fail", "install Python 3.12 or later")

    def missing(_name: str) -> Any:
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(importlib.metadata, "distribution", missing)
    assert one(cli, project, "runtime:package")["status"] == "fail"


def test_platform_check_reports_names_not_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEKAVACH_PLANTED", "planted-value")
    outcome = doctor._platform(CliContext())
    assert "CODEKAVACH_PLANTED" in outcome.details["codekavach_variables"]  # type: ignore[operator]
    assert "planted-value" not in json.dumps(dict(outcome.details))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="cp1252"))
    assert doctor._platform(CliContext()).status is CheckStatus.WARN
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    assert doctor._platform(CliContext()).status is CheckStatus.PASS


def test_config_check(cli: Cli, project: Path, isolated_home: Path) -> None:
    assert one(cli, project, "config:valid")["status"] == "pass"
    (isolated_home / "config.toml").write_text(
        '[privacy.provider_tier_levels]\npublic = "L2"\n', encoding="utf-8"
    )
    warned = one(cli, project, "config:valid")
    assert (warned["status"], warned["details"]["warnings"]) == ("warn", 1)
    (project / "codekavach.toml").write_text('[privacy]\nlevel = "L9"\n', encoding="utf-8")
    result = cli(["doctor"], cwd=project)
    assert result.exit_code == 1  # diagnosed, not a usage error
    lines = result.stdout.splitlines()
    assert any(line.startswith("FAIL  config:valid") for line in lines)
    assert any(line.startswith("PASS  runtime:python") for line in lines)
    assert "L9" not in result.stdout
    assert "hint  config:valid" in result.stdout


def test_state_dir_check(cli: Cli, project: Path) -> None:
    before = sorted(path.name for path in project.iterdir())
    fresh = one(cli, project, "storage:state-dir")
    assert (fresh["status"], fresh["summary"]) == ("pass", "does not exist yet and can be created")
    assert sorted(path.name for path in project.iterdir()) == before
    state = project / ".codekavach"
    state.mkdir(mode=0o700)
    assert one(cli, project, "storage:state-dir")["status"] == "pass"
    if os.name != "nt":
        state.chmod(0o755)
        loose = one(cli, project, "storage:state-dir")
        assert (loose["status"], loose["remediation"]) == ("warn", "chmod 700 .codekavach")
    state.rmdir()
    state.write_text("a file", encoding="utf-8")
    assert one(cli, project, "storage:state-dir")["status"] == "fail"


def test_artefact_and_database_checks(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert one(cli, project, "storage:artefacts")["status"] == "skip"
    stats = "codekavach.core.store.artefacts.store_stats"
    fake_backend(monkeypatch, stats, lambda _state: {"blobs": 3, "bytes": 2048})
    counted = one(cli, project, "storage:artefacts")
    assert (counted["status"], counted["summary"]) == ("pass", "3 blob(s), 2048 bytes")

    empty = one(cli, project, "storage:database")
    assert (empty["status"], empty["details"]["revision"]) == ("pass", None)
    assert not (project / ".codekavach").exists()
    engine = init_db(StateLayout(project / ".codekavach"))
    engine.dispose()
    at_head = one(cli, project, "storage:database")
    assert at_head["status"] == "pass"
    assert at_head["details"]["revision"] == at_head["details"]["head"]
    probe = "codekavach.core.store.repositories.db_probe"
    fake_backend(
        monkeypatch,
        probe,
        lambda _layout: {"path": "db", "exists": True, "revision": "0000_old", "head": "0001"},
    )
    behind = one(cli, project, "storage:database")
    assert (behind["status"], behind["required"]) == ("fail", False)


def test_grammar_checks(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert one(cli, project, "parsing:grammar:python")["status"] == "skip"
    loaded: list[str] = []

    def load(language: str) -> None:
        loaded.append(language)
        if language == "javascript":
            raise OSError("cannot open /home/alice/grammars/javascript.so")

    fake_backend(monkeypatch, "codekavach.parsing.grammars.load_grammar", load)
    assert one(cli, project, "parsing:grammar:python")["status"] == "pass"
    broken = cli(["doctor", "--category", "parsing"], cwd=project)
    assert broken.exit_code == 1
    assert "FAIL  parsing:grammar:javascript  grammar could not be loaded" in broken.stdout
    assert "alice" not in broken.stdout + broken.stderr
    assert loaded == ["python", "python", "javascript"]


@dataclass
class FakeKeyring:
    """The part of the ``keyring`` module that the check may touch."""

    def get_keyring(self) -> object:
        return SimpleNamespace()

    def get_password(self, *_args: object) -> str:
        raise AssertionError("doctor must not read a keyring entry")


def test_keyring_check_looks_at_the_backend_only(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(keys_module, "open_keyring", lambda *_args: FakeKeyring())
    available = one(cli, project, "secrets:keyring")
    assert (available["status"], available["details"]) == ("pass", {"backend": "SimpleNamespace"})

    def unavailable(*_args: object) -> Any:
        raise KeyringUnavailableError

    monkeypatch.setattr(keys_module, "open_keyring", unavailable)
    missing = one(cli, project, "secrets:keyring")
    assert missing["status"] == "warn"
    assert missing["summary"] == "no keyring backend; passphrase mode will be used"
    assert cli(["doctor", "--check", "secrets:keyring"], cwd=project).exit_code == 0
    assert cli(["doctor", "--check", "secrets:keyring", "--strict"], cwd=project).exit_code == 1


def test_plugin_check_passes_the_settings_to_the_registry(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    received: list[object] = []

    def environment(*settings: object) -> Any:
        received.extend(settings)
        return SimpleNamespace(failures=lambda: ())

    monkeypatch.setattr(registry_module, "registry_from_environment", environment)
    assert one(cli, project, "plugins:load")["status"] == "pass"
    assert len(received) == 1
    assert getattr(received[0], "plugins", None) is not None  # the loaded Settings


def test_plugin_check_loads_nothing_when_the_configuration_is_invalid(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without valid settings the allow-list is unknown, so no plugin may be imported to check it.
    def environment(*_settings: object) -> Any:
        raise AssertionError("the registry must not be built")

    monkeypatch.setattr(registry_module, "registry_from_environment", environment)
    (project / "codekavach.toml").write_text('[privacy]\nlevel = "L9"\n', encoding="utf-8")
    entry = one(cli, project, "plugins:load")
    assert entry["status"] == "warn"
    assert entry["summary"] == "plugins not checked: the configuration is invalid"


def test_plugin_check(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def environment(failures: tuple[PluginFailure, ...]) -> Callable[..., Any]:
        return lambda *_settings: SimpleNamespace(failures=lambda: failures)

    monkeypatch.setattr(registry_module, "registry_from_environment", environment(()))
    assert one(cli, project, "plugins:load")["status"] == "pass"
    spec = PluginSpec("codekavach.stages", "broken-stage", "pkg.mod:factory", "ck-broken", "1.0")
    failure = PluginFailure(spec=spec, stage="import", error_type="ImportError")
    monkeypatch.setattr(registry_module, "registry_from_environment", environment((failure,)))
    broken = one(cli, project, "plugins:load")
    assert (broken["status"], broken["summary"]) == ("warn", "1 plugin(s) failed to load")
    assert broken["details"] == {"broken": ["codekavach.stages:broken-stage"]}
    assert broken["remediation"] == "reinstall or remove the named plugin"
