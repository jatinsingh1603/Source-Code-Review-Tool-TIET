import signal
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from codekavach.cli import backends
from codekavach.cli import scan as scan_module
from codekavach.cli.signals import (
    SALT_BACKEND,
    cancellation_lines,
    normalise_resume,
    resume_refusal,
)
from codekavach.config import load_settings
from codekavach.config.snapshot import settings_fingerprint
from codekavach.core.models import ScanStatus
from codekavach.core.models.ids import new_scan_id
from codekavach.core.pipeline import runner as runner_module
from codekavach.core.pipeline.resume import (
    Checkpoint,
    ResumeMismatchError,
    target_digest,
    write_checkpoint,
)
from codekavach.core.pipeline.runner import codekavach_version, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.layout import StateLayout
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend
from tests.support.scan_stub import install_stub

Cli = Callable[..., CliResult]
SCAN = "scan_01ARYZ6S410000000000000000"
FIXED_SALT = ScanSalt.from_hex("2f" * 32)
SALT_PATH = ".".join(SALT_BACKEND)
RUN_SCAN_KEY = ("codekavach.core.pipeline.runner", "run_scan")


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def base(project: Path, *args: str) -> list[str]:
    return ["scan", str(project), "--fail-on", "none", *args]


def stored_salt(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, str]]:
    """Register a vault back end that returns ``FIXED_SALT`` and records its calls."""
    calls: list[tuple[Any, str]] = []

    def scan_salt_for(loaded: Any, resume: str) -> ScanSalt:
        calls.append((loaded, resume))
        return FIXED_SALT

    fake_backend(monkeypatch, SALT_PATH, scan_salt_for)
    return calls


# --resume without a value


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["scan", "."], ["scan", "."]),
        (["scan", ".", "--resume"], ["scan", ".", "--resume", "latest"]),
        (["scan", "--resume", "--json", "."], ["scan", "--resume", "latest", "--json", "."]),
        (["scan", ".", "--resume", SCAN], ["scan", ".", "--resume", SCAN]),
        (["scan", "--resume", "latest", "."], ["scan", "--resume", "latest", "."]),
        (["--resume"], ["--resume", "latest"]),
    ],
)
def test_bare_resume_means_latest(argv: list[str], expected: list[str]) -> None:
    assert normalise_resume(argv) == expected


# what reaches run_scan


def test_scan_lets_the_pipeline_handle_signals(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = signal.getsignal(signal.SIGINT)
    during: list[object] = []
    stub = install_stub(monkeypatch)
    original_call = type(stub).__call__

    def recording(self: Any, loaded: Any, target: str, **kwargs: Any) -> Any:
        during.append(signal.getsignal(signal.SIGINT))
        return original_call(self, loaded, target, **kwargs)

    monkeypatch.setattr(type(stub), "__call__", recording)
    result = cli(base(project))
    assert result.exit_code == 0, result.stderr
    (call,) = stub.calls
    assert call["handle_sigint"] is True
    assert (call["resume"], call["use_cache"], call["refresh"]) == (None, None, ())
    assert during == [before]  # the CLI installed no handler of its own for the run
    assert signal.getsignal(signal.SIGINT) is before


def test_cache_flags_reach_run_scan(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    assert cli(base(project, "--no-cache")).exit_code == 0
    assert stub.calls[0]["use_cache"] is False
    refreshed = cli(base(project, "--refresh-stage", "parse", "--refresh-stage", "analyse"))
    assert refreshed.exit_code == 0, refreshed.stderr
    assert stub.calls[1]["refresh"] == ("parse", "analyse")
    assert stub.calls[1]["use_cache"] is None


# cancelled scans


def test_cancelled_scan_prints_the_resume_hint(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_stub(monkeypatch, status=ScanStatus.CANCELLED, order=("ingest", "parse"))
    result = cli(base(project))
    assert result.exit_code == 130
    assert f"scan {SCAN} cancelled after stage 'parse'" in result.stderr
    assert f"resume with: codekavach scan {project} --resume {SCAN}" in " ".join(
        result.stderr.split()
    )
    assert result.stdout == ""
    machine = cli(base(project, "--json"))
    assert machine.exit_code == 130
    envelope = machine.json
    assert envelope["exit_code"] == 130
    assert envelope["ok"] is False
    assert [error["code"] for error in envelope["errors"]] == ["cancelled"]
    assert envelope["data"] == {"scan_id": SCAN, "resumable": True}
    assert "resume with" not in machine.stderr


def test_cancellation_lines() -> None:
    assert cancellation_lines(SCAN, ".", "parse") == [
        f"scan {SCAN} cancelled after stage 'parse'",
        f"resume with: codekavach scan . --resume {SCAN}",
    ]
    assert cancellation_lines(SCAN, ".", None)[0] == (
        f"scan {SCAN} cancelled before a stage completed"
    )


@pytest.mark.parametrize("phase", ["before", "after"])
def test_keyboard_interrupt_outside_run_scan_exits_130(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    stub = install_stub(monkeypatch)

    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    if phase == "before":
        monkeypatch.setattr(scan_module, "maybe_show_first_run_notice", interrupt)
    else:
        monkeypatch.setattr(scan_module, "to_cli_result", interrupt)
    before = signal.getsignal(signal.SIGINT)
    result = cli(base(project), tty=True)
    assert result.exit_code == 130
    assert "cancelled" in result.stderr
    assert len(stub.calls) == (0 if phase == "before" else 1)
    assert signal.getsignal(signal.SIGINT) is before
    assert "\x1b[?25l" not in result.stderr.split("cancelled")[-1]  # the cursor is not hidden


# --resume


def test_resume_passes_the_stored_salt_and_generates_none(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    calls = stored_salt(monkeypatch)

    def refuse() -> ScanSalt:
        raise AssertionError("a resumed scan must not get a fresh salt")

    monkeypatch.setattr(ScanSalt, "generate", staticmethod(refuse))
    latest = cli(base(project, "--resume"))
    assert latest.exit_code == 0, latest.stderr
    assert stub.calls[0]["resume"] == "latest"
    assert stub.calls[0]["salt"] is FIXED_SALT
    named = cli(base(project, "--resume", SCAN))
    assert named.exit_code == 0, named.stderr
    assert stub.calls[1]["resume"] == SCAN
    assert stub.calls[1]["salt"] is FIXED_SALT
    assert [resume for _, resume in calls] == ["latest", SCAN]


def test_resume_without_a_vault_is_refused(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    result = cli(base(project, "--resume"))
    assert result.exit_code == 2
    assert "error[resume_salt_changed]" in result.stderr
    assert "run without --resume" in result.stderr
    assert stub.calls == []


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("checkpoint", "resume_not_found"),
        ("status", "resume_not_cancelled"),
        ("codekavach_version", "resume_config_changed"),
        ("settings_fingerprint", "resume_config_changed"),
        ("salt_fingerprint", "resume_salt_changed"),
        ("target_digest", "resume_target_mismatch"),
    ],
)
def test_each_refused_resume_has_its_code(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch, field: str, code: str
) -> None:
    stored_salt(monkeypatch)
    install_stub(monkeypatch, error=ResumeMismatchError(SCAN, field))
    result = cli(base(project, "--resume", SCAN))
    assert result.exit_code == 2
    assert f"error[{code}]" in result.stderr
    assert "hint: run without --resume to start a new scan" in result.stderr
    assert resume_refusal(ResumeMismatchError(SCAN, field)).code == code
    machine = cli(base(project, "--resume", SCAN, "--json"))
    assert machine.json["exit_code"] == 2
    assert [error["code"] for error in machine.json["errors"]] == [code]


def test_resume_and_no_cache_conflict(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    stored_salt(monkeypatch)
    result = cli(base(project, "--resume", SCAN, "--no-cache"))
    assert result.exit_code == 2
    assert "error[resume_no_cache_conflict]" in result.stderr
    assert stub.calls == []


def interrupted_scan(project: Path, home: Path) -> str:
    """Leave the checkpoint of a cancelled scan of ``project`` and return its scan id."""
    loaded = load_settings(target=project, env={"CODEKAVACH_HOME": str(home)})
    scan_id = new_scan_id()
    layout = StateLayout(project / ".codekavach").ensure()
    write_checkpoint(
        layout,
        Checkpoint(
            scan_id=scan_id,
            status="cancelled",
            codekavach_version=codekavach_version(),
            settings_fingerprint=settings_fingerprint(loaded.settings),
            salt_fingerprint=FIXED_SALT.fingerprint(),
            target_digest=target_digest(str(project)),
            order=[],
            completed=[],
            updated_at=datetime.now(UTC),
        ),
    )
    return scan_id


def test_real_pipeline_refuses_unknown_and_changed_scans(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the real ``run_scan`` and no stage installed: the refusals come from the pipeline."""
    monkeypatch.setitem(backends._OVERRIDES, RUN_SCAN_KEY, run_scan)
    monkeypatch.setattr(runner_module, "registry_from_environment", lambda: PluginRegistry([]))
    stored_salt(monkeypatch)
    unknown = cli(base(project, "--resume", SCAN))
    assert unknown.exit_code == 2
    assert "error[resume_not_found]" in unknown.stderr
    assert "error[resume_not_found]" in cli(base(project, "--resume")).stderr

    scan_id = interrupted_scan(project, isolated_home)
    plain = ["scan", str(project)]  # the checkpoint was written for the default settings
    changed = cli([*plain, "--resume", scan_id, "--privacy-level", "L4"])
    assert changed.exit_code == 2
    assert "error[resume_config_changed]" in changed.stderr
    elsewhere = cli(["scan", str(project.parent), "--resume", scan_id])
    assert elsewhere.exit_code == 2
    monkeypatch.setitem(
        backends._OVERRIDES, SALT_BACKEND, lambda _loaded, _resume: ScanSalt.from_hex("3a" * 32)
    )
    other_salt = cli([*plain, "--resume", scan_id])
    assert "error[resume_salt_changed]" in other_salt.stderr
    stored_salt(monkeypatch)
    resumed = cli([*plain, "--resume"])
    assert resumed.exit_code == 0, resumed.stderr
    again = cli([*plain, "--resume", scan_id])
    assert "error[resume_not_cancelled]" in again.stderr
