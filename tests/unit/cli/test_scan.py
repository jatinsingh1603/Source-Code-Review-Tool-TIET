import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codekavach.cli import scan as scan_module
from codekavach.cli.errors import UsageError
from codekavach.cli.scan import check_target, split_formats
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.errors import StageCycleError
from tests.support.cli import CliResult
from tests.support.scan_stub import install_stub

Cli = Callable[..., CliResult]
REMOTE_PROVIDER = (
    '[llm]\ndefault_provider = "cloud"\n[llm.providers.cloud]\nkind = "openai"\nmodel = "m"\n'
)


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def test_target_validation(tmp_path: Path) -> None:
    assert check_target(str(tmp_path)) == tmp_path
    archive = tmp_path / "code.tar.gz"
    archive.write_bytes(b"x")
    assert check_target(str(archive)) == archive
    for url in ("https://example.invalid/r.git", "git@example.invalid:r.git", "ssh://h/r"):
        assert check_target(url) is None
    for bad in (str(tmp_path / "missing"), "", str(tmp_path / "file.txt")):
        if bad.endswith("file.txt"):
            Path(bad).write_text("x")
        with pytest.raises(UsageError) as error:
            check_target(bad)
        assert error.value.code == "target_not_found"


def test_split_formats() -> None:
    assert split_formats(["html,pdf", "sarif", " ,json"]) == ("html", "pdf", "sarif", "json")


def test_missing_target_and_bad_fail_on(cli: Cli, project: Path) -> None:
    result = cli(["scan", str(project / "nope")])
    assert result.exit_code == 2
    assert "error[target_not_found]" in result.stderr
    assert cli(["scan", str(project), "--fail-on", "urgent"]).exit_code == 2


def test_flags_reach_the_loader(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stub = install_stub(monkeypatch)
    result = cli(
        ["scan", str(project), "--no-llm", "--format", "html,pdf", "--format", "sarif",
         "--output-dir", "out", "--jobs", "2", "--fail-on", "HIGH", "--include", "src/**",
         "--exclude", "legacy/**"],
    )  # fmt: skip
    assert result.exit_code == 0, result.stderr
    loaded = stub.calls[0]["loaded"]
    settings = loaded.settings
    assert settings.llm.enabled is False
    assert [f.value for f in settings.reporting.formats] == ["html", "pdf", "sarif"]
    assert settings.scan.jobs == 2
    assert settings.scan.fail_on == "high"
    assert settings.scan.include == ["src/**"]
    assert settings.scan.exclude == ["legacy/**"]
    assert loaded.origins["scan.jobs"].source == "--jobs"


def test_engine_flags_reach_the_engines_section(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    result = cli(["scan", str(project), "--engine", "semgrep", "--skip-engine", "bandit"])
    assert result.exit_code == 0, result.stderr
    loaded = stub.calls[0]["loaded"]
    assert loaded.settings.engines.enabled == ["semgrep"]
    assert loaded.settings.engines.disabled == ["bandit"]
    assert loaded.origins["engines.enabled"].source == "--engine"


def test_invalid_engine_id_is_a_usage_error(cli: Cli, project: Path) -> None:
    result = cli(["scan", str(project), "--engine", "Not Valid"])
    assert result.exit_code == 2
    assert "Not Valid" not in result.stderr


def test_project_config_is_discovered_from_the_target(
    cli: Cli, project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    (project / "codekavach.toml").write_text("[scan]\njobs = 7\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert cli(["scan", str(project)], cwd=elsewhere).exit_code == 0
    assert stub.calls[0]["loaded"].settings.scan.jobs == 7


def test_everything_goes_through_run_scan(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    cli(["scan", str(project)])
    (call,) = stub.calls
    assert call["target"] == str(project)
    assert set(call) == {"loaded", "target", "salt", "bus", "cancellation"}
    assert type(call["salt"]).__name__ == "ScanSalt"


def test_remote_provider_is_refused(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = install_stub(monkeypatch)
    (project / "codekavach.toml").write_text(REMOTE_PROVIDER)
    # A provider defined in the project file needs a trusted project (E03-25).
    trust = "--trust-project-config"
    result = cli(["scan", str(project), trust])
    assert result.exit_code == 3
    assert "error[consent_unavailable]" in result.stderr
    assert stub.calls == []
    assert cli(["scan", str(project), "--no-llm", trust]).exit_code == 0
    assert len(stub.calls) == 1


def test_warnings_in_both_modes(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub(
        monkeypatch,
        status=ScanStatus.COMPLETED_WITH_ERRORS,
        order=("ingest", "analyse-taint"),
        failed=("analyse-taint",),
        blocked=2,
    )
    human = cli(["scan", str(project)])
    assert "warning[stage_degraded]: stage analyse-taint failed" in human.stderr
    assert "warning[egress_blocked]" in human.stderr
    machine = cli(["scan", str(project), "--json"])
    codes = [warning["code"] for warning in machine.json["warnings"]]
    assert codes == ["stage_degraded", "egress_blocked"]
    assert machine.json["data"]["degraded_stages"] == ["analyse-taint"]
    assert machine.json["data"]["egress"]["blocked"] == 2


def test_no_stages(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub(monkeypatch, order=())
    result = cli(["scan", str(project)])
    assert result.exit_code == 0
    assert "warning[no_stages]" in result.stderr


def test_mock_provider_message(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub(monkeypatch)
    result = cli(["scan", str(project)])
    assert "payloads were recorded but not transmitted" in result.stdout
    assert "LLM provider: mock (local), level L3" in result.stdout


def test_pipeline_errors(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub(monkeypatch, error=StageCycleError(("a", "b", "a")))
    result = cli(["scan", str(project)])
    assert result.exit_code == 4
    assert "error[pipeline_invalid]" in result.stderr


def test_run_level_privacy_failure(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class EgressBlocked(Exception):  # noqa: N818 - mirrors the E12 name
        block_code = "vault_unavailable"

    import codekavach.cli.app as app_module  # noqa: PLC0415

    real = app_module._optional_class

    def seam(module: str, name: str) -> Any:
        return EgressBlocked if name == "EgressBlocked" else real(module, name)

    monkeypatch.setattr(app_module, "_optional_class", seam)
    install_stub(monkeypatch, error=EgressBlocked())
    result = cli(["scan", str(project)])
    assert result.exit_code == 3


def test_failed_and_cancelled_scans(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_stub(monkeypatch, status=ScanStatus.FAILED, failed=("ingest",))
    failed = cli(["scan", str(project)])
    assert (failed.exit_code, "error[scan_failed]" in failed.stderr) == (4, True)
    install_stub(monkeypatch, status=ScanStatus.CANCELLED)
    assert cli(["scan", str(project)]).exit_code == 130


def test_no_egress_imports() -> None:
    code = (
        "import codekavach.cli.scan, sys; "
        "bad = [m for m in sys.modules if m.startswith(('codekavach.llm', "
        "'codekavach.privacy.egress'))]; assert not bad, bad"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
    assert scan_module.__doc__ is not None
