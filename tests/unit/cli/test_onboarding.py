import json
import os
import stat
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from rich.console import Console

from codekavach.cli.onboarding import (
    LEVEL_LINES,
    STATE_FILE,
    CliState,
    build_notice,
    notice_lines,
    read_cli_state,
    state_path,
    write_cli_state,
)
from codekavach.core.models import PrivacyLevel
from tests.support.cli import CliResult
from tests.support.golden import assert_matches_golden
from tests.support.scan_stub import install_stub

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden"
FORBIDDEN = ("never", "guarantee", "guaranteed", "impossible", "100%")
TITLE = "CodeKavach privacy notice"
REMOTE = (
    '[llm]\ndefault_provider = "primary"\n'
    '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'
)
VARIANTS = {
    "l3_mock": {
        "level": PrivacyLevel.L3,
        "provider_id": "mock",
        "provider_kind": "mock",
        "is_remote": False,
        "llm_enabled": True,
    },
    "l3_remote": {
        "level": PrivacyLevel.L3,
        "provider_id": "primary",
        "provider_kind": "anthropic",
        "is_remote": True,
        "llm_enabled": True,
        "origin": "project",
    },
    "l4_remote": {
        "level": PrivacyLevel.L4,
        "provider_id": "primary",
        "provider_kind": "anthropic",
        "is_remote": True,
        "llm_enabled": True,
        "origin": "cli",
    },
    "l0_local": {
        "level": PrivacyLevel.L0,
        "provider_id": "local",
        "provider_kind": "ollama",
        "is_remote": False,
        "llm_enabled": True,
        "origin": "profile",
    },
    "llm_disabled": {
        "level": PrivacyLevel.L3,
        "provider_id": "none",
        "provider_kind": "none",
        "is_remote": False,
        "llm_enabled": False,
    },
}


def flat(text: str) -> str:
    """The notice text on one line, without the panel border."""
    return " ".join(text.replace("│", " ").split())


def rendered(name: str) -> str:
    console = Console(
        width=100, record=True, force_terminal=False, color_system=None, legacy_windows=False
    )
    with console.capture() as capture:
        console.print(build_notice(**VARIANTS[name]))  # type: ignore[arg-type]
    return capture.get()


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_notice_matches_its_golden_file(name: str) -> None:
    text = rendered(name)
    assert_matches_golden(text, GOLDEN / f"notice_{name}.txt")
    assert TITLE in text
    assert len(text.splitlines()) <= 18
    lowered = text.lower()
    for word in FORBIDDEN:
        assert word not in lowered, word


def test_golden_files_hold_no_forbidden_words() -> None:
    files = sorted(GOLDEN.glob("notice_*.txt"))
    assert len(files) == len(VARIANTS)
    for path in files:
        lowered = path.read_text(encoding="utf-8").lower()
        for word in FORBIDDEN:
            assert word not in lowered, (path.name, word)


def test_notice_content_per_configuration() -> None:
    mock = rendered("l3_mock")
    assert "nothing is transmitted" in mock
    assert "Effective privacy level: L3 (from default)" in mock
    assert LEVEL_LINES[PrivacyLevel.L3] in mock
    assert "asked to confirm" not in mock
    remote = rendered("l3_remote")
    assert "LLM provider: primary (kind anthropic, remote)" in remote
    assert "asked to confirm before the first payload is sent" in flat(remote)
    assert "structure and control flow of each slice" in flat(remote)
    assert "data-flow facts only, no code" in flat(rendered("l4_remote"))
    assert "nothing leaves the machine" in flat(rendered("l0_local"))
    disabled = rendered("llm_disabled")
    assert "LLM review is disabled; only local engines run" in disabled
    assert "LLM provider:" not in disabled
    every_level = [
        notice_lines(
            level=level, provider_id="p", provider_kind="k", is_remote=True, llm_enabled=True
        )
        for level in PrivacyLevel
    ]
    assert len({tuple(lines) for lines in every_level}) == len(PrivacyLevel)


# state


def test_state_round_trip_and_location(tmp_path: Path) -> None:
    env = {"CODEKAVACH_HOME": str(tmp_path / "home")}
    assert read_cli_state(env) == CliState()
    assert not read_cli_state(env).notice_shown
    shown = datetime(2026, 10, 4, 9, 30, tzinfo=UTC)
    write_cli_state(env, CliState(shown, "0.1.0"))
    path = tmp_path / "home" / STATE_FILE
    assert state_path(env) == path
    assert read_cli_state(env) == CliState(shown, "0.1.0")
    assert read_cli_state(env).notice_shown
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document == {
        "version": 1,
        "first_run_notice_shown_at": "2026-10-04T09:30:00Z",
        "codekavach_version": "0.1.0",
    }
    assert [entry.name for entry in path.parent.iterdir()] == [STATE_FILE]
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_write_failure_is_ignored(tmp_path: Path) -> None:
    blocker = tmp_path / "home"
    blocker.write_text("a file where the directory should be", encoding="utf-8")
    env = {"CODEKAVACH_HOME": str(blocker)}
    write_cli_state(env, CliState(datetime.now(UTC), "0.1.0"))
    assert read_cli_state(env) == CliState()


@pytest.mark.parametrize(
    "content",
    [
        b"{",
        b"\x00\xff\xfe binary",
        b"[]",
        b"null",
        b'{"version": 2, "first_run_notice_shown_at": "2026-10-04T09:30:00Z"}',
        b'{"version": 1}',
        b'{"version": 1, "first_run_notice_shown_at": "yesterday"}',
        b'{"version": 1, "first_run_notice_shown_at": "2026-10-04T09:30:00"}',
        b'{"version": 1, "first_run_notice_shown_at": null}',
    ],
)
def test_malformed_state_means_not_shown(tmp_path: Path, content: bytes) -> None:
    env = {"CODEKAVACH_HOME": str(tmp_path)}
    (tmp_path / STATE_FILE).write_bytes(content)
    assert read_cli_state(env) == CliState()


@given(content=st.binary(max_size=400))
def test_arbitrary_bytes_never_raise_and_mean_not_shown(content: bytes) -> None:
    import tempfile  # noqa: PLC0415 - one directory per example

    with tempfile.TemporaryDirectory() as directory:
        Path(directory, STATE_FILE).write_bytes(content)
        state = read_cli_state({"CODEKAVACH_HOME": directory})
    try:
        document = json.loads(content)
        valid = isinstance(document, dict) and document.get("version") == 1
    except (ValueError, RecursionError):
        valid = False
    if not valid:
        assert state == CliState()


# scan and privacy notice


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def scan(cli: Cli, project: Path, *args: str, tty: bool = True) -> CliResult:
    return cli(["scan", str(project), "--fail-on", "none", *args], tty=tty)


def test_scan_shows_the_notice_once(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_stub(monkeypatch)
    first = scan(cli, project)
    assert first.exit_code == 0, first.stderr
    assert TITLE in first.stderr
    assert "nothing is transmitted" in first.stderr
    assert TITLE not in first.stdout
    state = isolated_home / STATE_FILE
    assert state.is_file()
    assert read_cli_state({"CODEKAVACH_HOME": str(isolated_home)}).notice_shown
    if os.name != "nt":
        assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert not list(project.rglob(STATE_FILE))
    second = scan(cli, project)
    assert TITLE not in second.stderr


@pytest.mark.parametrize(
    ("args", "tty"),
    [(("--quiet",), True), (("--json",), True), (("--no-input",), True), ((), False)],
)
def test_notice_is_not_shown_or_recorded_without_a_person(  # noqa: PLR0917 - fixtures
    cli: Cli,
    project: Path,
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: tuple[str, ...],
    tty: bool,
) -> None:
    install_stub(monkeypatch)
    result = scan(cli, project, *args, tty=tty)
    assert result.exit_code == 0, result.stderr
    assert TITLE not in result.stderr
    assert TITLE not in result.stdout
    assert not (isolated_home / STATE_FILE).exists()


@pytest.mark.parametrize("content", [b"{", b"\x00\x01\x02\xff"])
def test_corrupt_state_shows_the_notice_and_is_rewritten(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    install_stub(monkeypatch)
    (isolated_home / STATE_FILE).write_bytes(content)
    result = scan(cli, project)
    assert TITLE in result.stderr
    assert read_cli_state({"CODEKAVACH_HOME": str(isolated_home)}).notice_shown


def test_remote_provider_notice_names_the_confirmation(
    cli: Cli, project: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_stub(monkeypatch)
    (project / "codekavach.toml").write_text(REMOTE, encoding="utf-8")
    result = scan(cli, project, "--trust-project-config")
    assert result.exit_code == 3  # the consent gate is not in this build
    assert "kind anthropic, remote" in result.stderr
    assert "asked to confirm" in flat(result.stderr)


def test_privacy_notice_command(cli: Cli, project: Path, isolated_home: Path) -> None:
    for _ in range(2):
        result = cli(["privacy", "notice"], cwd=project)
        assert result.exit_code == 0, result.stderr
        assert TITLE in result.stdout
        assert "nothing is transmitted" in result.stdout
    assert not (isolated_home / STATE_FILE).exists()
    (project / "codekavach.toml").write_text("[llm]\nenabled = false\n", encoding="utf-8")
    disabled = cli(["privacy", "notice"], cwd=project)
    assert "LLM review is disabled" in disabled.stdout
    machine = cli(["privacy", "notice", "--json", "--privacy-level", "L4"], cwd=project)
    data = machine.json["data"]
    assert (data["privacy_level"], data["origin"], data["llm_enabled"]) == ("L4", "cli", False)
    assert any("LLM review is disabled" in line for line in data["lines"])
