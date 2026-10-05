import re
from pathlib import Path

import pytest
import typer
from typer import _click as click

from codekavach.cli.app import HELP, build_cli
from codekavach.cli.exit_codes import ExitCode
from tests.support.help_snapshots import (
    UPDATE_VARIABLE,
    WRITTEN,
    CommandPath,
    check_snapshot,
    command_paths,
    normalise,
    orphan_snapshots,
    render_help,
    snapshot_name,
)

SNAPSHOTS = Path(__file__).parent / "snapshots" / "help"
PATHS = command_paths(build_cli())
WIDTH = 100
ABSOLUTE_PATH = re.compile(r"(?<![\w.])(?:[A-Za-z]:[\\/]|/(?:home|Users|tmp|var|root|private)/)")


@pytest.mark.parametrize("path", PATHS, ids=[snapshot_name(path) for path in PATHS])
def test_help_matches_its_snapshot(path: CommandPath, isolated_home: Path) -> None:
    current = render_help(path, home=isolated_home)
    assert str(isolated_home) not in current
    check_snapshot(path, current, SNAPSHOTS)


def test_every_snapshot_belongs_to_a_command() -> None:
    orphans = orphan_snapshots(SNAPSHOTS, PATHS)
    assert not orphans, f"snapshot without a command, delete it: {', '.join(orphans)}"


def test_snapshots_are_plain_narrow_and_free_of_absolute_paths() -> None:
    files = sorted(SNAPSHOTS.glob("*.txt"))
    assert len(files) == len(PATHS)
    for file in files:
        text = file.read_text(encoding="utf-8")
        assert "\x1b" not in text, file.name
        assert text == normalise(text), file.name
        assert ABSOLUTE_PATH.search(text) is None, file.name
        assert max(len(line) for line in text.splitlines()) <= WIDTH, file.name


def test_root_snapshot_keeps_its_four_markers() -> None:
    """A wholesale update cannot drop the description, the commands, the options or the codes."""
    flat = " ".join((SNAPSHOTS / "root.txt").read_text(encoding="utf-8").split())
    assert HELP in flat
    assert "Global options" in flat
    assert "Exit codes:" in flat
    for code in ExitCode:
        assert f"{code.value} {code.name}" in flat
    top_level = [path[0] for path in PATHS if len(path) == 1]
    assert top_level
    commands = flat.split("Commands", 1)[1].split("Exit codes:", 1)[0]
    for name in top_level:
        assert re.search(rf"│ {re.escape(name)} ", commands), name


def test_two_renders_are_identical(isolated_home: Path) -> None:
    for path in ((), ("scan",)):
        first = render_help(path, home=isolated_home)
        assert render_help(path, home=isolated_home).encode() == first.encode()


# the helper


def _nothing() -> None:
    """A command body for synthetic trees."""


def synthetic_tree() -> click.Command:
    ledger = typer.Typer()
    ledger.command("verify")(_nothing)
    ledger.command("show")(_nothing)
    privacy = typer.Typer()
    privacy.add_typer(ledger, name="ledger")
    privacy.command("internal", hidden=True)(_nothing)
    privacy.command("notice")(_nothing)
    concealed = typer.Typer()
    concealed.command("one")(_nothing)
    concealed.command("two")(_nothing)
    root = typer.Typer()
    root.add_typer(privacy, name="privacy")
    root.add_typer(concealed, name="secret-group", hidden=True)
    root.command("scan")(_nothing)
    return typer.main.get_command(root)


def test_enumeration_of_a_synthetic_tree() -> None:
    paths = command_paths(synthetic_tree())
    assert paths == [
        (),
        ("privacy",),
        ("privacy", "ledger"),
        ("privacy", "ledger", "show"),
        ("privacy", "ledger", "verify"),
        ("privacy", "notice"),
        ("scan",),
    ]
    assert [snapshot_name(path) for path in paths] == [
        "root",
        "privacy",
        "privacy-ledger",
        "privacy-ledger-show",
        "privacy-ledger-verify",
        "privacy-notice",
        "scan",
    ]
    assert len({snapshot_name(path) for path in PATHS}) == len(PATHS)


def test_normalisation() -> None:
    assert normalise("a  \n\n b\t\n") == "a\n\n b\n"
    assert normalise("a") == "a\n"
    assert normalise("a\n\n\n") == "a\n"
    assert normalise("\n a   \r\n") == "\n a\n"


def test_compare_mode_shows_a_unified_diff(tmp_path: Path) -> None:
    (tmp_path / "scan.txt").write_text("Usage\n  --fail-on LEVEL\nend\n", encoding="utf-8")
    check_snapshot(("scan",), "Usage\n  --fail-on LEVEL\nend\n", tmp_path, update=False)
    with pytest.raises(AssertionError) as caught:
        check_snapshot(("scan",), "Usage\n  --fail-at LEVEL\nend\n", tmp_path, update=False)
    message = str(caught.value)
    assert message.startswith("help text changed for 'scan':\n--- snapshot\n+++ current\n@@")
    assert "\n-  --fail-on LEVEL\n+  --fail-at LEVEL\n" in message


def synthetic_app() -> typer.Typer:
    app = typer.Typer()
    app.command("temporary")(_nothing)
    return app


def test_a_command_without_a_snapshot_fails_with_the_instruction() -> None:
    command = build_cli()
    command.add_command(typer.main.get_command(synthetic_app()), "temporary")  # type: ignore[attr-defined]
    assert ("temporary",) in command_paths(command)
    with pytest.raises(AssertionError) as caught:
        check_snapshot(("temporary",), "text\n", SNAPSHOTS, update=False)
    assert str(caught.value) == (
        "no snapshot for 'temporary'; run CODEKAVACH_UPDATE_SNAPSHOTS=1 "
        "uv run pytest tests/unit/cli/test_help_snapshots.py"
    )
    with pytest.raises(AssertionError, match="no snapshot for 'vault rotate'"):
        check_snapshot(("vault", "rotate"), "text\n", SNAPSHOTS / "missing", update=False)


def test_orphan_detection(tmp_path: Path) -> None:
    paths: list[CommandPath] = [(), ("scan",), ("vault", "rotate")]
    for name in ("root.txt", "scan.txt", "vault-rotate.txt"):
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    assert orphan_snapshots(tmp_path, paths) == []
    (tmp_path / "vault-export.txt").write_text("x\n", encoding="utf-8")
    assert orphan_snapshots(tmp_path, paths) == ["vault-export.txt"]
    assert orphan_snapshots(tmp_path / "absent", paths) == []


def test_update_mode_writes_and_still_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(UPDATE_VARIABLE, "1")
    folder = tmp_path / "help"
    with pytest.raises(AssertionError) as caught:
        check_snapshot(("scan",), "new text\n", folder)
    assert str(caught.value) == WRITTEN
    assert str(caught.value) == "snapshot written; re-run without CODEKAVACH_UPDATE_SNAPSHOTS"
    assert (folder / "scan.txt").read_bytes() == b"new text\n"
    monkeypatch.delenv(UPDATE_VARIABLE)
    check_snapshot(("scan",), "new text\n", folder)
    monkeypatch.setenv(UPDATE_VARIABLE, "true")  # only "1" asks for an update
    with pytest.raises(AssertionError, match="help text changed"):
        check_snapshot(("scan",), "other text\n", folder)
