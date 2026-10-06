"""Help-text snapshots: every command's ``--help`` compared with a committed text file.

The option grammar and help text of the CLI are a public contract. A snapshot per command path
makes a change visible as a diff in the commit that causes it. The workflow is described in
``docs/process/cli-snapshots.md``.

No snapshot library is used: the need is a folder of text files and a diff. An update is asked
for with ``CODEKAVACH_UPDATE_SNAPSHOTS=1``; the file is then written and the test still fails, so
an update cannot pass a pipeline unnoticed.
"""

import contextlib
import difflib
import os
from collections.abc import Iterator, Sequence
from pathlib import Path

import rich.console
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click
from typer.core import TyperGroup

from tests.support.cli import run_cli

UPDATE_VARIABLE = "CODEKAVACH_UPDATE_SNAPSHOTS"
ROOT_NAME = "root"
TEST_FILE = "tests/unit/cli/test_help_snapshots.py"
WRITTEN = f"snapshot written; re-run without {UPDATE_VARIABLE}"

CommandPath = tuple[str, ...]


def command_paths(command: object) -> list[CommandPath]:
    """The root, every group and every leaf command, in name order; hidden commands excluded."""
    paths: list[CommandPath] = [()]

    def visit(node: object, prefix: CommandPath) -> None:
        # Through the Click API, so that lazily mounted commands (E05-31) are resolved too.
        children: dict[str, object] = {}
        if isinstance(node, TyperGroup):
            ctx = click.Context(node)
            for name in node.list_commands(ctx):
                found = node.get_command(ctx, name)
                if found is not None:
                    children[name] = found
        for name in sorted(children):
            child = children[name]
            if getattr(child, "hidden", False):
                continue
            paths.append((*prefix, name))
            visit(child, (*prefix, name))

    visit(command, ())
    return paths


def snapshot_name(path: CommandPath) -> str:
    """The file stem and test id of a command path: ``privacy-ledger-verify``, or ``root``."""
    return "-".join(path) or ROOT_NAME


def label(path: CommandPath) -> str:
    """The command path as messages name it."""
    return " ".join(path) or ROOT_NAME


def normalise(text: str) -> str:
    """``text`` without trailing whitespace on any line and with a single trailing newline."""
    lines = [line.rstrip() for line in text.splitlines()]
    return "\n".join(lines).rstrip("\n") + "\n"


@contextlib.contextmanager
def platform_independent_rendering() -> Iterator[None]:
    """Render as Linux and macOS do, also on Windows.

    For output that is not a console, Rich on Windows assumes a legacy console: one column
    narrower and with square instead of rounded boxes. Snapshots are shared by all platforms.
    """
    saved = rich.console.detect_legacy_windows
    rich.console.detect_legacy_windows = lambda: False
    try:
        yield
    finally:
        rich.console.detect_legacy_windows = saved


def render_help(path: CommandPath, *, home: Path | None = None) -> str:
    """``codekavach <path> --help`` in the harness environment, normalised."""
    with platform_independent_rendering():
        result = run_cli([*path, "--help"], home=home)
    assert result.exit_code == 0, f"--help of '{label(path)}' failed: {result.stderr}"
    return normalise(result.stdout)


def update_requested() -> bool:
    """Whether this run was asked to rewrite the snapshots."""
    return os.environ.get(UPDATE_VARIABLE) == "1"


def check_snapshot(
    path: CommandPath, current: str, directory: Path, *, update: bool | None = None
) -> None:
    """Compare ``current`` with the snapshot of ``path`` in ``directory``.

    Raises:
        AssertionError: the snapshot is missing or differs (with a unified diff), and always in
            update mode, after the file was written.
    """
    file = directory / f"{snapshot_name(path)}.txt"
    if update_requested() if update is None else update:
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(current.encode("utf-8"))
        raise AssertionError(WRITTEN)
    if not file.is_file():
        raise AssertionError(
            f"no snapshot for '{label(path)}'; run {UPDATE_VARIABLE}=1 uv run pytest {TEST_FILE}"
        )
    stored = file.read_text(encoding="utf-8")
    if stored == current:
        return
    diff = difflib.unified_diff(
        stored.splitlines(), current.splitlines(), "snapshot", "current", lineterm=""
    )
    raise AssertionError(f"help text changed for '{label(path)}':\n" + "\n".join(diff))


def orphan_snapshots(directory: Path, paths: Sequence[CommandPath]) -> list[str]:
    """Files in ``directory`` that belong to no command path."""
    if not directory.is_dir():
        return []
    expected = {f"{snapshot_name(path)}.txt" for path in paths}
    return sorted(file.name for file in directory.iterdir() if file.name not in expected)
