"""Generate ``docs/reference/cli.md`` from the live command tree (E05-29).

Usage: ``uv run python tools/gen_cli_docs.py [--out PATH] [--check]``.

A hand-written command reference goes stale within weeks, and this grammar is consumed by other
interfaces (the GitHub Action, the VS Code extension, the pre-commit hook), so the reference is
generated from what ``build_cli()`` builds: the Click tree after the global options are attached
and the sub-applications are mounted, which is what users see. ``--check`` renders in memory,
compares with the file on disk and exits 1 with a diff when they differ (2 when the file is
missing), which is what CI and pre-commit run.

The output is deterministic: no absolute path, no ANSI escape, no Rich markup, a fixed terminal
width, children sorted by name. It is development tooling, so it does not ship in the package.
"""

import argparse
import difflib
import inspect
import os
import re
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path, PurePath
from typing import Any

from rich.errors import MarkupError
from rich.text import Text
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click
from typer.core import TyperGroup

from codekavach.cli.app import build_cli
from codekavach.cli.exit_codes import EXIT_CODE_HELP
from codekavach.cli.options import PANEL

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "docs" / "reference" / "cli.md"
PROGRAM = "codekavach"
WIDTH = 100
NOTICE = (
    "This page is produced by tools/gen_cli_docs.py from the command tree. Do not edit it by hand."
)
DIFF_LINES = 80
SECRET_NAME = re.compile(r"key|token|secret|password|passphrase", re.IGNORECASE)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_ANGLE = re.compile(r"(?<!`)<([^<>\s`]+)>(?!`)")

Params = Sequence[click.Parameter]


# --- walking the tree -----------------------------------------------------------------------


def iter_commands(root: click.Command) -> Iterator[tuple[tuple[str, ...], click.Command]]:
    """Every visible command path, depth first, children sorted by name; hidden ones skipped."""

    def walk(
        command: click.Command, path: tuple[str, ...], ctx: click.Context
    ) -> Iterator[tuple[tuple[str, ...], click.Command]]:
        yield path, command
        if not isinstance(command, TyperGroup):
            return
        for name in sorted(command.list_commands(ctx)):
            child = command.get_command(ctx, name)
            if child is None or getattr(child, "hidden", False):
                continue
            child_ctx = click.Context(child, info_name=name, parent=ctx)
            yield from walk(child, (*path, name), child_ctx)

    yield from walk(root, (), click.Context(root, info_name=PROGRAM, terminal_width=WIDTH))


# --- text helpers ---------------------------------------------------------------------------


def plain(text: str | None) -> str:
    """Help text without Rich markup, ANSI escapes or Typer's ``\\b`` markers, reflowed."""
    if not text:
        return ""
    cleaned = _ANSI.sub("", inspect.cleandoc(text)).replace("\b", "")
    paragraphs = [" ".join(block.split()) for block in re.split(r"\n\s*\n", cleaned)]
    return "\n\n".join(item for item in (_markup_free(block) for block in paragraphs) if item)


def _markup_free(paragraph: str) -> str:
    try:
        return Text.from_markup(paragraph).plain
    except MarkupError:
        return paragraph  # not markup after all: keep the text as written


def escape_cell(text: str) -> str:
    """Make ``text`` safe inside a Markdown table cell: pipes escaped, angle brackets in code."""
    flat = " ".join(plain(text).split())
    return _ANGLE.sub(r"`<\1>`", flat).replace("|", "\\|")


def escape_paragraph(text: str) -> str:
    """Angle brackets of a help paragraph go inside backticks so they render literally."""
    return _ANGLE.sub(r"`<\1>`", plain(text))


def relative(text: str) -> str:
    """A path below the working or home directory in relative form (``~/x``), with forward slashes.

    No absolute path survives into the page, and the same text comes out on every platform.
    """
    candidate = Path(text)
    if not candidate.is_absolute():
        return text.replace(chr(92), "/")
    for base, prefix in ((Path.cwd(), ""), (Path.home(), "~")):
        try:
            rest = candidate.relative_to(base)
        except ValueError:
            continue
        if not rest.parts:
            return prefix or "."
        return f"{prefix}/{rest.as_posix()}" if prefix else rest.as_posix()
    return text


# --- one parameter --------------------------------------------------------------------------


def is_flag(param: click.Parameter) -> bool:
    """A boolean option that takes no value."""
    return bool(getattr(param, "is_flag", False)) and not getattr(param, "count", False)


def type_text(param: click.Parameter) -> str:
    """The type or choices column: a choice list, a range, a metavar or the type name."""
    if is_flag(param):
        return "flag"
    if getattr(param, "count", False):
        return "count"
    kind = param.type
    choices = getattr(kind, "choices", None)
    metavar = getattr(param, "metavar", None)
    if choices:
        text = " | ".join(str(choice) for choice in choices)
    elif metavar:
        text = str(metavar)
    else:
        text = _named_type(kind)
    if getattr(param, "multiple", False):
        text += " (repeatable)"
    return text


def _named_type(kind: Any) -> str:
    name = type(kind).__name__
    low, high = getattr(kind, "min", None), getattr(kind, "max", None)
    if name in {"IntRange", "FloatRange"}:
        label = "INTEGER" if name == "IntRange" else "FLOAT"
        if low is not None and high is not None:
            return f"{label} {low}..{high}"
        if low is not None:
            return f"{label} >= {low}"
        if high is not None:
            return f"{label} <= {high}"
        return label
    return {
        "IntParamType": "INTEGER",
        "FloatParamType": "FLOAT",
        "BoolParamType": "BOOLEAN",
        "StringParamType": "TEXT",
        "TyperPath": "PATH",
    }.get(name, str(getattr(kind, "name", name)).upper())


def default_text(param: click.Parameter) -> str:  # noqa: PLR0911 - one return per kind of default
    """The default column; ``required``, ``(dynamic)`` or the value as written."""
    if param.required:
        return "required"
    default = param.default
    if callable(default):
        return "(dynamic)"
    if is_flag(param):
        return "on" if default else "off"
    if default is None or default in ((), []):
        return ""
    if SECRET_NAME.search(param.name or ""):
        return "(dynamic)"
    if isinstance(default, (list, tuple)):
        return ", ".join(relative(_as_text(item)) for item in default)
    return relative(_as_text(default))


def _as_text(value: object) -> str:
    """A default as text; a path with forward slashes whatever the platform."""
    return PurePath(value).as_posix() if isinstance(value, os.PathLike) else str(value)


def option_name(option: click.Parameter) -> str:
    """``--a / --no-a`` for a flag pair, otherwise every spelling."""
    opts, secondary = list(option.opts), list(getattr(option, "secondary_opts", []))
    if secondary:
        return f"`{opts[0]} / {secondary[0]}`"
    return ", ".join(f"`{name}`" for name in opts)


def description(param: click.Parameter) -> str:
    """The help text of ``param`` plus its environment variable."""
    text = escape_cell(getattr(param, "help", None) or "")
    envvar = getattr(param, "envvar", None)
    if envvar and not getattr(param, "hidden", False):
        names = envvar if isinstance(envvar, str) else ", ".join(envvar)
        suffix = f"Environment: `{names}`."
        text = f"{text} {suffix}".strip()
    return text


# --- sections -------------------------------------------------------------------------------


def _visible(params: Params) -> list[click.Parameter]:
    return [param for param in params if not getattr(param, "hidden", False)]


def is_argument(param: click.Parameter) -> bool:
    """Whether ``param`` is a positional argument and not an option."""
    return getattr(param, "param_type_name", None) == "argument"


def is_global(param: click.Parameter) -> bool:
    """Whether ``param`` is one of the global options shared by every command."""
    return getattr(param, "rich_help_panel", None) == PANEL


def options_table(options: Params) -> list[str]:
    """The ``Option | Type or choices | Default | Description`` table."""
    lines = ["| Option | Type or choices | Default | Description |", "|---|---|---|---|"]
    for option in options:
        cells = [
            option_name(option),
            escape_cell(type_text(option)),
            escape_cell(default_text(option)),
            description(option),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def arguments_table(arguments: Params) -> list[str]:
    """The ``Argument | Type | Default | Description`` table."""
    lines = ["| Argument | Type | Default | Description |", "|---|---|---|---|"]
    for argument in arguments:
        name = str(getattr(argument, "metavar", None) or argument.name or "").upper()
        cells = [
            f"`{name}`",
            escape_cell(type_text(argument)),
            escape_cell(default_text(argument)),
            escape_cell(getattr(argument, "help", None) or ""),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def usage_of(path: tuple[str, ...], command: click.Command) -> str:
    """``Usage: codekavach <path> [OPTIONS] ...`` at the fixed width."""
    name = " ".join((PROGRAM, *path))
    ctx = click.Context(command, info_name=name, terminal_width=WIDTH)
    return " ".join(command.get_usage(ctx).split())


def heading(path: tuple[str, ...]) -> str:
    """The section heading of a command path."""
    return " ".join((PROGRAM, *path))


def anchor(path: tuple[str, ...]) -> str:
    """The GitHub anchor of a command section."""
    return re.sub(r"[^a-z0-9 -]", "", heading(path).lower()).replace(" ", "-")


def render_command(path: tuple[str, ...], command: click.Command) -> str:
    """One section: the heading, the help, the usage, the arguments and the options."""
    params = [param for param in _visible(command.params) if not is_global(param)]
    arguments = [param for param in params if is_argument(param)]
    options = [param for param in params if not is_argument(param)]
    lines = [f"## {heading(path)}", ""]
    text = escape_paragraph(getattr(command, "help", None) or "")
    if text:
        lines += [text, ""]
    lines += ["```text", usage_of(path, command), "```", ""]
    if arguments:
        lines += ["**Arguments**", "", *arguments_table(arguments), ""]
    if options:
        lines += ["**Options**", "", *options_table(options), ""]
    if isinstance(command, TyperGroup):
        lines += ["Run a sub-command with `--help` for its options.", ""]
    lines.append("Global options apply.")
    return "\n".join(lines) + "\n"


def render_reference(root: click.Command) -> str:
    """The whole page for the command tree ``root``."""
    commands = list(iter_commands(root))
    out = [
        "# Command-line reference",
        "",
        NOTICE,
        "",
        "Every command accepts `--help` / `-h`. The global options below are accepted before or"
        " after the sub-command.",
        "",
        "## Contents",
        "",
        "- [Global options](#global-options)",
        "- [Exit codes](#exit-codes)",
    ]
    out += [f"- [{heading(path)}](#{anchor(path)})" for path, _ in commands]
    out += ["", "## Global options", "", *options_table(_visible(_globals(root))), ""]
    out += ["## Exit codes", "", "```text", EXIT_CODE_HELP.rstrip("\n"), "```", ""]
    for path, command in commands:
        out.append(render_command(path, command))
    return "\n".join(out).rstrip("\n") + "\n"


def _globals(root: click.Command) -> list[click.Parameter]:
    return [param for param in root.params if is_global(param)]


# --- the command line -----------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Write the reference, or with ``--check`` report whether the file on disk is current."""
    parser = argparse.ArgumentParser(description="Generate docs/reference/cli.md.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Where to write the page.")
    parser.add_argument("--check", action="store_true", help="Fail when the file is out of date.")
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    content = render_reference(build_cli())
    if not args.check:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        return 0
    if not args.out.exists():
        sys.stderr.write(f"missing: {args.out}\nrefresh: uv run python tools/gen_cli_docs.py\n")
        return 2
    current = args.out.read_bytes().decode("utf-8").replace("\r\n", "\n")  # a CRLF checkout
    if current == content:
        return 0
    diff = difflib.unified_diff(
        current.splitlines(keepends=True),
        content.splitlines(keepends=True),
        fromfile=str(args.out),
        tofile="generated",
    )
    sys.stderr.writelines(list(diff)[:DIFF_LINES])
    sys.stderr.write("\nstale: refresh with `uv run python tools/gen_cli_docs.py`\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
