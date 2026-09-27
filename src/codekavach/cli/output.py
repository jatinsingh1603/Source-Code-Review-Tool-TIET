"""The single output abstraction of every command: Rich for people, one JSON envelope for machines.

Owning epic: E05.

A command calls ``out = get_output(ctx)``, then ``out.info``, ``out.warn`` and
``out.result(data, human=render)``. In human mode results go to stdout and diagnostics to stderr;
``--quiet`` drops ``info`` only. In ``--json`` mode stdout carries exactly one compact JSON
document, the versioned ``Envelope``, written once by ``finish()`` with the final exit code, which
``codekavach.cli.app.run`` calls on every path, including errors.

Machine output is copied into CI logs, issue comments and dashboards, so ``to_jsonable`` is the
only serialisation path and it refuses raw client code (``RawCode``, ``CodeSlice``), vault
material (any class from ``codekavach.privacy.vault``) and, unless explicitly allowed, sanitised
text (I2, I3). The walk happens on Python objects, because JSON conversion erases the wrappers.
"""

import dataclasses
import enum
import json
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import PurePath
from typing import Any, Literal

from pydantic import BaseModel, JsonValue
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli._version import get_version
from codekavach.cli.console import get_console, get_err_console

OUTPUT_KEY = "codekavach.output"
SCHEMA_VERSION: Literal["1"] = "1"
_REFUSED_NAMES = {
    ("codekavach.core.models.text", "RawCode"),
    ("codekavach.core.models.slice", "CodeSlice"),
}
_SANITISED = ("codekavach.core.models.text", "SanitisedText")
_VAULT_PREFIX = "codekavach.privacy.vault"
_SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
# One explicit border style: Rich would otherwise pick a different default on legacy Windows
# consoles, and output would differ between platforms.
TABLE_BOX = box.SQUARE
_STATUS_STYLES = {"pass": "green", "warn": "yellow", "fail": "red", "skip": "dim"}


class EnvelopeMessage(BaseModel):
    """One warning or error in the envelope."""

    code: str
    message: str
    hint: str | None = None


class Envelope(BaseModel):
    """The JSON document written to stdout in ``--json`` mode (stable while additive)."""

    schema_version: Literal["1"]
    codekavach_version: str
    command: str
    ok: bool
    exit_code: int
    data: JsonValue
    warnings: tuple[EnvelopeMessage, ...]
    errors: tuple[EnvelopeMessage, ...]


def _identity(obj: object) -> tuple[str, str]:
    cls = type(obj)
    return cls.__module__, cls.__qualname__


def _refuse(obj: object) -> TypeError:
    return TypeError(f"refusing to serialise {type(obj).__name__} to CLI output")


def _check(obj: object, allow_sanitised: bool) -> None:
    module, name = _identity(obj)
    if (module, name) in _REFUSED_NAMES or module.startswith(_VAULT_PREFIX):
        raise _refuse(obj)
    if (module, name) == _SANITISED and not allow_sanitised:
        raise _refuse(obj)


def to_jsonable(obj: Any, *, allow_sanitised: bool = False) -> JsonValue:  # noqa: PLR0911
    """Convert ``obj`` to JSON data, refusing raw code, vault material and sanitised text."""
    _check(obj, allow_sanitised)
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if _identity(obj) == _SANITISED:
        return str(obj.expose())
    if isinstance(obj, enum.Enum):
        return to_jsonable(obj.value, allow_sanitised=allow_sanitised)
    if isinstance(obj, datetime):
        moment = obj if obj.tzinfo else obj.replace(tzinfo=UTC)
        return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, PurePath):
        return str(obj)
    if isinstance(obj, BaseModel):
        _deep_check(obj, allow_sanitised)
        dumped: JsonValue = obj.model_dump(mode="json")
        return dumped
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            field.name: to_jsonable(getattr(obj, field.name), allow_sanitised=allow_sanitised)
            for field in dataclasses.fields(obj)
        }
    if isinstance(obj, Mapping):
        return {
            str(key): to_jsonable(value, allow_sanitised=allow_sanitised)
            for key, value in obj.items()
        }
    if isinstance(obj, (set, frozenset, tuple, list)):
        items = [to_jsonable(item, allow_sanitised=allow_sanitised) for item in obj]
        if isinstance(obj, (set, frozenset)):
            try:
                return sorted(items)  # type: ignore[type-var]
            except TypeError:
                return items
        return items
    raise TypeError(f"cannot serialise {type(obj).__name__} to CLI output")


def _deep_check(obj: object, allow_sanitised: bool) -> None:
    _check(obj, allow_sanitised)
    if isinstance(obj, BaseModel):
        for name in type(obj).model_fields:
            _deep_check(getattr(obj, name), allow_sanitised)
    elif isinstance(obj, Mapping):
        for key, value in obj.items():
            _deep_check(key, allow_sanitised)
            _deep_check(value, allow_sanitised)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            _deep_check(item, allow_sanitised)
    elif dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        for field in dataclasses.fields(obj):
            _deep_check(getattr(obj, field.name), allow_sanitised)


class Output:
    """Output of one invocation (human or JSON)."""

    def __init__(self, *, json_mode: bool, quiet: bool, command: str) -> None:
        self.json_mode = json_mode
        self.quiet = quiet
        self.command = command
        self._data: JsonValue = None
        self._warnings: list[EnvelopeMessage] = []
        self._errors: list[EnvelopeMessage] = []
        self._finished = False

    def info(self, text: str) -> None:
        """A progress or context line on stderr; dropped under ``--quiet`` and in JSON mode."""
        if not self.json_mode and not self.quiet:
            get_err_console().print(text, markup=False)

    def warn(self, code: str, message: str, hint: str | None = None) -> None:
        """A warning: stderr in human mode (also under ``--quiet``), the envelope in JSON mode."""
        if self.json_mode:
            self._warnings.append(EnvelopeMessage(code=code, message=message, hint=hint))
            return
        console = get_err_console()
        console.print(f"warning[{code}]: {message}", markup=False)
        if hint:
            console.print(f"hint: {hint}", markup=False)

    def result(self, data: Any, *, human: Callable[[Console], None] | None = None) -> None:
        """The command's result: rendered to stdout, or stored for the envelope."""
        jsonable = to_jsonable(data)
        if self.json_mode:
            self._data = jsonable
            return
        console = get_console()
        if human is not None:
            human(console)
        elif isinstance(jsonable, dict):
            console.print(kv_table(None, [(key, _plain(value)) for key, value in jsonable.items()]))
        else:
            console.print(_plain(jsonable), markup=False)

    def record_error(self, code: str, message: str, hint: str | None = None) -> None:
        """Keep an error for the envelope (at most one per raised error)."""
        self._errors.append(EnvelopeMessage(code=code, message=message, hint=hint))

    def error(self, exc: BaseException) -> None:
        """Record ``exc`` for the envelope (JSON mode) or print its diagnostic (human mode)."""
        from codekavach.cli.errors import CliError, error_line  # noqa: PLC0415 - cycle

        if isinstance(exc, CliError):
            code, message, hint = exc.code, exc.message, exc.hint
        else:
            code = "internal"
            message = f"unexpected {type(exc).__name__}; run again with --debug for a traceback"
            hint = None
        if self.json_mode:
            self.record_error(code, message, hint)
            return
        console = get_err_console()
        console.print(error_line(code, message), markup=False)
        if hint:
            console.print(f"hint: {hint}", markup=False)

    def envelope(self, exit_code: int) -> Envelope:
        """The envelope for ``exit_code``."""
        return Envelope(
            schema_version=SCHEMA_VERSION,
            codekavach_version=get_version(),
            command=self.command,
            ok=exit_code == 0,
            exit_code=exit_code,
            data=self._data,
            warnings=tuple(self._warnings),
            errors=tuple(self._errors),
        )

    def finish(self, exit_code: int) -> None:
        """Write the envelope once (JSON mode); later calls do nothing."""
        if self._finished:
            return
        self._finished = True
        if self.json_mode:
            text = json.dumps(
                self.envelope(exit_code).model_dump(mode="json"),
                separators=(",", ":"),
                ensure_ascii=False,
            )
            sys.stdout.write(text + "\n")
            sys.stdout.flush()


_CURRENT: list[Output] = []
_PENDING: list[EnvelopeMessage] = []


def current_output() -> Output | None:
    """The ``Output`` of the invocation in progress, if a command created one."""
    return _CURRENT[-1] if _CURRENT else None


def begin_invocation() -> None:
    """Forget the previous invocation's output and pending errors (called by ``run``)."""
    _CURRENT.clear()
    _PENDING.clear()


def fallback_output(*, json_mode: bool, command: str) -> Output:
    """The current output, or a new one (holding pending errors) when no command created one."""
    found = current_output()
    if found is not None:
        return found
    output = Output(json_mode=json_mode, quiet=False, command=command)
    for message in _PENDING:
        output.record_error(message.code, message.message, message.hint)
    _PENDING.clear()
    _CURRENT.append(output)
    return output


def write_error_envelope(*, code: str, message: str, hint: str | None) -> None:
    """Record an error for the envelope that ``run`` writes with the final exit code."""
    output = current_output()
    if output is None:
        _PENDING.append(EnvelopeMessage(code=code, message=message, hint=hint))
    else:
        output.record_error(code, message, hint)


def command_path(ctx: click.Context) -> str:
    """``privacy ledger verify`` for ``codekavach privacy ledger verify``."""
    parts = ctx.command_path.split()
    return " ".join(parts[1:])


def get_output(ctx: click.Context) -> Output:
    """The ``Output`` of this invocation, created once from the global options."""
    from codekavach.cli.context import get_context  # noqa: PLC0415 - keeps imports light

    root = ctx.find_root()
    cached = root.meta.get(OUTPUT_KEY)
    if isinstance(cached, Output):
        return cached
    cli_context = get_context(ctx)
    output = Output(
        json_mode=cli_context.json_mode, quiet=cli_context.quiet, command=command_path(ctx)
    )
    root.meta[OUTPUT_KEY] = output
    _CURRENT.append(output)
    return output


def _plain(value: JsonValue) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return "" if value is None else str(value)


def kv_table(title: str | None, rows: Iterable[tuple[str, str]]) -> Table:
    """A two-column key/value table without colour-only meaning."""
    table = Table(title=title, show_header=False, box=None, pad_edge=False)
    table.add_column("key", style="bold", no_wrap=True)
    table.add_column("value", overflow="fold")
    for key, value in rows:
        table.add_row(key, value)
    return table


def simple_table(columns: Sequence[str], rows: Iterable[Sequence[str]]) -> Table:
    """A table with a header row; long values fold instead of being truncated."""
    table = Table(show_header=True, header_style="bold", pad_edge=False, box=TABLE_BOX)
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(*row)
    return table


def severity_style(severity: str) -> str:
    """The Rich style of a severity (the word itself carries the meaning)."""
    return _SEVERITY_STYLES.get(str(severity).lower(), "")


def status_text(status: str) -> Text:
    """``PASS``, ``WARN``, ``FAIL`` or ``SKIP`` as a styled word, never a symbol."""
    word = str(status).lower()
    return Text(word.upper(), style=_STATUS_STYLES.get(word, ""))
