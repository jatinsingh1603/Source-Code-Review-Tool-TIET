"""Global options, accepted before or after the subcommand.

Owning epic: E05.

Typer cannot share options across commands without repeating them in every signature, so the
global options are options with ``expose_value=False`` attached to the root group and to every
leaf command by ``attach_global_options``. Their callbacks store only explicitly given values
(command line or the option's environment variable) in the root context's ``meta``; the position
nearer the subcommand is parsed later and wins, and a default after the subcommand never erases a
value given before it. ``--set`` values from both positions accumulate.

Typer 0.27 vendors a reduced Click (``typer._click``) without ``Option``, ``Choice`` or ``Path``;
the options are ``typer.core.TyperOption`` objects and ``--config`` and ``--privacy-level`` are
validated in their callbacks.
"""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from typer import _click as click  # Typer >= 0.27 ships its own copy of Click
from typer._click.core import ParameterSource
from typer._click.exceptions import BadParameter
from typer.core import TyperOption

GLOBALS_KEY = "codekavach.globals"
PANEL = "Global options"
PRIVACY_LEVELS = ("L0", "L1", "L2", "L3", "L4")
LOG_LEVELS = ("debug", "info", "warning", "error", "critical")
LOG_FORMATS = ("console", "json")
_EXPLICIT = frozenset({ParameterSource.COMMANDLINE, ParameterSource.ENVIRONMENT})

Converter = Callable[[Any], Any]


def globals_of(ctx: click.Context) -> dict[str, Any]:
    """The explicitly given global option values of this invocation."""
    meta: dict[str, Any] = ctx.find_root().meta.setdefault(GLOBALS_KEY, {})
    return meta


def _privacy_level(value: Any) -> Any:
    if value is None:
        return None
    text = str(value).upper()
    if text not in PRIVACY_LEVELS:
        raise BadParameter(f"must be one of {', '.join(PRIVACY_LEVELS)}")
    return text


def _one_of(choices: tuple[str, ...]) -> Converter:
    def convert(value: Any) -> Any:
        if value is None:
            return None
        text = str(value).strip().lower()
        if text not in choices:
            raise BadParameter(f"must be one of {', '.join(choices)}")
        return text

    return convert


def _log_file(value: Any) -> Any:
    if value is None:
        return None
    path = Path(str(value))
    if path.is_dir() or not path.parent.is_dir():
        raise BadParameter("must be a file path in an existing directory")
    return path


def _config_file(value: Any) -> Any:
    if value is None:
        return None
    path = Path(str(value))
    if not path.is_file():
        raise BadParameter("file does not exist or is not a regular file")
    return path


def _storing(convert: Converter | None) -> Callable[[click.Context, click.Parameter, Any], Any]:
    def store(ctx: click.Context, param: click.Parameter, value: Any) -> Any:
        name = param.name
        if name is None or ctx.get_parameter_source(name) not in _EXPLICIT:
            return value
        if convert is not None:
            value = convert(value)
        values = globals_of(ctx)
        if name == "set_values":
            values[name] = [*values.get(name, []), *value]
        else:
            values[name] = value
        return value

    return store


def _option(*decls: str, convert: Converter | None = None, **attrs: Any) -> TyperOption:
    return TyperOption(
        param_decls=list(decls),
        expose_value=False,
        callback=_storing(convert),
        rich_help_panel=PANEL,
        **attrs,
    )


def make_global_options() -> tuple[TyperOption, ...]:
    """Fresh option objects (a parameter belongs to one command)."""
    return (
        _option(
            "--config",
            convert=_config_file,
            metavar="PATH",
            help="Configuration file to use instead of the discovered project file.",
        ),
        _option("--profile", help="Profile to apply (for example demo or ci)."),
        _option(
            "--privacy-level",
            convert=_privacy_level,
            metavar="[L0|L1|L2|L3|L4]",
            envvar="CODEKAVACH_PRIVACY_LEVEL",
            help="Privacy level for this run; cannot go below the configured floor.",
        ),
        _option("--provider", envvar="CODEKAVACH_PROVIDER", help="LLM provider id to use."),
        _option("--model", envvar="CODEKAVACH_MODEL", help="Model of the selected provider."),
        _option(
            "--offline",
            is_flag=True,
            envvar="CODEKAVACH_OFFLINE",
            help="Open no connection outside this machine (no remote provider or integration).",
        ),
        _option(
            "--json",
            "json_mode",
            is_flag=True,
            envvar="CODEKAVACH_JSON",
            help="Write machine-readable JSON to stdout.",
        ),
        _option(
            "--quiet",
            "-q",
            is_flag=True,
            envvar="CODEKAVACH_QUIET",
            help="Print only results and errors.",
        ),
        _option(
            "--verbose",
            "-v",
            count=True,
            envvar="CODEKAVACH_VERBOSE",
            help="More diagnostics on stderr; repeat for more.",
        ),
        _option("--debug", is_flag=True, help="Print tracebacks and debug logs on stderr."),
        _option(
            "--log-level",
            convert=_one_of(LOG_LEVELS),
            metavar="[debug|info|warning|error]",
            envvar="CODEKAVACH_LOG_LEVEL",
            help="Lowest level of log events on stderr; wins over --verbose and --quiet.",
        ),
        _option(
            "--log-format",
            convert=_one_of(LOG_FORMATS),
            metavar="[console|json]",
            envvar="CODEKAVACH_LOG_FORMAT",
            help="Format of log events on stderr.",
        ),
        _option(
            "--log-file",
            convert=_log_file,
            metavar="PATH",
            help="Also write redacted debug logs to this file (created with mode 0600).",
        ),
        _option("--no-user-config", is_flag=True, help="Ignore the user configuration file."),
        _option(
            "--trust-project-config",
            is_flag=True,
            help="Trust restricted keys in the project configuration for this run.",
        ),
        _option(
            "--set",
            "set_values",
            multiple=True,
            metavar="KEY=VALUE",
            help="Override one setting; may be repeated.",
        ),
    )


def _declared(command: click.Command) -> set[str]:
    names: set[str] = set()
    for param in command.params:
        if param.name:
            names.add(param.name)
        names.update(getattr(param, "opts", []))
        names.update(getattr(param, "secondary_opts", []))
    return names


def _walk(command: click.Command) -> Iterator[click.Command]:
    yield command
    children: dict[str, click.Command] = getattr(command, "commands", {}) or {}
    for name in sorted(children):
        yield from _walk(children[name])


def attach_global_options(command: click.Command) -> None:
    """Add the global options to the root group and every command below it.

    An option that a command already declares (by name or flag) is skipped: the command's own
    declaration wins.
    """
    for target in _walk(command):
        declared = _declared(target)
        for option in make_global_options():
            spellings = {option.name or "", *option.opts, *option.secondary_opts}
            if spellings & declared:
                continue
            target.params.append(option)
