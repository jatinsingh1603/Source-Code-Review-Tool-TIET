"""Maps the CLI verbosity and format flags onto ``codekavach.core.log`` (E05-06).

Owning epic: E05.

There is one logging stack: ``codekavach.core.log.configure_logging`` (E01-20) owns the stderr
handler, the rendering, the third-party loggers and the optional file destination, and the
fail-closed redaction processor (E01-21) sits in front of every destination. This module only
chooses the level and the format from the command line and passes them on, so stdout stays free
for results and ``--log-file`` cannot bypass redaction.

Level: ``--log-level`` wins; else ``--quiet`` gives ERROR, ``-v`` INFO, ``-vv`` or ``--debug``
DEBUG, and ``-vvv`` also shows third-party loggers; else ``logging.level`` when a configuration
source sets it; else WARNING. Format: ``--log-format`` wins; else ``--json`` gives ``json``; else
``logging.format`` when a configuration source sets it; else ``console``.
"""

import logging
from typing import TYPE_CHECKING, Final, Literal

from codekavach.core.log import configure_logging

if TYPE_CHECKING:
    from codekavach.cli.context import CliContext
    from codekavach.config import LoadedConfig

Format = Literal["console", "json"]

LOG_LEVELS: Final = ("debug", "info", "warning", "error", "critical")
LOG_FORMATS: Final[tuple[Format, ...]] = ("console", "json")
THIRD_PARTY_VERBOSITY: Final = 3
_DEBUG_VERBOSITY: Final = 2
_DEFAULT_LAYER: Final = "default"


def log_level_and_format(*, verbosity: int, quiet: bool, json_mode: bool) -> tuple[int, Format]:
    """The level and format that the verbosity flags ask for."""
    if quiet:
        level = logging.ERROR
    elif verbosity >= _DEBUG_VERBOSITY:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    return level, "json" if json_mode else "console"


def _named_level(name: str) -> int:
    return int(logging.getLevelName(name.upper()))


def _configured(loaded: "LoadedConfig | None", key: str) -> bool:
    """True when a configuration source, not the built-in default, sets ``key``."""
    if loaded is None:
        return False
    origin = loaded.origins.get(key)
    return origin is not None and origin.layer != _DEFAULT_LAYER


def configure_cli_logging(ctx: "CliContext", loaded: "LoadedConfig | None" = None) -> None:
    """Configure logging for this invocation; safe to call again (``force=True``).

    ``loaded`` supplies the ``[logging]`` settings once the configuration has been read; they
    apply only where no flag chose the level or the format.
    """
    level, fmt = log_level_and_format(
        verbosity=_DEBUG_VERBOSITY if ctx.debug else ctx.verbosity,
        quiet=ctx.quiet,
        json_mode=ctx.json_mode,
    )
    flags_set_level = ctx.quiet or ctx.debug or ctx.verbosity > 0
    if ctx.log_level is not None:
        level = _named_level(ctx.log_level)
    elif not flags_set_level and _configured(loaded, "logging.level") and loaded is not None:
        level = _named_level(loaded.settings.logging.level)
    if ctx.log_format is not None:
        fmt = ctx.log_format
    elif not ctx.json_mode and _configured(loaded, "logging.format") and loaded is not None:
        fmt = loaded.settings.logging.format
    configure_logging(
        level=level,
        fmt=fmt,
        force=True,
        log_file=ctx.log_file,
        third_party=True if ctx.verbosity >= THIRD_PARTY_VERBOSITY else None,
    )
