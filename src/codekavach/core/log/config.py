"""Structured logging configuration (ADR-0005).

Owning epic: E01.

Every event, whether it starts as a structlog event or as a standard-library record from a
third-party package, is rendered by one ``ProcessorFormatter`` on the single root handler, so a
processor in the redaction slot sees each event once, after exceptions have become data and
before anything is written. Output goes to stderr only; stdout is reserved for command results.
Tracebacks never show local variables.
"""

import logging
import os
import sys
from typing import Literal, TextIO, cast

import structlog
from structlog.typing import Processor

from codekavach.core.log.redaction import RedactionProcessor

Format = Literal["console", "json"]

LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")
FORMATS: tuple[Format, ...] = ("console", "json")
THIRD_PARTY_LOGGERS = (
    "httpx",
    "httpcore",
    "urllib3",
    "litellm",
    "openai",
    "anthropic",
    "botocore",
    "asyncio",
)
LEVEL_VARIABLE = "CODEKAVACH_LOG_LEVEL"
FORMAT_VARIABLE = "CODEKAVACH_LOG_FORMAT"
THIRD_PARTY_VARIABLE = "CODEKAVACH_LOG_THIRD_PARTY"

_handler: logging.Handler | None = None


def _resolve_level(level: str | int | None) -> int:
    value: str | int = level if level is not None else os.environ.get(LEVEL_VARIABLE, "INFO")
    if isinstance(value, int):
        if value not in (logging.getLevelName(name) for name in LEVELS):
            raise ValueError(f"log level must be one of {', '.join(LEVELS)}")
        return value
    name = value.strip().upper()
    if name not in LEVELS:
        raise ValueError(f"log level must be one of {', '.join(LEVELS)}")
    return cast(int, logging.getLevelName(name))


def _resolve_format(fmt: str | None, stream: TextIO) -> Format:
    value = fmt if fmt is not None else os.environ.get(FORMAT_VARIABLE)
    if value is None:
        isatty = getattr(stream, "isatty", None)
        return "console" if callable(isatty) and isatty() else "json"
    if value not in FORMATS:
        raise ValueError(f"log format must be one of {', '.join(FORMATS)}")
    return value


def _exception_renderer(fmt: Format) -> Processor:
    if fmt == "json":
        return structlog.processors.ExceptionRenderer(
            structlog.tracebacks.ExceptionDictTransformer(show_locals=False)
        )
    return structlog.processors.format_exc_info


def _renderer(fmt: Format, stream: TextIO) -> Processor:
    if fmt == "json":
        return structlog.processors.JSONRenderer(sort_keys=True)
    isatty = getattr(stream, "isatty", None)
    colors = callable(isatty) and bool(isatty()) and "NO_COLOR" not in os.environ
    return structlog.dev.ConsoleRenderer(
        colors=colors, exception_formatter=structlog.dev.plain_traceback
    )


def _shared_processors(fmt: Format) -> list[Processor]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        _exception_renderer(fmt),
    ]


def _formatter_processors(fmt: Format, stream: TextIO) -> list[Processor]:
    return [
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        RedactionProcessor(),  # the redaction slot (E01-21): after exceptions, before rendering
        _renderer(fmt, stream),
    ]


def configure_logging(
    *,
    level: str | int | None = None,
    fmt: Format | None = None,
    stream: TextIO | None = None,
    force: bool = False,
) -> None:
    """Configure structlog and the standard library to write structured events to stderr.

    Resolution order for level and format: argument, then ``CODEKAVACH_LOG_LEVEL`` /
    ``CODEKAVACH_LOG_FORMAT``, then the default (``INFO``; ``console`` on a TTY, else ``json``).
    A second call does nothing unless ``force`` is true.

    Raises:
        ValueError: the level or format is not one of the accepted values.
    """
    global _handler  # noqa: PLW0603 - one process-wide handler by design
    if _handler is not None and not force:
        return
    target = stream if stream is not None else sys.stderr
    resolved_level = _resolve_level(level)
    resolved_fmt = _resolve_format(fmt, target)
    shared = _shared_processors(resolved_fmt)

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=_formatter_processors(resolved_fmt, target),
    )
    handler = logging.StreamHandler(target)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    if _handler is not None:
        root.removeHandler(_handler)
    root.addHandler(handler)
    root.setLevel(resolved_level)
    _handler = handler

    third_party_debug = os.environ.get(THIRD_PARTY_VARIABLE) == "1"
    for name in THIRD_PARTY_LOGGERS:
        logging.getLogger(name).setLevel(logging.NOTSET if third_party_debug else logging.WARNING)
    if third_party_debug:
        get_logger(__name__).warning("third_party_debug_logging_enabled")


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger; the only supported way to obtain one in CodeKavach."""
    return structlog.stdlib.get_logger(name)


def bind_scan_context(**values: str | int) -> None:
    """Attach key-value context to every subsequent event in the current context."""
    structlog.contextvars.bind_contextvars(**values)


def clear_scan_context() -> None:
    """Remove all context bound with ``bind_scan_context``."""
    structlog.contextvars.clear_contextvars()
