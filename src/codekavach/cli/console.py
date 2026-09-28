"""The two shared Rich consoles: results on stdout, diagnostics on stderr.

Owning epic: E05.

Rich honours ``NO_COLOR`` and disables colour when a stream is not a terminal; ``force_terminal``
is never passed. ``CODEKAVACH_NO_COLOR=1`` additionally switches colour off for CI systems that
emulate a terminal.
"""

import os
import sys
from functools import lru_cache

from rich.console import Console

NO_COLOR_ENV = "CODEKAVACH_NO_COLOR"


def _console(stderr: bool) -> Console:
    # No ``file`` argument: Rich then writes to the current sys.stdout or sys.stderr, which
    # keeps output capture in tests working. Legacy Windows console handling (one column less,
    # substitute box characters) applies to real legacy terminals only, never to pipes and files,
    # so that captured output is the same on every platform.
    stream = sys.stderr if stderr else sys.stdout
    interactive = bool(getattr(stream, "isatty", lambda: False)())
    no_color = os.environ.get(NO_COLOR_ENV) == "1"
    return Console(
        stderr=stderr,
        soft_wrap=False,
        highlight=False,
        emoji=False,
        color_system=None if no_color else "auto",
        legacy_windows=None if interactive else False,
    )


@lru_cache(maxsize=1)
def get_console() -> Console:
    """The console for results (stdout)."""
    return _console(stderr=False)


@lru_cache(maxsize=1)
def get_err_console() -> Console:
    """The console for diagnostics, progress and prompts (stderr)."""
    return _console(stderr=True)


def reset_consoles() -> None:
    """Forget the cached consoles (tests change streams and environment variables)."""
    get_console.cache_clear()
    get_err_console.cache_clear()
