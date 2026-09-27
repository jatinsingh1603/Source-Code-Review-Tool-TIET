"""The two shared Rich consoles: results on stdout, diagnostics on stderr.

Owning epic: E05.

Rich honours ``NO_COLOR`` and disables colour when a stream is not a terminal; ``force_terminal``
is never passed. ``CODEKAVACH_NO_COLOR=1`` additionally switches colour off for CI systems that
emulate a terminal.
"""

import os
from functools import lru_cache

from rich.console import Console

NO_COLOR_ENV = "CODEKAVACH_NO_COLOR"


def _console(stderr: bool) -> Console:
    # No ``file`` argument: Rich then writes to the current sys.stdout or sys.stderr, which
    # keeps output capture in tests working.
    if os.environ.get(NO_COLOR_ENV) == "1":
        return Console(
            stderr=stderr, soft_wrap=False, highlight=False, emoji=False, color_system=None
        )
    return Console(stderr=stderr, soft_wrap=False, highlight=False, emoji=False)


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
