"""Optional extras: probing for them and warning once when one is missing (E08-04).

Owning epic: E08.

Everything in E08-04 sits behind an extra and behind an ``available()`` probe, and the native
detectors never call into it. A missing extra is not an error: the capability is simply absent,
and the process says so **once**, naming what to install, so a log does not repeat the same line
for every file. :func:`warn_unavailable` keeps that memory; tests clear it with
:func:`reset_warnings`.
"""

import importlib.util
from typing import Final

from codekavach.core.log import get_logger

_log = get_logger("codekavach.privacy.detect")

_warned: set[str] = set()

NER_EXTRA: Final = "codekavach[pii]"


def module_present(name: str) -> bool:
    """Whether the top-level module ``name`` can be found, without importing it."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def warn_unavailable(feature: str, extra: str, *, reason: str) -> bool:
    """Log one warning per ``feature`` per process; return whether this call logged it."""
    if feature in _warned:
        return False
    _warned.add(feature)
    _log.warning("optional_extra_unavailable", feature=feature, extra=extra, reason=reason)
    return True


def reset_warnings() -> None:
    """Forget which warnings were given (for tests)."""
    _warned.clear()
