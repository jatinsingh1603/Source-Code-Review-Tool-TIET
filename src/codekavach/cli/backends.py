"""Lazy loading of optional back ends delivered by later epics.

Owning epic: E05.

A command whose back end is not part of this build fails with ``backend_unavailable`` (exit 2)
instead of an import error. Only a missing module *named in the call* or a missing attribute is
treated that way; an ``ImportError`` raised from inside an existing module is a defect and
propagates. Tests register fakes in ``_OVERRIDES`` (``tests.support.fakes.fake_backend``).
"""

import importlib
from typing import Any

from codekavach.cli.errors import BackendUnavailableError

_OVERRIDES: dict[tuple[str, str], Any] = {}


def _unavailable(feature: str, epic: str) -> BackendUnavailableError:
    return BackendUnavailableError(
        f"{feature} is not available in this build", hint=f"delivered by epic {epic}"
    )


def load_backend(dotted_module: str, attr: str, *, feature: str, epic: str) -> Any:
    """``dotted_module.attr``, a registered override, or ``BackendUnavailableError``."""
    override = _OVERRIDES.get((dotted_module, attr))
    if override is not None:
        return override
    try:
        module = importlib.import_module(dotted_module)
    except ModuleNotFoundError as error:
        missing = error.name or ""
        if dotted_module == missing or dotted_module.startswith(f"{missing}."):
            raise _unavailable(feature, epic) from None
        raise
    try:
        return getattr(module, attr)
    except AttributeError:
        raise _unavailable(feature, epic) from None
