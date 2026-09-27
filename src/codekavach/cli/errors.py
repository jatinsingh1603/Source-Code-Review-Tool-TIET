"""CLI error types that carry exit codes, and their conservative rendering.

Owning epic: E05.

Exception messages can contain a line of client code, a path or a credential, and CI logs of hosted
runners are outside the client's trust boundary. Only ``CliError`` messages, written by CodeKavach
itself, are printed; any other exception is reported by its type name, and the traceback is an
explicit local opt-in on stderr.
"""

import importlib
import re
from typing import ClassVar

from codekavach.cli.console import get_err_console
from codekavach.cli.exit_codes import ExitCode

_CODE = re.compile(r"^[a-z][a-z0-9_]{1,47}$")


class CliError(Exception):
    """An expected error with an exit code, a machine code, a message and an optional hint."""

    exit_code: ClassVar[ExitCode] = ExitCode.INTERNAL
    default_code: ClassVar[str] = "error"

    def __init__(
        self, message: str = "", *, code: str | None = None, hint: str | None = None
    ) -> None:
        self.code = code or self.default_code
        if not _CODE.match(self.code):
            raise ValueError("an error code matches ^[a-z][a-z0-9_]{1,47}$")
        self.message = message
        self.hint = hint
        super().__init__(message)


class UsageError(CliError):
    """The command cannot be carried out as invoked."""

    exit_code = ExitCode.USAGE
    default_code = "usage"


class BackendUnavailableError(UsageError):
    """A feature's back end is not part of this build."""

    default_code = "backend_unavailable"


class PrivacyBlockError(CliError):
    """A privacy control refused the operation."""

    exit_code = ExitCode.PRIVACY_BLOCK
    default_code = "privacy_block"


class ThresholdExceeded(CliError):  # noqa: N818 - a signal, not a failure; name fixed by E05-04
    """The command has rendered its result and found problems at or above its threshold."""

    exit_code = ExitCode.FINDINGS
    default_code = "threshold_exceeded"


class InternalError(CliError):
    """A defect or unexpected environment failure, described by CodeKavach itself."""

    exit_code = ExitCode.INTERNAL
    default_code = "internal"


def error_line(code: str, message: str) -> str:
    """``error[<code>]: <message>``."""
    return f"error[{code}]: {message}"


def _write_json(code: str, message: str, hint: str | None) -> bool:
    """Write the JSON error envelope when the output layer (E05-07) exists."""
    try:
        output = importlib.import_module("codekavach.cli.output")  # optional until E05-07
    except ImportError:
        return False
    writer = getattr(output, "write_error_envelope", None)
    if writer is None:
        return False
    writer(code=code, message=message, hint=hint)
    return True


def render_error(exc: BaseException, *, verbosity: int = 0, json_mode: bool = False) -> None:
    """Print one diagnostic for ``exc`` (stderr, or the JSON envelope in JSON mode)."""
    del verbosity  # tracebacks are decided by the caller
    if isinstance(exc, CliError):
        code, message, hint = exc.code, exc.message, exc.hint
    else:
        code = "internal"
        message = f"unexpected {type(exc).__name__}; run again with --debug for a traceback"
        hint = None
    if json_mode and _write_json(code, message, hint):
        return
    console = get_err_console()
    console.print(error_line(code, message), markup=False)
    if hint:
        console.print(f"hint: {hint}", markup=False)
