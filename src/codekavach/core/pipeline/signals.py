"""The bridge from operating-system signals to the cancellation token (E04-29).

Owning epic: E04.

The first SIGINT or SIGTERM cancels the scan cooperatively: no new stage starts, the running stage
stops at its next check, its outputs are discarded, and the manifest and the checkpoint are
written, so the scan is resumable and an interrupted privacy stage leaves nothing a resumed run
could send without preparing it again (I4). A second signal exits the process at once with status
130: stage threads that do not cooperate, and their subprocesses, could otherwise keep the
interpreter alive. Every E04 write is an atomic replace, so the worst outcome is a stray temporary
file inside the state directory and a checkpoint left at ``running``, which can be resumed.

The handlers replace Python's default SIGINT handler for the duration of the scan, so
``KeyboardInterrupt`` is not raised while they are installed. The messages are fixed strings.
"""

import contextlib
import os
import signal
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from types import FrameType
from typing import Any, Final

from codekavach.core.log import get_logger
from codekavach.core.pipeline.cancel import CancellationToken

SIGNAL_REASON: Final = "signal"
HARD_EXIT_STATUS: Final = 130
FIRST_MESSAGE: Final = (
    "Cancelling... finishing the current stage. Press Ctrl-C again to exit immediately.\n"
)
SECOND_MESSAGE: Final = "Exiting immediately; the scan can be resumed.\n"
DEFAULT_SIGNALS: Final[tuple[signal.Signals, ...]] = (signal.SIGINT, signal.SIGTERM)

_log = get_logger("codekavach.pipeline.signals")


def _write_stderr(message: str) -> None:
    """Write with ``os.write``: no buffered stream is touched from inside a signal handler."""
    with contextlib.suppress(OSError, ValueError, AttributeError):
        os.write(sys.stderr.fileno(), message.encode("ascii"))


@contextlib.contextmanager
def cancel_on_signals(
    token: CancellationToken,
    *,
    signals: Sequence[signal.Signals] = DEFAULT_SIGNALS,
    hard_exit: Callable[[int], Any] = os._exit,
) -> Iterator[None]:
    """Cancel ``token`` on the first signal and call ``hard_exit(130)`` on the second.

    The previous handlers are restored on exit. Outside the main thread nothing is installed,
    because Python delivers signals to the main thread only. A signal that cannot be registered
    on this platform (``SIGTERM`` in some Windows configurations) is skipped.
    """
    if threading.current_thread() is not threading.main_thread():
        _log.debug("signal_handlers_not_installed", reason="not_main_thread")
        yield
        return
    received = [0]

    def handler(_signum: int, _frame: FrameType | None) -> None:
        received[0] += 1
        if received[0] == 1:
            token.cancel(SIGNAL_REASON)
            _write_stderr(FIRST_MESSAGE)
            return
        _write_stderr(SECOND_MESSAGE)
        hard_exit(HARD_EXIT_STATUS)

    previous: dict[signal.Signals, Any] = {}
    try:
        for signum in signals:
            try:
                previous[signum] = signal.signal(signum, handler)
            except (ValueError, OSError):
                _log.debug("signal_not_registered", signal=int(signum))
        yield
    finally:
        for signum, earlier in previous.items():
            signal.signal(signum, earlier if earlier is not None else signal.SIG_DFL)
