"""Cooperative cancellation of a scan.

Owning epic: E04.

Stages call ``ctx.check_cancelled()`` at natural boundaries (per file, per candidate); nothing is
interrupted forcibly. A child token (one per stage run) is cancelled with its parent, while
cancelling a child leaves the parent running.
"""

import threading

from codekavach.core.pipeline.errors import PipelineError


class ScanCancelledError(PipelineError):
    """The scan was cancelled; ``reason`` is a code such as ``cancelled`` or ``deadline``."""

    def __init__(self, reason: str = "cancelled") -> None:
        self.reason = reason
        super().__init__(reason)


class CancellationToken:
    """A thread-safe, one-way cancellation flag with parent-to-child propagation."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._reason: str | None = None
        self._children: list[CancellationToken] = []

    def cancel(self, reason: str = "cancelled") -> None:
        """Set the flag (the first reason wins) and cancel every child."""
        with self._lock:
            if self._reason is None:
                self._reason = reason
            children = tuple(self._children)
            self._event.set()
        for child in children:
            child.cancel(reason)

    @property
    def is_cancelled(self) -> bool:
        """True once cancelled."""
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        """Why the token was cancelled, or ``None``."""
        return self._reason

    def raise_if_cancelled(self) -> None:
        """Raise ``ScanCancelledError`` when cancelled."""
        if self._event.is_set():
            raise ScanCancelledError(self._reason or "cancelled")

    def wait(self, timeout: float) -> bool:
        """Block up to ``timeout`` seconds; True when cancelled."""
        return self._event.wait(timeout)

    def child(self) -> "CancellationToken":
        """A token cancelled together with this one."""
        token = CancellationToken()
        with self._lock:
            self._children.append(token)
            cancelled, reason = self._event.is_set(), self._reason
        if cancelled:
            token.cancel(reason or "cancelled")
        return token
