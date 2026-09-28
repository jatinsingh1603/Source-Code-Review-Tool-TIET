"""Per-stage timeouts: resolving the effective limit and running a stage under a deadline (E04-18).

Owning epic: E04.

Python cannot kill a thread. A stage therefore runs in a dedicated daemon thread while the
orchestrator waits with a deadline. On expiry the orchestrator cancels the stage's token, revokes
its store view (E04-17) and moves on; the thread is abandoned. Daemon threads let the process exit,
and a dedicated thread (not a pool worker) means an abandoned stage never occupies a slot that
concurrent waves (E04-19) need.

Cooperative cancellation contract for stage authors:

- call ``ctx.check_cancelled()`` at least once per unit of work (file, candidate);
- pass ``ctx.remaining_seconds()`` to every subprocess or network timeout;
- terminate child processes when ``ScanCancelledError`` is raised.

A stage that ignores the contract keeps a thread busy after its timeout, but it cannot change
results: its view is revoked and its token is cancelled.
"""

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from codekavach.config.models.scan import ScanSettings
from codekavach.core.pipeline.stage import StageInfo

DeadlineOutcome = Literal["completed", "timed_out", "exception"]


@dataclass(frozen=True, slots=True)
class DeadlineResult:
    """How a function run under a deadline ended."""

    outcome: DeadlineOutcome
    thread: threading.Thread
    error: BaseException | None = None


def resolve_timeout(
    info: StageInfo, settings: ScanSettings, remaining_scan_seconds: float | None
) -> float:
    """The stage's effective timeout in seconds; the first match wins, then the scan caps it.

    1. ``scan.stage_timeouts[<stage name>]``;
    2. ``scan.stage_timeouts[<category value>]`` (the group, for example ``analyse``);
    3. the stage's declared ``timeout_seconds``;
    4. ``scan.stage_timeout_seconds``.
    """
    timeouts = settings.stage_timeouts
    group = info.category.value if info.category is not None else None
    if info.name in timeouts:
        seconds = float(timeouts[info.name])
    elif group is not None and group in timeouts:
        seconds = float(timeouts[group])
    elif info.timeout_seconds is not None:
        seconds = float(info.timeout_seconds)
    else:
        seconds = float(settings.stage_timeout_seconds)
    if remaining_scan_seconds is not None:
        seconds = min(seconds, max(0.0, remaining_scan_seconds))
    return seconds


def run_with_deadline(
    fn: Callable[[], None], timeout: float, *, thread_name: str
) -> DeadlineResult:
    """Run ``fn`` in a new daemon thread and wait at most ``timeout`` seconds.

    An exception raised by ``fn`` before the deadline is returned (the same object) so that the
    caller re-raises it in its own thread; one raised after the deadline is ignored.
    """
    done = threading.Event()
    box: list[BaseException] = []

    def target() -> None:
        try:
            fn()
        except BaseException as error:  # noqa: BLE001 - handed to the orchestrator thread
            box.append(error)
        finally:
            done.set()

    thread = threading.Thread(target=target, name=thread_name, daemon=True)
    thread.start()
    if not done.wait(timeout):
        return DeadlineResult("timed_out", thread)
    if box:
        return DeadlineResult("exception", thread, box[0])
    return DeadlineResult("completed", thread)
