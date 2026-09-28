"""Per-item failure reporting: how I4 becomes observable for single candidates (E04-20).

Owning epic: E04.

A privacy stage that cannot prepare one candidate (redaction, pseudonymisation, validation or the
egress guard fails) aborts that candidate's request and carries on; the candidate is still reported
from deterministic evidence. ``RunContext.fail_item(item_id, error_code)`` records such an event in
one uniform, code-only form: it is published as ``ItemFailed``, returned in
``PipelineResult.item_failures`` and stored under ``scan.item_failures``.

``item_id`` is an entity id (``cand_...``, ``pay_...``), never a path, a symbol name or a message,
and ``error_code`` is a machine code. Both are validated, and a rejected value is not echoed, so
exception text, paths and identifiers from client code cannot reach the record.

``guard_item`` wraps the work on one item: an ordinary exception fails that item and is dropped on
purpose; cancellation, budget overruns and a revoked store are control flow and propagate.
"""

import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Final

from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline.budget import BudgetExceededError
from codekavach.core.pipeline.cancel import ScanCancelledError
from codekavach.core.store.scoped import StageRevokedError

if TYPE_CHECKING:
    from codekavach.core.pipeline.context import RunContext

ITEM_ID: Final = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
ERROR_CODE: Final = re.compile(r"^[a-z][a-z0-9_]{1,63}$")

# Well-known codes; stages may add their own that match ERROR_CODE.
PRIVACY_REDACTION_FAILED: Final = "privacy_redaction_failed"
PRIVACY_PSEUDONYMISE_FAILED: Final = "privacy_pseudonymise_failed"
PRIVACY_VALIDATION_FAILED: Final = "privacy_validation_failed"
EGRESS_BLOCKED: Final = "egress_blocked"
POLICY_NEVER_SEND: Final = "policy_never_send"
BUDGET_EXHAUSTED: Final = "budget_exhausted"
LLM_OUTPUT_INVALID: Final = "llm_output_invalid"
RESTORE_FAILED: Final = "restore_failed"
ITEM_EXCEPTION: Final = "item_exception"

_CONTROL_FLOW = (ScanCancelledError, BudgetExceededError, StageRevokedError)


@dataclass(frozen=True, slots=True)
class ItemFailure:
    """One failed item of one stage: ids and codes only."""

    stage: str
    item_id: str
    error_code: str
    at: datetime

    def to_json(self) -> dict[str, str]:
        """The form stored under ``scan.item_failures`` (without the timestamp)."""
        return {"stage": self.stage, "item_id": self.item_id, "error_code": self.error_code}


def check_item(item_id: object, error_code: object) -> None:
    """Validate an item id and an error code; the message names the argument, not the value.

    Raises:
        ValueError: either argument does not match its pattern.
    """
    if not isinstance(item_id, str) or not ITEM_ID.match(item_id):
        raise ValueError("item_id must match ^[A-Za-z0-9_.:-]{1,64}$")
    if not isinstance(error_code, str) or not ERROR_CODE.match(error_code):
        raise ValueError("error_code must match ^[a-z][a-z0-9_]{1,63}$")


class ItemFailureLog:
    """A thread-safe record of the item failures of one run."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: list[ItemFailure] = []

    def add(self, stage: str, item_id: str, error_code: str) -> ItemFailure:
        """Validate and record one failure.

        Raises:
            ValueError: ``item_id`` or ``error_code`` is malformed.
        """
        check_item(item_id, error_code)
        failure = ItemFailure(stage, item_id, error_code, utc_now())
        with self._lock:
            self._failures.append(failure)
        return failure

    def __len__(self) -> int:
        with self._lock:
            return len(self._failures)

    def snapshot(self) -> tuple[ItemFailure, ...]:
        """Every failure so far, sorted by stage, item id and error code."""
        with self._lock:
            failures = list(self._failures)
        return tuple(sorted(failures, key=lambda f: (f.stage, f.item_id, f.error_code)))

    def to_json(self) -> list[dict[str, str]]:
        """The sorted failures as the JSON list stored under ``scan.item_failures``."""
        return [failure.to_json() for failure in self.snapshot()]


@contextmanager
def guard_item(ctx: "RunContext", item_id: str, error_code: str = ITEM_EXCEPTION) -> Iterator[None]:
    """Fail ``item_id`` with ``error_code`` if the block raises an ordinary exception.

    ``ScanCancelledError``, ``BudgetExceededError`` and ``StageRevokedError`` propagate unrecorded.
    """
    check_item(item_id, error_code)
    try:
        yield
    except _CONTROL_FLOW:
        raise
    except Exception:  # noqa: BLE001 - the exception is dropped on purpose (no free text)
        ctx.fail_item(item_id, error_code)
