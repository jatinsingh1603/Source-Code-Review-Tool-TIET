"""Finding status lifecycle: allowed transitions, actor rules and an append-only history.

Owning epic: E02.

This is an integrity control against malicious repository content that prompt-injects the
model to suppress findings (ARCHITECTURE section 6.4). There is no LLM actor, only humans may
mark a finding as a false positive, and history is append-only, so a model has no path to
``false_positive``, ``suppressed`` or ``fixed``. Error messages name statuses and rules, never
the ``reason`` text, which may quote code.
"""

from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import ClassVar

from pydantic import Field

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import ActorKind, FindingStatus
from codekavach.core.models.errors import InvalidStatusTransition
from codekavach.core.models.timeutil import UtcDatetime

_S = FindingStatus

_FROM_ACTIVE = frozenset({_S.FALSE_POSITIVE, _S.ACCEPTED_RISK, _S.SUPPRESSED, _S.FIXED})

ALLOWED_TRANSITIONS: Mapping[FindingStatus, frozenset[FindingStatus]] = MappingProxyType(
    {
        _S.OPEN: frozenset(
            {_S.CONFIRMED, _S.FALSE_POSITIVE, _S.ACCEPTED_RISK, _S.SUPPRESSED, _S.FIXED}
        ),
        _S.CONFIRMED: frozenset(
            {_S.OPEN, _S.FALSE_POSITIVE, _S.ACCEPTED_RISK, _S.SUPPRESSED, _S.FIXED}
        ),
        _S.FALSE_POSITIVE: frozenset({_S.OPEN}),
        _S.ACCEPTED_RISK: frozenset({_S.OPEN, _S.CONFIRMED, _S.FIXED}),
        _S.SUPPRESSED: frozenset({_S.OPEN}),
        _S.FIXED: frozenset({_S.OPEN}),
    }
)

PERMITTED_ACTORS: Mapping[FindingStatus, frozenset[ActorKind]] = MappingProxyType(
    {
        _S.CONFIRMED: frozenset({ActorKind.HUMAN}),
        _S.FALSE_POSITIVE: frozenset({ActorKind.HUMAN}),
        _S.ACCEPTED_RISK: frozenset({ActorKind.HUMAN}),
        _S.SUPPRESSED: frozenset({ActorKind.POLICY, ActorKind.HUMAN}),
        _S.FIXED: frozenset({ActorKind.SYSTEM}),
        _S.OPEN: frozenset({ActorKind.SYSTEM, ActorKind.HUMAN}),
    }
)

REASON_REQUIRED = frozenset({_S.FALSE_POSITIVE, _S.ACCEPTED_RISK, _S.SUPPRESSED})


class StatusChange(KavachModel):
    """One entry of a finding's status history."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    from_status: FindingStatus
    to_status: FindingStatus
    at: UtcDatetime
    actor_kind: ActorKind
    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(default="", max_length=1000)
    expires_at: UtcDatetime | None = None


def validate_transition(change: StatusChange) -> None:
    """Check a change against the transition table and the actor rules.

    Raises:
        InvalidStatusTransition: the change is not allowed; the message never quotes ``reason``.
    """
    source, target = change.from_status, change.to_status
    if target not in ALLOWED_TRANSITIONS[source]:
        raise InvalidStatusTransition(
            f"cannot move {source.value} -> {target.value}: not an allowed transition"
        )
    permitted = PERMITTED_ACTORS[target]
    if change.actor_kind not in permitted:
        kinds = " or ".join(sorted(kind.value for kind in permitted))
        raise InvalidStatusTransition(f"{target.value} requires actor_kind {kinds}")
    if target in REASON_REQUIRED and not change.reason.strip():
        raise InvalidStatusTransition(f"{target.value} requires a non-empty reason")
    if change.expires_at is not None:
        if target is not _S.ACCEPTED_RISK:
            raise InvalidStatusTransition("expires_at is allowed only for accepted_risk")
        if change.expires_at <= change.at:
            raise InvalidStatusTransition("accepted_risk expires_at must be later than at")


def apply_transition(
    current: FindingStatus, history: tuple[StatusChange, ...], change: StatusChange
) -> tuple[FindingStatus, tuple[StatusChange, ...]]:
    """Validate ``change`` against the current state and return the new status and history."""
    if change.from_status is not current:
        raise InvalidStatusTransition(
            f"change starts at {change.from_status.value} but the finding is {current.value}"
        )
    validate_transition(change)
    if history and change.at < history[-1].at:
        raise InvalidStatusTransition("a status change must not be older than the last one")
    return change.to_status, (*history, change)


def effective_status(
    status: FindingStatus, history: tuple[StatusChange, ...], now: datetime
) -> FindingStatus:
    """Return the status in force at ``now``: an expired acceptance counts as ``open``."""
    if status is _S.ACCEPTED_RISK and history:
        expires_at = history[-1].expires_at
        if expires_at is not None and expires_at <= now:
            return _S.OPEN
    return status
