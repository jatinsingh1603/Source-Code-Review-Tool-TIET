from datetime import UTC, datetime, timedelta
from itertools import product
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import DataClassification, FindingStatus, InvalidStatusTransition
from codekavach.core.models.enums import ActorKind
from codekavach.core.models.lifecycle import (
    ALLOWED_TRANSITIONS,
    StatusChange,
    apply_transition,
    effective_status,
    validate_transition,
)

S = FindingStatus
T0 = datetime(2026, 10, 1, tzinfo=UTC)
REASON_TEXT = "cur.execute(sql) is parameterised upstream"

TABLE = {
    S.OPEN: {S.CONFIRMED, S.FALSE_POSITIVE, S.ACCEPTED_RISK, S.SUPPRESSED, S.FIXED},
    S.CONFIRMED: {S.OPEN, S.FALSE_POSITIVE, S.ACCEPTED_RISK, S.SUPPRESSED, S.FIXED},
    S.FALSE_POSITIVE: {S.OPEN},
    S.ACCEPTED_RISK: {S.OPEN, S.CONFIRMED, S.FIXED},
    S.SUPPRESSED: {S.OPEN},
    S.FIXED: {S.OPEN},
}
LEGAL_ACTOR = {
    S.CONFIRMED: ActorKind.HUMAN,
    S.FALSE_POSITIVE: ActorKind.HUMAN,
    S.ACCEPTED_RISK: ActorKind.HUMAN,
    S.SUPPRESSED: ActorKind.POLICY,
    S.FIXED: ActorKind.SYSTEM,
    S.OPEN: ActorKind.SYSTEM,
}
PERMITTED = {
    S.CONFIRMED: {ActorKind.HUMAN},
    S.FALSE_POSITIVE: {ActorKind.HUMAN},
    S.ACCEPTED_RISK: {ActorKind.HUMAN},
    S.SUPPRESSED: {ActorKind.POLICY, ActorKind.HUMAN},
    S.FIXED: {ActorKind.SYSTEM},
    S.OPEN: {ActorKind.SYSTEM, ActorKind.HUMAN},
}


def change(
    source: FindingStatus,
    target: FindingStatus,
    actor_kind: ActorKind | None = None,
    **overrides: Any,
) -> StatusChange:
    fields: dict[str, Any] = {
        "from_status": source,
        "to_status": target,
        "at": T0,
        "actor_kind": actor_kind or LEGAL_ACTOR[target],
        "actor": "alice",
        "reason": REASON_TEXT,
    }
    fields.update(overrides)
    return StatusChange.model_validate(fields)


def test_table_matches_specification() -> None:
    assert {k: set(v) for k, v in ALLOWED_TRANSITIONS.items()} == TABLE


@pytest.mark.parametrize(("source", "target"), list(product(S, S)))
def test_transition_matrix(source: FindingStatus, target: FindingStatus) -> None:
    candidate = change(source, target)
    if target in TABLE[source]:
        validate_transition(candidate)
    else:
        with pytest.raises(InvalidStatusTransition, match="not an allowed transition"):
            validate_transition(candidate)


@pytest.mark.parametrize(("target", "kind"), list(product(list(PERMITTED), list(ActorKind))))
def test_actor_matrix(target: FindingStatus, kind: ActorKind) -> None:
    source = S.OPEN if target is not S.OPEN else S.CONFIRMED
    candidate = change(source, target, kind)
    if kind in PERMITTED[target]:
        validate_transition(candidate)
    else:
        with pytest.raises(InvalidStatusTransition, match="requires actor_kind"):
            validate_transition(candidate)


def test_llm_actor_is_rejected_by_validation() -> None:
    with pytest.raises(ValidationError):
        StatusChange.model_validate(
            {
                "from_status": "open",
                "to_status": "false_positive",
                "at": T0,
                "actor_kind": "llm",
                "actor": "model",
                "reason": "the model says so",
            }
        )


@pytest.mark.parametrize("target", [S.FALSE_POSITIVE, S.ACCEPTED_RISK, S.SUPPRESSED])
def test_reason_required(target: FindingStatus) -> None:
    with pytest.raises(InvalidStatusTransition, match="reason"):
        validate_transition(change(S.OPEN, target, reason="   "))


def test_expiry_rules() -> None:
    validate_transition(change(S.OPEN, S.ACCEPTED_RISK, expires_at=T0 + timedelta(days=30)))
    with pytest.raises(InvalidStatusTransition, match="later than"):
        validate_transition(change(S.OPEN, S.ACCEPTED_RISK, expires_at=T0))
    with pytest.raises(InvalidStatusTransition, match="only for accepted_risk"):
        validate_transition(change(S.OPEN, S.CONFIRMED, expires_at=T0 + timedelta(days=1)))


def test_field_bounds() -> None:
    with pytest.raises(ValidationError):
        change(S.OPEN, S.CONFIRMED, actor="")
    with pytest.raises(ValidationError):
        change(S.OPEN, S.CONFIRMED, actor="a" * 129)
    with pytest.raises(ValidationError):
        change(S.OPEN, S.CONFIRMED, reason="r" * 1001)
    assert StatusChange.DATA_CLASSIFICATION is DataClassification.RAW


def test_apply_transition() -> None:
    first = change(S.OPEN, S.CONFIRMED)
    status, history = apply_transition(S.OPEN, (), first)
    assert status is S.CONFIRMED
    assert history == (first,)
    later = change(S.CONFIRMED, S.FIXED, at=T0 + timedelta(hours=1))
    status, history = apply_transition(status, history, later)
    assert status is S.FIXED
    assert history == (first, later)


def test_apply_rejects_wrong_current_status() -> None:
    with pytest.raises(InvalidStatusTransition, match="finding is confirmed"):
        apply_transition(S.CONFIRMED, (), change(S.OPEN, S.FIXED))


def test_apply_rejects_older_change() -> None:
    _, history = apply_transition(S.OPEN, (), change(S.OPEN, S.CONFIRMED))
    with pytest.raises(InvalidStatusTransition, match="older"):
        apply_transition(S.CONFIRMED, history, change(S.CONFIRMED, S.FIXED, at=T0 - timedelta(1)))


def test_effective_status_expiry() -> None:
    accept = change(S.OPEN, S.ACCEPTED_RISK, expires_at=T0 + timedelta(days=7))
    history = (accept,)
    assert effective_status(S.ACCEPTED_RISK, history, T0 + timedelta(days=1)) is S.ACCEPTED_RISK
    assert effective_status(S.ACCEPTED_RISK, history, T0 + timedelta(days=8)) is S.OPEN
    no_expiry = (change(S.OPEN, S.ACCEPTED_RISK),)
    assert effective_status(S.ACCEPTED_RISK, no_expiry, T0 + timedelta(days=999)) is S.ACCEPTED_RISK
    assert effective_status(S.OPEN, history, T0 + timedelta(days=8)) is S.OPEN


def test_error_messages_never_contain_reason() -> None:
    attempts = [
        change(S.FALSE_POSITIVE, S.FIXED),
        change(S.OPEN, S.FALSE_POSITIVE, ActorKind.SYSTEM),
        change(S.OPEN, S.ACCEPTED_RISK, expires_at=T0),
    ]
    for attempt in attempts:
        with pytest.raises(InvalidStatusTransition) as info:
            validate_transition(attempt)
        assert REASON_TEXT not in str(info.value)
    with pytest.raises(InvalidStatusTransition) as info:
        validate_transition(change(S.FALSE_POSITIVE, S.FIXED))
    assert str(info.value) == "cannot move false_positive -> fixed: not an allowed transition"


# properties


@given(st.lists(st.integers(0, 10**6), min_size=1, max_size=25))
def test_legal_sequences_are_accepted(choices: list[int]) -> None:
    status: FindingStatus = S.OPEN
    history: tuple[StatusChange, ...] = ()
    at = T0
    for count, pick in enumerate(choices, start=1):
        targets = sorted(TABLE[status])
        target = targets[pick % len(targets)]
        at += timedelta(minutes=1)
        status, history = apply_transition(status, history, change(status, target, at=at))
        assert len(history) == count


@given(st.lists(st.integers(0, 10**6), min_size=1, max_size=10), st.integers(0, 10**6))
def test_one_illegal_step_is_rejected_there(choices: list[int], bad_pick: int) -> None:
    status: FindingStatus = S.OPEN
    history: tuple[StatusChange, ...] = ()
    at = T0
    for pick in choices:
        targets = sorted(TABLE[status])
        at += timedelta(minutes=1)
        status, history = apply_transition(
            status, history, change(status, targets[pick % len(targets)], at=at)
        )
    illegal = sorted(set(S) - TABLE[status])
    target = illegal[bad_pick % len(illegal)]
    with pytest.raises(InvalidStatusTransition):
        apply_transition(status, history, change(status, target, at=at + timedelta(minutes=1)))
    assert len(history) == len(choices)
