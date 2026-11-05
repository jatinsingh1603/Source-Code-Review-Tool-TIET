"""``resolve_overlaps``: the scenario table, determinism and properties (E08-01)."""

import random
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.models import Confidence, PlaceholderKind
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.overlap import MIN_REMAINDER, resolve_overlaps

S, P, T = PlaceholderKind.SECRET, PlaceholderKind.PII, PlaceholderKind.TERM
HIGH, MEDIUM, LOW = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

Row = tuple[PlaceholderKind, str, int, int]


def span(  # noqa: PLR0917 - a compact builder used positionally by the scenario table
    kind: PlaceholderKind,
    subtype: str,
    start: int,
    end: int,
    confidence: Confidence = HIGH,
    detector: str = "test.a",
) -> TypedSpan:
    return TypedSpan(
        kind=kind,
        subtype=subtype,
        start_byte=start,
        end_byte=end,
        confidence=confidence,
        detector=detector,
    )


def rows(spans: tuple[TypedSpan, ...]) -> list[Row]:
    return [(s.kind, s.subtype, s.start_byte, s.end_byte) for s in spans]


# (name, input spans, expected (kind, subtype, start, end) rows)
SCENARIOS: list[tuple[str, list[TypedSpan], list[Row]]] = [
    ("empty", [], []),
    ("single span is unchanged", [span(S, "jwt", 3, 40)], [(S, "jwt", 3, 40)]),
    (
        "disjoint spans come out ascending",
        [span(P, "email", 30, 40), span(S, "jwt", 0, 10)],
        [(S, "jwt", 0, 10), (P, "email", 30, 40)],
    ),
    (
        "adjacent spans stay separate",
        [span(P, "email", 0, 5), span(P, "ipv4", 5, 10)],
        [(P, "email", 0, 5), (P, "ipv4", 5, 10)],
    ),
    (
        "identical spans collapse to one",
        [span(S, "jwt", 0, 10), span(S, "jwt", 0, 10)],
        [(S, "jwt", 0, 10)],
    ),
    (
        "same kind: the container is kept, the contained span dropped",
        [span(P, "email", 0, 20), span(P, "ipv4", 5, 10)],
        [(P, "email", 0, 20)],
    ),
    (
        "worked example: connection string keeps the AWS key and the term inside it",
        [
            span(S, "connection_string", 16, 71, MEDIUM),
            span(S, "aws_access_key", 33, 53, HIGH),
            span(T, "domain", 60, 68, MEDIUM),
        ],
        [(S, "connection_string", 16, 71)],
    ),
    (
        "a more specific, more confident span cuts a generic container",
        [span(P, "phone_intl", 0, 30, LOW), span(P, "indian_mobile", 10, 20, HIGH)],
        [(P, "phone_intl", 0, 10), (P, "indian_mobile", 10, 20), (P, "phone_intl", 20, 30)],
    ),
    (
        "the cut drops a remainder shorter than the minimum",
        [span(P, "phone_intl", 0, 12, LOW), span(P, "indian_mobile", 2, 10, HIGH)],
        [(P, "indian_mobile", 2, 10)],
    ),
    (
        "the cut keeps a remainder of exactly the minimum",
        [
            span(P, "phone_intl", 0, 8 + MIN_REMAINDER, LOW),
            span(P, "indian_mobile", 0, 8, HIGH),
        ],
        [(P, "indian_mobile", 0, 8), (P, "phone_intl", 8, 8 + MIN_REMAINDER)],
    ),
    (
        "no cut when the contained span is not more confident",
        [span(P, "phone_intl", 0, 30, HIGH), span(P, "indian_mobile", 10, 20, HIGH)],
        [(P, "phone_intl", 0, 30)],
    ),
    (
        "no cut when the contained span is not more specific",
        [span(P, "email", 0, 30, LOW), span(P, "ipv4", 10, 20, HIGH)],
        [(P, "email", 0, 30)],
    ),
    (
        "a secret inside a secret never cuts the container",
        [span(S, "generic_credential", 0, 40, LOW), span(S, "aws_access_key", 10, 30, HIGH)],
        [(S, "generic_credential", 0, 40)],
    ),
    (
        "a secret that contains an email keeps the whole secret",
        [span(S, "jwt", 0, 50, MEDIUM), span(P, "email", 10, 30, HIGH)],
        [(S, "jwt", 0, 50)],
    ),
    (
        "a term around a secret is cut around it",
        [span(T, "domain", 0, 20, HIGH), span(S, "aws_access_key", 5, 10, HIGH)],
        [(T, "domain", 0, 5), (S, "aws_access_key", 5, 10), (T, "domain", 10, 20)],
    ),
    (
        "cross-kind partial overlap: the secret wins, the email keeps the rest",
        [span(S, "jwt", 0, 10), span(P, "email", 5, 15)],
        [(S, "jwt", 0, 10), (P, "email", 10, 15)],
    ),
    (
        "equal kind and confidence: the earlier start wins a partial overlap",
        [span(P, "email", 0, 10), span(P, "ipv4", 5, 15)],
        [(P, "email", 0, 10), (P, "ipv4", 10, 15)],
    ),
    (
        "higher confidence beats an earlier start",
        [span(P, "email", 0, 10, LOW), span(P, "ipv4", 5, 15, HIGH)],
        [(P, "email", 0, 5), (P, "ipv4", 5, 15)],
    ),
    (
        "a chain of partial overlaps resolves left to right",
        [span(P, "email", 0, 10), span(P, "ipv4", 8, 20), span(P, "iban", 18, 30)],
        [(P, "email", 0, 10), (P, "ipv4", 10, 20), (P, "iban", 20, 30)],
    ),
    (
        "same range: the higher confidence wins",
        [span(P, "email", 0, 10, MEDIUM), span(P, "ipv4", 0, 10, HIGH)],
        [(P, "ipv4", 0, 10)],
    ),
    (
        "same range and confidence: the specific subtype wins",
        [span(P, "phone_intl", 0, 10), span(P, "indian_mobile", 0, 10)],
        [(P, "indian_mobile", 0, 10)],
    ),
    (
        "same range, confidence and specificity: the smaller detector id wins",
        [span(P, "email", 0, 10, detector="test.b"), span(P, "email", 0, 10, detector="test.a")],
        [(P, "email", 0, 10)],
    ),
    (
        "same start: the longer span contains the shorter one",
        [span(P, "email", 0, 6), span(P, "ipv4", 0, 10)],
        [(P, "ipv4", 0, 10)],
    ),
]


@pytest.mark.parametrize(
    ("spans", "expected"),
    [pytest.param(spans, expected, id=name) for name, spans, expected in SCENARIOS],
)
def test_overlap_scenarios(spans: list[TypedSpan], expected: list[Row]) -> None:
    assert rows(resolve_overlaps(spans)) == expected


def test_there_are_at_least_fifteen_scenarios() -> None:
    assert len(SCENARIOS) >= 15


@pytest.mark.parametrize(
    "spans", [pytest.param(spans, id=name) for name, spans, _ in SCENARIOS if len(spans) > 1]
)
def test_the_result_does_not_depend_on_the_input_order(spans: list[TypedSpan]) -> None:
    expected = resolve_overlaps(spans)
    generator = random.Random(8)  # noqa: S311 - a deterministic shuffle, not security
    for _ in range(25):
        shuffled = list(spans)
        generator.shuffle(shuffled)
        assert resolve_overlaps(shuffled) == expected
    assert resolve_overlaps(list(reversed(spans))) == expected


@pytest.mark.parametrize("spans", [pytest.param(s, id=n) for n, s, _ in SCENARIOS])
def test_the_output_is_ascending_and_non_overlapping(spans: list[TypedSpan]) -> None:
    result = resolve_overlaps(spans)
    for before, after in pairwise(result):
        assert before.end_byte <= after.start_byte


def test_resolving_twice_changes_nothing() -> None:
    for _, spans, _ in SCENARIOS:
        once = resolve_overlaps(spans)
        assert resolve_overlaps(once) == once


# --- properties ----------------------------------------------------------------------------

SUBTYPES = {
    S: ["aws_access_key", "generic_credential", "connection_string", "jwt"],
    P: ["email", "phone_intl", "indian_mobile", "ipv4"],
    T: ["domain"],
}


@st.composite
def random_spans(draw: st.DrawFn) -> list[TypedSpan]:
    count = draw(st.integers(min_value=0, max_value=12))
    spans: list[TypedSpan] = []
    for _ in range(count):
        kind = draw(st.sampled_from([S, P, T]))
        start = draw(st.integers(min_value=0, max_value=60))
        length = draw(st.integers(min_value=1, max_value=30))
        spans.append(
            span(
                kind,
                draw(st.sampled_from(SUBTYPES[kind])),
                start,
                start + length,
                draw(st.sampled_from([LOW, MEDIUM, HIGH])),
                draw(st.sampled_from(["test.a", "test.b", "test.c"])),
            )
        )
    return spans


def covered(spans: list[TypedSpan] | tuple[TypedSpan, ...]) -> set[int]:
    return {byte for s in spans for byte in range(s.start_byte, s.end_byte)}


@settings(max_examples=300, deadline=None)
@given(random_spans())
def test_property_ascending_non_overlapping_and_a_subset_of_the_input(
    spans: list[TypedSpan],
) -> None:
    result = resolve_overlaps(spans)
    for before, after in pairwise(result):
        assert before.end_byte <= after.start_byte
    assert covered(result) <= covered(spans)


@settings(max_examples=300, deadline=None)
@given(random_spans(), st.randoms(use_true_random=False))
def test_property_order_independent_and_idempotent(
    spans: list[TypedSpan], generator: random.Random
) -> None:
    result = resolve_overlaps(spans)
    shuffled = list(spans)
    generator.shuffle(shuffled)
    assert resolve_overlaps(shuffled) == result
    assert resolve_overlaps(result) == result


@settings(max_examples=200, deadline=None)
@given(random_spans())
def test_property_secret_coverage_is_never_reduced(spans: list[TypedSpan]) -> None:
    """Overlap resolution never uncovers a secret byte: a secret loses only to a secret."""
    secrets_in = covered([s for s in spans if s.kind is S])
    secrets_out = covered([s for s in resolve_overlaps(spans) if s.kind is S])
    assert secrets_out == secrets_in
