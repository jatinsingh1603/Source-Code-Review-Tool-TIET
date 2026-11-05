"""Overlap resolution: from many detectors' spans to one non-overlapping, ascending list.

Owning epic: E08.

Detectors disagree: an AWS key inside a connection string inside a comment, an email that is
also a domain term, an entropy hit over a whole JWT that a specific rule also matched.
:func:`resolve_overlaps` applies these rules, in this order, to the **set** of spans, so the
result does not depend on the order they arrive in:

1. **Containment, same kind.** A span fully inside another of the same kind is dropped and the
   container kept. Exception: when the contained span has a more specific subtype *and* higher
   confidence, it is kept and the container is cut around it, keeping each remaining piece that
   is at least ``MIN_REMAINDER`` bytes; if no piece is that long the container is dropped. A
   ``SECRET`` inside a ``SECRET`` has no exception: the container always stays, because cutting a
   connection string around the credential inside it would split one URL into two placeholders.
   Spans with the same range are decided by confidence, then specificity, then detector id and
   subtype.
2. **Kinds.** ``SECRET`` beats ``PII`` beats ``TERM``: a lower-ranking span loses the bytes a
   higher-ranking one covers, and keeps the rest. A secret that contains an email keeps the whole
   secret span.
3. **Partial overlap.** Higher confidence wins; on equal confidence the earlier start, then the
   longer span, then the lexicographically smaller detector id (and subtype) wins. The loser keeps
   the bytes the winner does not cover.
4. The result is checked to be ascending and non-overlapping; anything else is a
   :class:`~codekavach.privacy.errors.RedactionError`.

Pieces left by rules 2 and 3 are kept whatever their length: a recall-first choice, since
dropping a short remainder of a secret would leave part of it in the text. Only rule 1's cut uses
``MIN_REMAINDER``, which is the threshold the issue fixes there.
"""

from bisect import bisect_right
from collections.abc import Iterable, Sequence
from itertools import pairwise
from typing import Final

from codekavach.core.models import PlaceholderKind
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.vocabulary import is_specific
from codekavach.privacy.errors import RedactionError

MIN_REMAINDER: Final = 4
_KIND_RANK: Final = {PlaceholderKind.SECRET: 0, PlaceholderKind.PII: 1, PlaceholderKind.TERM: 2}

type Interval = tuple[int, int]


def _order_key(span: TypedSpan) -> tuple[int, int, int, int, str, str]:
    """A total order over spans, used wherever a deterministic choice is needed."""
    return (
        span.start_byte,
        -span.end_byte,
        _KIND_RANK[span.kind],
        -span.confidence.rank,
        span.detector,
        span.subtype,
    )


def _beats(first: TypedSpan, second: TypedSpan) -> bool:
    """For two spans of the same range and kind: does ``first`` win the tie?"""
    return (
        -first.confidence.rank,
        not is_specific(first.subtype),
        first.detector,
        first.subtype,
    ) < (
        -second.confidence.rank,
        not is_specific(second.subtype),
        second.detector,
        second.subtype,
    )


def _contains(outer: TypedSpan, inner: TypedSpan) -> bool:
    return outer.start_byte <= inner.start_byte and inner.end_byte <= outer.end_byte


def _is_exception(inner: TypedSpan, outer: TypedSpan) -> bool:
    """Containment exception: ``inner`` is more specific *and* more confident than ``outer``."""
    return (
        inner.kind is not PlaceholderKind.SECRET
        and is_specific(inner.subtype)
        and not is_specific(outer.subtype)
        and inner.confidence > outer.confidence
    )


def remainders(span: TypedSpan, cuts: Iterable[Interval], *, minimum: int) -> list[TypedSpan]:
    """``span`` minus the ``cuts``: the remaining runs of at least ``minimum`` bytes."""
    pieces: list[TypedSpan] = []
    position = span.start_byte
    for start, end in sorted(cuts):
        if position >= span.end_byte:
            break
        if start > position:
            pieces.append(_clip(span, position, min(start, span.end_byte)))
        position = max(position, end)
    if position < span.end_byte:
        pieces.append(_clip(span, position, span.end_byte))
    return [piece for piece in pieces if piece.length >= minimum]


def _clip(span: TypedSpan, start: int, end: int) -> TypedSpan:
    return TypedSpan(
        kind=span.kind,
        subtype=span.subtype,
        start_byte=start,
        end_byte=end,
        confidence=span.confidence,
        detector=span.detector,
    )


def _resolve_containment(spans: Sequence[TypedSpan]) -> list[TypedSpan]:
    """Rule 1, one kind at a time, with a sweep over spans sorted by start then length."""
    result: list[TypedSpan] = []
    for kind in PlaceholderKind:
        kept: list[TypedSpan] = []
        active: list[int] = []  # indices into ``kept`` of spans that can still contain a later one
        cuts: dict[int, list[Interval]] = {}
        for span in sorted((s for s in spans if s.kind is kind), key=_order_key):
            active = [i for i in active if kept[i].end_byte > span.start_byte]
            containers = [i for i in active if _contains(kept[i], span)]
            if not containers:
                kept.append(span)
                active.append(len(kept) - 1)
                continue
            twin = next((i for i in containers if _same_range(kept[i], span)), None)
            if twin is not None:
                if _beats(span, kept[twin]):
                    kept[twin] = span
            elif all(_is_exception(span, kept[i]) for i in containers):
                for i in containers:
                    cuts.setdefault(i, []).append((span.start_byte, span.end_byte))
                kept.append(span)
                active.append(len(kept) - 1)
        for index, span in enumerate(kept):
            if index in cuts:
                result.extend(remainders(span, cuts[index], minimum=MIN_REMAINDER))
            else:
                result.append(span)
    return result


def _same_range(first: TypedSpan, second: TypedSpan) -> bool:
    return (first.start_byte, first.end_byte) == (second.start_byte, second.end_byte)


def _greedy(spans: Sequence[TypedSpan]) -> list[TypedSpan]:
    """Rules 2 and 3: best span first; each later span keeps only the bytes still free.

    The accepted spans never overlap, so they are held sorted by start and the ones a new span
    overlaps are found by bisection, not by scanning all of them.
    """
    accepted: list[TypedSpan] = []
    starts: list[int] = []
    ranking = sorted(spans, key=lambda s: (_KIND_RANK[s.kind], -s.confidence.rank, *_order_key(s)))
    for span in ranking:
        first = max(bisect_right(starts, span.start_byte) - 1, 0)
        overlapping = [
            (a.start_byte, a.end_byte)
            for a in accepted[first:]
            if a.start_byte < span.end_byte and span.start_byte < a.end_byte
        ]
        pieces = remainders(span, overlapping, minimum=1) if overlapping else [span]
        for piece in pieces:
            index = bisect_right(starts, piece.start_byte)
            starts.insert(index, piece.start_byte)
            accepted.insert(index, piece)
    return accepted


def resolve_overlaps(spans: Sequence[TypedSpan]) -> tuple[TypedSpan, ...]:
    """Return a non-overlapping, ascending sequence from ``spans`` (see the module docstring).

    Raises:
        RedactionError: the result is not ascending and non-overlapping (a bug, caught here
            rather than redacted wrongly).
    """
    unique = sorted(set(spans), key=_order_key)
    resolved = tuple(sorted(_greedy(_resolve_containment(unique)), key=_order_key))
    for before, after in pairwise(resolved):
        if after.start_byte < before.end_byte:
            raise RedactionError("overlap resolution produced overlapping spans")
    return resolved
