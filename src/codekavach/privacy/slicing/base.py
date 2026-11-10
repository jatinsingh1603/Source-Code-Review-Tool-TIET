"""The slice strategy protocol, its registry and the refusal record.

Owning epic: E11. MVP; extended by E11-03 (path-based strategies) and E11-04 (the context loop).

A strategy turns a candidate and a ``ParseIndex`` into a ``CodeSlice``. When it must not, because
the candidate sits in a file the policy never sends, in vendored or generated code, or because no
slice can be made to parse or to fit, it raises ``SlicingError`` with a reason from a closed
vocabulary and the candidate is reported from its deterministic evidence alone (invariant I4).

``CodeSlice`` requires at least one segment, so a refusal cannot be stored as an empty slice.
It is stored as a ``SliceRefusal`` under the candidate's id instead. What ``slice_for`` (the
payload source the CLI defines in E05-16 and E13-03 implements) finds for a candidate is therefore
one of three things, and ``privacy inspect`` shows each differently:

* a ``CodeSlice``: the candidate was sliced;
* a ``SliceRefusal``: slicing was attempted and refused, for the stated reason (for example
  "excluded by policy"); there is nothing to show but the reason;
* nothing: the candidate never reached slicing.

``outcome_for`` is the one call that produces the first two.
"""

from collections.abc import Iterable
from typing import ClassVar, Final, Literal, Protocol

from codekavach.core.models import (
    Candidate,
    CodeSlice,
    DataClassification,
    KavachModel,
    SliceStrategy,
)
from codekavach.core.models.ids import CandidateIdField
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex

REASONS: Final = (
    "policy_never_send",
    "vendored",
    "generated",
    "minified",
    "unknown_file",
    "unsupported_language",
    "no_enclosing_code",
    "not_coherent",
    "over_budget",
)


class SlicingError(Exception):
    """A slice could not be made; ``reason`` is one of ``REASONS``.

    The message is the reason and nothing else: no path, symbol or code, because exception text is
    logged and the code is the thing being protected.
    """

    def __init__(self, reason: str) -> None:
        if reason not in REASONS:
            reason = "not_coherent"
        self.reason = reason
        super().__init__(reason)


class NotApplicableError(SlicingError):
    """The strategy has no input for this candidate; a selector may try a weaker one.

    As a ``SlicingError`` its ``reason`` is ``no_enclosing_code`` (nothing was cut). ``fallback``
    says what was missing, from the closed vocabulary of ``CodeSlice.fallback_reason``.
    """

    def __init__(self, fallback: str) -> None:
        super().__init__("no_enclosing_code")
        self.fallback = fallback


class Slicer(Protocol):
    """One way of cutting a slice (the ``SliceStrategy`` of the M1 interface contract).

    Named ``Slicer`` here because ``SliceStrategy`` is already the enum of strategy names.
    """

    name: SliceStrategy

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The slice for ``candidate``; raises ``SlicingError`` instead of returning a bad one."""
        ...


class SliceRefusal(KavachModel):
    """Slicing was attempted for ``candidate_id`` and refused, for ``reason``.

    It holds an id and a closed-vocabulary reason, so it is metadata and may be stored,
    reported and shown by ``privacy inspect``.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    candidate_id: CandidateIdField
    reason: Literal[
        "policy_never_send",
        "vendored",
        "generated",
        "minified",
        "unknown_file",
        "unsupported_language",
        "no_enclosing_code",
        "not_coherent",
        "over_budget",
    ]


class StrategyRegistry:
    """Strategies keyed by their ``SliceStrategy`` name."""

    def __init__(self) -> None:
        self._by_name: dict[SliceStrategy, Slicer] = {}

    def register(self, strategy: Slicer) -> None:
        """Add ``strategy``; a second strategy under one name is an error."""
        if strategy.name in self._by_name:
            raise ValueError(f"a strategy named {strategy.name.value} is already registered")
        self._by_name[strategy.name] = strategy

    def get(self, name: SliceStrategy) -> Slicer:
        """The strategy registered as ``name``; ``KeyError`` when there is none."""
        return self._by_name[name]

    def names(self) -> tuple[SliceStrategy, ...]:
        """Registered names in enum order."""
        return tuple(name for name in SliceStrategy if name in self._by_name)


def outcome_for(
    strategy: Slicer, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
) -> CodeSlice | SliceRefusal:
    """Run ``strategy``; a refusal becomes a ``SliceRefusal`` rather than an exception."""
    try:
        return strategy.build(candidate, parsed, budget=budget)
    except SlicingError as refused:
        return SliceRefusal(candidate_id=candidate.id, reason=refused.reason)  # type: ignore[arg-type]


def lookup_outcome(
    candidate_id: str,
    slices: Iterable[CodeSlice],
    refusals: Iterable[SliceRefusal],
) -> CodeSlice | SliceRefusal | None:
    """What ``PayloadSource.slice_for`` finds: a slice, a refusal, or ``None`` (never sliced).

    One outcome is stored per candidate id; a slice wins over a refusal if both were somehow
    recorded, because the slice is the later and fuller fact.
    """
    for found in slices:
        if found.candidate_id == candidate_id:
            return found
    for refusal in refusals:
        if refusal.candidate_id == candidate_id:
            return refusal
    return None
