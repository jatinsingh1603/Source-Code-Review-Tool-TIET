"""The metered needs-context loop: turning a model's request for one more definition into a slice.

Owning epic: E11. Interface contract M1: ``ContextResolver.resolve(request, *, vault, budget)``.

A task may answer ``needs_context`` and name a pseudonym. The resolver maps it back to a real
symbol through the restore engine's ``resolve_symbol`` (see ``SymbolSource``), so the vault is
touched in one place (invariant I3), locates the definition, and cuts a slice with the configured
strategy. It returns a ``CodeSlice``, never a payload: redaction, pseudonymisation, validation and
the egress guard all run again on it, and the guard writes the expansion's own ledger entry.

**The loop is metered.** Demand-driven agents (``docs/research/INSIGHTS.md`` section 1.2) follow
the call chain by asking for more code, with good results; the same mechanism without a meter is
a slow path to disclosing the whole repository. Here every expansion counts against a round cap
per candidate (``privacy.slice.max_needs_context_rounds``), against the aggregation budget of the
scan, and is recorded in ``ScanDisclosure``. The loop exists to recover the accuracy floor of
section 1.3; its cost is measured, not assumed.

**Refusals are legible locally and invisible to the provider.** ``resolve`` returns ``None`` in
every refusal case and leaves the reason in ``last_refusal``. The reason is never part of any
payload, because "that file is never-send" is itself information about the client's policy: the
stage tells the model only that no further context is available.

**Pseudonym stability.** The model asked about ``fn_12``; the expansion must call the same
function ``fn_12``. With the per-scan generator this holds on its own. In ``per_request`` link
mode every request gets fresh names, a second prompt would contradict the first, and the
resolver refuses with ``link_mode_per_request`` rather than produce an incoherent conversation.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, CodeSlice, ContextKind, ContextRequest, Location
from codekavach.parsing.functions import FunctionRange
from codekavach.privacy.slicing.base import Slicer, SlicingError
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.metrics import ScanDisclosure
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy

_LOG = get_logger("codekavach.privacy.slicing")
DEFAULT_MAX_SYMBOLS: Final = 3
_SUPPORTED_KINDS: Final = frozenset({ContextKind.CALLEE_BODY, ContextKind.OTHER})


class SymbolSource(Protocol):
    """What the resolver needs from the vault: one pseudonym in, one real symbol out.

    The restore engine bound to the scan's vault (``RestoreEngine(vault, scan_id=...)``, E10-02)
    is the implementation, so the vault is still touched in one place. The protocol keeps this
    package from importing the vault or the restore engine, which the I3 import contract
    (``vault-record-locality``) forbids for every package except those two.
    """

    def resolve_symbol(self, pseudonym: str) -> str | None:
        """The real name behind ``pseudonym``, or ``None`` when it is not a known token."""
        ...


class ContextRefusal(StrEnum):
    """Why a request for more context was refused. Local only: never sent to a provider."""

    UNKNOWN_PSEUDONYM = "unknown_pseudonym"
    DEFINITION_NOT_FOUND = "definition_not_found"
    DEFINITION_EXCLUDED = "definition_excluded"
    ROUND_CAP = "round_cap"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TOO_BROAD = "too_broad"
    LINK_MODE = "link_mode_per_request"
    KIND_NOT_SUPPORTED = "kind_not_supported"
    NOT_SLICEABLE = "not_sliceable"


class AggregationBudget:
    """A per-scan, per-provider ceiling on the share of the repository disclosed.

    The share is the union of disclosed lines over the repository's lines (``ScanDisclosure``),
    in percent. ``consume`` reads the disclosure and says whether there is still room;
    ``admits`` says whether a figure would still be within the ceiling. The enforcement inside
    the egress guard (E12-02) consumes this same object.
    """

    def __init__(self, ceiling_pct: float) -> None:
        if not 0.0 <= ceiling_pct <= 100.0:
            raise ValueError("an aggregation ceiling is between 0 and 100 percent")
        self._ceiling = ceiling_pct
        self._used = 0.0

    @property
    def ceiling_pct(self) -> float:
        """The configured ceiling."""
        return self._ceiling

    def consume(self, disclosure: ScanDisclosure) -> bool:
        """Note the current union share; ``True`` while it is still below the ceiling."""
        self._used = disclosure.repo_pct
        return self._used < self._ceiling

    def admits(self, pct: float) -> bool:
        """Whether a union share of ``pct`` percent is within the ceiling."""
        return pct <= self._ceiling

    def remaining_pct(self) -> float:
        """Percentage points left under the ceiling at the last ``consume``."""
        return max(0.0, self._ceiling - self._used)


@dataclass(frozen=True, slots=True, repr=False)
class ContextOutcome:
    """The result of one request: a slice, or the reason there is none."""

    slice: CodeSlice | None
    refusal: ContextRefusal | None

    def __repr__(self) -> str:
        return f"ContextOutcome({self.refusal.value if self.refusal else 'slice'})"


class ContextResolver:
    """Resolves the context requests of one candidate in one scan.

    One resolver serves one candidate, so the round cap is naturally per candidate; the rounds
    used are recorded on ``disclosure`` under the candidate's id for the report.
    """

    def __init__(
        self,
        *,
        candidate: Candidate,
        index: ParseIndex,
        disclosure: ScanDisclosure,
        settings: Settings,
        strategy: Slicer | None = None,
        max_symbols: int = DEFAULT_MAX_SYMBOLS,
    ) -> None:
        self._candidate = candidate
        self._index = index
        self._disclosure = disclosure
        self._settings = settings
        self._strategy: Slicer = strategy or EnclosingFunctionStrategy()
        self._max_symbols = max_symbols
        self.last_refusal: ContextRefusal | None = None

    def __repr__(self) -> str:
        return "ContextResolver(<candidate>)"

    @property
    def rounds_used(self) -> int:
        """Context rounds delivered for this candidate so far."""
        return self._disclosure.rounds_used(self._candidate.id)

    def resolve(
        self, request: ContextRequest, *, vault: SymbolSource, budget: AggregationBudget
    ) -> CodeSlice | None:
        """The slice for ``request``, or ``None`` (the reason is in ``last_refusal``)."""
        return self.attempt(request, vault=vault, budget=budget).slice

    def attempt(
        self, request: ContextRequest, *, vault: SymbolSource, budget: AggregationBudget
    ) -> ContextOutcome:
        """Like ``resolve`` but returns the outcome with its reason."""
        outcome = self._attempt(request, vault, budget)
        self.last_refusal = outcome.refusal
        _LOG.info(
            "context_request",
            outcome=outcome.refusal.value if outcome.refusal else "expanded",
            kind=request.kind.value,
            round=self.rounds_used,
        )
        return outcome

    # ------------------------------------------------------------------ internals

    def _refuse(self, reason: ContextRefusal) -> ContextOutcome:
        return ContextOutcome(None, reason)

    def _gate(self, request: ContextRequest, budget: AggregationBudget) -> ContextRefusal | None:
        """The refusals that need no lookup, in the order they are checked."""
        settings = self._settings
        if settings.privacy.pseudonym.link_mode == "per_request":
            return ContextRefusal.LINK_MODE
        if self.rounds_used >= settings.privacy.slice.max_needs_context_rounds:
            return ContextRefusal.ROUND_CAP
        if not budget.consume(self._disclosure):
            return ContextRefusal.BUDGET_EXHAUSTED
        if request.kind not in _SUPPORTED_KINDS:
            return ContextRefusal.KIND_NOT_SUPPORTED
        return None

    def _attempt(
        self, request: ContextRequest, vault: SymbolSource, budget: AggregationBudget
    ) -> ContextOutcome:
        refused = self._gate(request, budget)
        if refused is not None:
            return self._refuse(refused)
        pseudonyms = [part for part in request.symbol.replace(",", " ").split() if part]
        if not pseudonyms:
            return self._refuse(ContextRefusal.UNKNOWN_PSEUDONYM)
        if len(pseudonyms) > self._max_symbols:
            return self._refuse(ContextRefusal.TOO_BROAD)
        names = [vault.resolve_symbol(pseudonym) for pseudonym in pseudonyms]
        if any(name is None for name in names):
            return self._refuse(ContextRefusal.UNKNOWN_PSEUDONYM)
        found = self._locate([name for name in names if name is not None])
        if isinstance(found, ContextRefusal):
            return self._refuse(found)
        return self._expand(found, budget)

    def _locate(self, names: list[str]) -> list[tuple[str, FunctionRange]] | ContextRefusal:
        primary = self._candidate.locations[0].path
        located: list[tuple[str, FunctionRange]] = []
        for name in dict.fromkeys(names):
            where = self._index.definition_of(name, primary)
            if where is None:
                everywhere = self._index.functions_named(name)
                if len(everywhere) != 1:
                    return ContextRefusal.DEFINITION_NOT_FOUND
                where = everywhere[0]
            if self._index.is_excluded(where[0])[0]:
                return ContextRefusal.DEFINITION_EXCLUDED
            located.append(where)
        return located

    def _expand(
        self, located: list[tuple[str, FunctionRange]], budget: AggregationBudget
    ) -> ContextOutcome:
        locations = tuple(
            Location(path=path, start_line=found.full.start_line, end_line=found.full.end_line)
            for path, found in located
        )
        wanted = self._candidate.evolve(locations=locations, taint_path=None)
        try:
            slice_ = self._strategy.build(
                wanted, self._index, budget=SliceBudget(self._settings.privacy.slice.max_tokens)
            )
        except SlicingError as refused:
            if refused.reason in {"policy_never_send", "vendored", "generated", "minified"}:
                return self._refuse(ContextRefusal.DEFINITION_EXCLUDED)
            return self._refuse(ContextRefusal.NOT_SLICEABLE)
        if not budget.admits(self._disclosure.would_reach_pct(slice_)):
            return self._refuse(ContextRefusal.BUDGET_EXHAUSTED)
        self._disclosure.record(slice_, self._index, expansion=True)
        return ContextOutcome(slice_, None)
