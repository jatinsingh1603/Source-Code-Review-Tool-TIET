"""The taint lattice and the per-program-point state (E17-02).

Owning epic: E17. A value is ``Untainted``, ``Tainted(labels)`` or ``Unknown``. Labels are the
source kinds of the catalogue vocabulary (``http_param``, ``cli``, ...), because a value read from
a query string and one read from a database are different risks. ``Unknown`` is what an unmodelled
call returns when an argument was tainted: it is reported as tainted but the path is marked
uncertain, so the reasoning layer and the auditor can see the engine guessed. ``Unknown`` is never
turned into ``Untainted``, which is how a real flaw would disappear.

The state maps a place to the *facts* about it, one fact per origin (the source read that
introduced the taint). A fact carries the chain of steps that carried the taint from its source,
the contexts for which a sanitiser or a narrowing conversion has cleared it and the lines of the
branches that tested it. Keeping one fact per origin lets one sink report one path per source, and
keeping the shorter chain when two paths of one origin meet makes the iteration over a loop
converge and prefers short paths, which is also the smaller payload for the slicer.
"""

from dataclasses import dataclass, field, replace
from typing import Final

from codekavach.analysis.taint.ir import Place
from codekavach.core.models import Location, TaintRole

MAX_ORIGINS: Final = 8
MAX_GUARDS: Final = 16


@dataclass(frozen=True, slots=True)
class Untainted:
    """No tainted data."""


@dataclass(frozen=True, slots=True)
class Tainted:
    """Data derived from the sources with these kinds."""

    labels: frozenset[str]


@dataclass(frozen=True, slots=True)
class Unknown:
    """Possibly tainted: an unmodelled step touched tainted data. ``labels`` are those it saw."""

    labels: frozenset[str] = frozenset()


Lattice = Untainted | Tainted | Unknown


def join(left: Lattice, right: Lattice) -> Lattice:
    """The least upper bound: union of labels; ``Unknown`` absorbs ``Tainted`` and stays Unknown."""
    if isinstance(left, Untainted):
        return right
    if isinstance(right, Untainted):
        return left
    labels = left.labels | right.labels
    if isinstance(left, Unknown) or isinstance(right, Unknown):
        return Unknown(labels)
    return Tainted(labels)


@dataclass(frozen=True, slots=True)
class Step:
    """One step of a witness chain, before it becomes a ``TaintStep``.

    ``covers`` is set on sanitiser steps: the contexts the sanitiser is adequate for. ``note``
    names an operation and a symbol, never a literal value.
    """

    role: TaintRole
    location: Location
    note: str | None = None
    covers: frozenset[str] = frozenset()
    symbol: str | None = None  # the function the step is in, when it is not the analysed one


@dataclass(frozen=True, slots=True)
class Fact:
    """Taint of one origin at one place."""

    value: Tainted | Unknown
    chain: tuple[Step, ...]
    cleared: frozenset[str] = frozenset()
    guards: tuple[int, ...] = ()

    @property
    def labels(self) -> frozenset[str]:
        """The source kinds of the value."""
        return self.value.labels

    @property
    def uncertain(self) -> bool:
        """Whether an unmodelled step was crossed."""
        return isinstance(self.value, Unknown)


Facts = dict[str, Fact]


def _prefer(left: Fact, right: Fact) -> Fact:
    """Merge two facts of one origin: shorter chain, weaker clearing, union of guards."""
    first, second = (left, right) if len(left.chain) <= len(right.chain) else (right, left)
    guards = tuple(dict.fromkeys(first.guards + second.guards))[:MAX_GUARDS]
    return Fact(
        value=join(first.value, second.value),  # type: ignore[arg-type]
        chain=first.chain,
        cleared=first.cleared & second.cleared,
        guards=guards,
    )


def merge(*parts: Facts) -> Facts:
    """The facts of several values joined, by origin; at most ``MAX_ORIGINS`` shortest origins."""
    merged: Facts = {}
    for part in parts:
        for origin, fact in part.items():
            existing = merged.get(origin)
            merged[origin] = fact if existing is None else _prefer(existing, fact)
    if len(merged) > MAX_ORIGINS:
        keep = sorted(merged, key=lambda key: (len(merged[key].chain), key))[:MAX_ORIGINS]
        merged = {key: merged[key] for key in sorted(keep)}
    return merged


def with_step(facts: Facts, step: Step, *, uncertain: bool = False) -> Facts:
    """``facts`` with ``step`` appended to every chain.

    A propagator step at the location the chain already ends at is not repeated; a sanitiser step
    is always kept. ``uncertain`` turns every value into ``Unknown``.
    """
    out: Facts = {}
    for origin, fact in facts.items():
        chain = fact.chain
        repeated = (
            step.role is not TaintRole.SANITISER
            and bool(chain)
            and chain[-1].location == step.location
        )
        if not repeated:
            chain = (*chain, step)
        value = Unknown(fact.labels) if uncertain else fact.value
        cleared = fact.cleared | step.covers
        out[origin] = replace(fact, value=value, chain=chain, cleared=cleared)
    return out


def with_cleared(facts: Facts, contexts: frozenset[str]) -> Facts:
    """``facts`` additionally cleared for ``contexts`` (narrowing conversions)."""
    return {o: replace(f, cleared=f.cleared | contexts) for o, f in facts.items()}


def with_guard(facts: Facts, line: int) -> Facts:
    """``facts`` noting that a branch on line ``line`` tested them."""
    out: Facts = {}
    for origin, fact in facts.items():
        guards = fact.guards if line in fact.guards else (*fact.guards, line)
        out[origin] = replace(fact, guards=guards[:MAX_GUARDS])
    return out


@dataclass(slots=True)
class TaintState:
    """Facts per place at one program point. Entries are replaced, never edited in place."""

    entries: dict[str, tuple[Place, Facts]] = field(default_factory=dict)

    def copy(self) -> "TaintState":
        """A state sharing its (immutable by convention) entries."""
        return TaintState(dict(self.entries))

    def read(self, place: Place) -> Facts:
        """The facts of every stored place that can denote the same storage as ``place``."""
        found = [facts for stored, facts in self.entries.values() if stored.related(place)]
        return merge(*found) if found else {}

    def write(self, place: Place, facts: Facts) -> None:
        """Store ``facts`` at ``place``: a strong write replaces it and the paths below it."""
        key = place.text
        if place.strong():
            for name in [
                name
                for name, (stored, _) in self.entries.items()
                if stored.base == place.base and stored.steps[: len(place.steps)] == place.steps
            ]:
                del self.entries[name]
            if facts:
                self.entries[key] = (place, facts)
            return
        if not facts:
            return
        existing = self.entries.get(key)
        self.entries[key] = (place, merge(existing[1], facts) if existing else facts)

    def guard(self, origins: set[str], line: int) -> None:
        """Note on every fact of these origins that the branch on ``line`` tested them."""
        for name, (stored, facts) in list(self.entries.items()):
            if origins.isdisjoint(facts):
                continue
            tested = with_guard({o: f for o, f in facts.items() if o in origins}, line)
            self.entries[name] = (stored, {o: tested.get(o, f) for o, f in facts.items()})

    def clear_origins(self, origins: frozenset[str], contexts: frozenset[str]) -> None:
        """Mark every fact of these origins as cleared for ``contexts`` (a validated value)."""
        for name, (stored, facts) in list(self.entries.items()):
            if origins.isdisjoint(facts):
                continue
            self.entries[name] = (
                stored,
                {
                    o: replace(f, cleared=f.cleared | contexts) if o in origins else f
                    for o, f in facts.items()
                },
            )

    def join(self, other: "TaintState") -> "TaintState":
        """The state holding the facts of both."""
        joined: dict[str, tuple[Place, Facts]] = dict(self.entries)
        for name, (place, facts) in other.entries.items():
            existing = joined.get(name)
            joined[name] = (place, merge(existing[1], facts) if existing else facts)
        return TaintState(joined)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TaintState) and {
            name: facts for name, (_, facts) in self.entries.items()
        } == {name: facts for name, (_, facts) in other.entries.items()}

    __hash__ = None  # type: ignore[assignment]
