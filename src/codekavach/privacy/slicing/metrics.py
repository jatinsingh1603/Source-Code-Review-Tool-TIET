"""Disclosure measurement: how much of the repository a slice, and a scan, has prepared to send.

Owning epic: E11. Metric M7 of ``docs/research/INSIGHTS.md`` section 4.3.

``measure`` describes one slice (lines, estimated tokens, functions, files, the fraction of its
files and of the repository, stubs, whether it was truncated). ``ScanDisclosure`` accumulates the
same facts over a scan.

**The union, not the sum.** Ten candidates in one 80-line function each disclose the same 80
lines; adding them gives 800 lines and a fraction that can exceed 100 percent. The number the
privacy attestation prints is the *union* of the disclosed lines: an interval set per file in
which two overlapping slices count once. A worked case: a 10 000-line repository, three
candidates in one 60-line function and one in a 40-line function, gives a union of 100 lines
(1.0 percent) where the sum would give 220 lines (2.2 percent). The sum is kept only as an
activity count (``lines_total``) and is never divided by the repository size.

**Call edges.** Deterministic pseudonyms let a provider stitch the slices of one scan into a call
graph (``INSIGHTS.md`` section 4.2). The number of distinct pairs of functions that appeared
together in a slice, stubs included, is the measure of how much of that graph a provider could
rebuild. A pair that appears together is counted as an edge whether or not one calls the other,
which over-states the graph rather than under-states it. Nothing here prevents the attack: the
controls are the aggregation budget, the per-request pseudonym mode and the stub design.

Everything here is a count or a fraction. ``as_attestation_rows`` holds no path and no name.
"""

from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from typing import Final

from codekavach.core.models import CodeSlice
from codekavach.privacy.slicing.index import ParseIndex

_PERCENT: Final = 100.0


@dataclass(frozen=True, slots=True)
class SliceDisclosure:
    """What one slice discloses.

    ``file_fraction`` is the slice's lines over the line count of the files it touches (for a
    multi-file slice, summed over those files); ``repo_fraction`` is its lines over the
    inventory's total. Both are fractions of one, and neither accounts for overlap with other
    slices: that is what ``ScanDisclosure`` is for.
    """

    lines: int
    tokens: int
    functions: int
    files: int
    file_fraction: float
    repo_fraction: float
    stub_count: int
    truncated: bool
    strategy: str


class IntervalSet:
    """Disjoint, non-adjacent line intervals of one file, in a sorted list.

    Insertion finds its place by binary search and merges every interval it touches, so the list
    stays short and ``total`` is always the number of distinct lines covered.
    """

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []
        self._total = 0

    @property
    def total(self) -> int:
        """Distinct lines covered."""
        return self._total

    def intervals(self) -> tuple[tuple[int, int], ...]:
        """The merged intervals, ascending."""
        return tuple(zip(self._starts, self._ends, strict=True))

    def covered(self, start: int, end: int) -> int:
        """How many lines of ``start..end`` are already covered."""
        count = 0
        index = bisect_left(self._ends, start)
        while index < len(self._starts) and self._starts[index] <= end:
            count += min(end, self._ends[index]) - max(start, self._starts[index]) + 1
            index += 1
        return count

    def add(self, start: int, end: int) -> int:
        """Cover ``start..end`` (inclusive); returns how many lines were not covered before."""
        if end < start:
            raise ValueError("an interval ends at or after its start")
        low = bisect_left(self._ends, start - 1)  # first interval that touches or follows
        high = low
        merged_start, merged_end = start, end
        removed = 0
        while high < len(self._starts) and self._starts[high] <= end + 1:
            merged_start = min(merged_start, self._starts[high])
            merged_end = max(merged_end, self._ends[high])
            removed += self._ends[high] - self._starts[high] + 1
            high += 1
        self._starts[low:high] = [merged_start]
        self._ends[low:high] = [merged_end]
        gained = (merged_end - merged_start + 1) - removed
        self._total += gained
        return gained


def _function_keys(slice_: CodeSlice, index: ParseIndex) -> frozenset[tuple[str, str]]:
    """The functions whose full range a segment of the slice overlaps, as ``(path, name)``."""
    keys: set[tuple[str, str]] = set()
    for segment in slice_.segments:
        start, end = segment.region.start_line, segment.region.end_line
        try:
            ranges = index.function_ranges_of(segment.path)
        except KeyError:
            continue  # in the inventory but never parsed
        keys.update(
            (segment.path, found.qualified_name)
            for found in ranges
            if found.full.start_line <= end and start <= found.full.end_line
        )
    return frozenset(keys)


def _stub_keys(slice_: CodeSlice) -> frozenset[tuple[str, str]]:
    return frozenset((stub.path or "", stub.symbol) for stub in slice_.stubs)


def measure(slice_: CodeSlice, index: ParseIndex) -> SliceDisclosure:
    """The disclosure of one slice; negligible cost (a pass over the segments)."""
    paths = slice_.files
    file_lines = sum(index.line_count_of(path) for path in paths)
    repo_lines = index.total_lines
    lines = slice_.total_lines
    return SliceDisclosure(
        lines=lines,
        tokens=slice_.token_estimate,
        functions=len(_function_keys(slice_, index)),
        files=len(paths),
        file_fraction=lines / file_lines if file_lines else 0.0,
        repo_fraction=lines / repo_lines if repo_lines else 0.0,
        stub_count=len(slice_.stubs),
        truncated=slice_.truncated,
        strategy=slice_.strategy.value,
    )


class ScanDisclosure:
    """What a scan has disclosed so far, over every candidate and every context round.

    ``repo_lines`` is the inventory's total (``ParseIndex.total_lines``). The object is the one
    the aggregation budget reads, so a slice is recorded here before it is prepared for egress.
    Recording is order-independent: every figure is a set, a sum or an interval union.
    """

    def __init__(self, repo_lines: int) -> None:
        if repo_lines < 1:
            raise ValueError("a repository has at least one line")
        self._repo_lines = repo_lines
        self._intervals: dict[str, IntervalSet] = {}
        self._functions: set[tuple[str, str]] = set()
        self._edges: set[tuple[tuple[str, str], tuple[str, str]]] = set()
        self._strategies: Counter[str] = Counter()
        self._rounds: Counter[str] = Counter()
        self._lines_total = 0
        self._tokens = 0
        self._slices = 0
        self._expansions = 0

    @classmethod
    def for_index(cls, index: ParseIndex) -> "ScanDisclosure":
        """A fresh record for the repository ``index`` describes."""
        return cls(max(index.total_lines, 1))

    # ---- recording ---------------------------------------------------------------------

    def record(
        self,
        slice_: CodeSlice,
        index: ParseIndex,
        *,
        expansion: bool = False,
    ) -> SliceDisclosure:
        """Add ``slice_``; ``expansion`` marks a context round (counted against the candidate)."""
        for segment in slice_.segments:
            self._intervals.setdefault(segment.path, IntervalSet()).add(
                segment.region.start_line, segment.region.end_line
            )
        functions = _function_keys(slice_, index)
        together = sorted(functions | _stub_keys(slice_))
        self._functions.update(functions)
        self._edges.update(combinations(together, 2))
        self._strategies[slice_.strategy.value] += 1
        self._lines_total += slice_.total_lines
        self._tokens += slice_.token_estimate
        self._slices += 1
        if expansion:
            self._expansions += 1
            self._rounds[slice_.candidate_id] += 1
        return measure(slice_, index)

    def would_reach_pct(self, slice_: CodeSlice) -> float:
        """The union percentage after ``slice_`` is added; nothing is recorded."""
        extra = 0
        for segment in slice_.segments:  # the segments of one slice never overlap (CodeSlice)
            start, end = segment.region.start_line, segment.region.end_line
            known = self._intervals.get(segment.path)
            extra += (end - start + 1) - (known.covered(start, end) if known else 0)
        return (self.union_lines + extra) / self._repo_lines * _PERCENT

    # ---- reading -----------------------------------------------------------------------

    @property
    def union_lines(self) -> int:
        """Distinct lines disclosed over the scan."""
        return sum(found.total for found in self._intervals.values())

    @property
    def repo_pct(self) -> float:
        """Union lines as a percentage of the repository."""
        return self.union_lines / self._repo_lines * _PERCENT

    @property
    def lines_total(self) -> int:
        """Lines summed over every slice: an activity count, never a fraction of anything."""
        return self._lines_total

    @property
    def files(self) -> int:
        """Distinct files touched."""
        return len(self._intervals)

    @property
    def functions(self) -> int:
        """Distinct functions touched."""
        return len(self._functions)

    @property
    def call_edges(self) -> int:
        """Distinct pairs of functions that appeared together in a slice."""
        return len(self._edges)

    @property
    def expansions(self) -> int:
        """Context rounds delivered over the scan."""
        return self._expansions

    @property
    def tokens(self) -> int:
        """Estimated tokens summed over every slice."""
        return self._tokens

    def rounds_used(self, candidate_id: str) -> int:
        """Context rounds delivered for ``candidate_id`` (the cap is per candidate)."""
        return self._rounds[candidate_id]

    def strategy_mix(self) -> tuple[tuple[str, int], ...]:
        """How many slices each strategy produced, by strategy name."""
        return tuple(sorted(self._strategies.items()))

    def as_attestation_rows(self) -> tuple[tuple[str, str], ...]:
        """The rows the report's privacy attestation prints: counts and fractions, no paths."""
        rows = [
            ("slices", str(self._slices)),
            ("files", str(self.files)),
            ("functions", str(self.functions)),
            ("lines_disclosed", str(self.union_lines)),
            ("lines_prepared_total", str(self._lines_total)),
            ("tokens_estimated", str(self._tokens)),
            ("repository_fraction_pct", f"{self.repo_pct:.2f}"),
            ("call_edges", str(self.call_edges)),
            ("context_expansions", str(self._expansions)),
        ]
        rows.extend((f"strategy_{name}", str(count)) for name, count in self.strategy_mix())
        return tuple(rows)

    def snapshot(self) -> dict[str, object]:
        """The figures as a plain mapping (used for the disclosure golden file)."""
        return dict(self.as_attestation_rows())
