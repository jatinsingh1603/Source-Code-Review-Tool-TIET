"""The enclosing-function slice strategy.

Owning epic: E11. MVP (the Demo 1 minimum); extended by E11-03 (path-based strategies).

For each location of a candidate the strategy takes the function or method around it, in full and
with its decorators; the headers (and, with braces, the closing lines) of the classes and
functions around that; and the imports the taken code actually uses. Overlapping and adjacent
ranges are merged into one segment. Code that sits outside any function (module level, a
configuration file, a template) is cut as a window of whole top-level statements around the
location, its size derived from the budget.

When the result is over budget it is shrunk in a fixed order, a table and not a heuristic, so the
same input always shrinks the same way (invariant I5):

1. drop the import segments;
2. halve the window around module-level code until it reaches the candidate's own statement;
3. elide the interior of the largest unit (function, or top-level statement) that can still be
   cut, then the next largest, and so on.

The lines of the candidate itself, the signature of the enclosing function and every compound
statement that dominates the candidate are never removed: a missing guard is exactly the context
whose absence produces a false positive. If the slice still does not fit, the strategy refuses
(``over_budget``) instead of exceeding the budget. A slice that does not parse after a cut is not
used; the cut is undone, and if even the uncut slice does not parse the strategy refuses
(``not_coherent``). Everything here is a pure function of the inputs.
"""

import hashlib
from dataclasses import dataclass, replace

from tree_sitter import Node

from codekavach.core.log import get_logger
from codekavach.core.models import (
    Candidate,
    CodeRegion,
    CodeSlice,
    Language,
    Location,
    RawCode,
    SegmentRole,
    SliceSegment,
    SliceStrategy,
)
from codekavach.core.models.ids import SliceId, encode_ulid
from codekavach.core.models.text import split_lines
from codekavach.parsing.functions import FunctionRange
from codekavach.parsing.models import ParsedFile
from codekavach.privacy.slicing.assemble import assemble, numbered_labels
from codekavach.privacy.slicing.base import SlicingError
from codekavach.privacy.slicing.budget import SliceBudget, estimate
from codekavach.privacy.slicing.cutting import (
    Range,
    context_ranges,
    imports_for,
    is_coherent,
    merge_ranges,
    supported_language,
    trim_blank,
)
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.shape import (
    SUPPORTED,
    Lines,
    body_of,
    closer_line,
    is_function_of,
    kept_lines,
    node_for_lines,
    runs,
    span,
    statement_of,
    unit_of,
)
from codekavach.privacy.slicing.stubs import StubStats, build_stubs, fit_stubs

_LOG = get_logger("codekavach.privacy.slicing")
_MIN_WINDOW = 3
_MAX_WINDOW = 30
_TOKENS_PER_WINDOW_LINE = 64


@dataclass(frozen=True, slots=True)
class _Unit:
    """The code taken around one location of the candidate."""

    path: str
    location: Location
    node: Node | None
    statement: Node | None
    function: FunctionRange | None
    anchor: Lines
    signature: Lines | None

    @property
    def can_elide(self) -> bool:
        return self.node is not None and self.anchor.end > self.anchor.start


@dataclass(frozen=True, slots=True)
class _Flags:
    """Which shrink steps have been taken."""

    imports: bool
    window: int
    elided: frozenset[int] = frozenset()
    refused: frozenset[int] = frozenset()


def _window_for(budget: SliceBudget) -> int:
    return max(_MIN_WINDOW, min(_MAX_WINDOW, budget.max_tokens // _TOKENS_PER_WINDOW_LINE))


def slice_id_for(
    candidate: Candidate,
    segments: list[SliceSegment],
    strategy: SliceStrategy = SliceStrategy.ENCLOSING_FUNCTION,
) -> SliceId:
    """A slice id derived from the candidate and the slice, so equal inputs give equal bytes."""
    digest = hashlib.sha256()
    digest.update(candidate.id.encode())
    digest.update(strategy.value.encode())
    for segment in segments:
        digest.update(
            f"{segment.path}:{segment.region.start_line}:{segment.region.end_line}".encode()
        )
        digest.update(segment.text.expose().encode())
    raw = digest.digest()
    return SliceId("slice_" + encode_ulid(int.from_bytes(raw[:6], "big"), raw[6:16]))


@dataclass(frozen=True, slots=True)
class _Job:
    """Everything the shrink loop needs to turn flags into a slice."""

    parsed: ParseIndex
    units: list[_Unit]
    primary: Location
    language: Language

    def ranges(self, flags: _Flags) -> list[Range]:
        ranges: list[Range] = []
        taken: dict[str, list[Lines]] = {}
        for number, unit in enumerate(self.units):
            file = self.parsed.parsed_of(unit.path)
            for lines in _code(unit, flags, number, file.language):
                ranges.append(Range(unit.path, lines, "code"))
                taken.setdefault(unit.path, []).append(lines)
            if unit.node is not None:
                ranges.extend(
                    Range(unit.path, c, "context") for c in context_ranges(file, unit.node)
                )
        if flags.imports:
            for path, lines_taken in taken.items():
                ranges.extend(
                    Range(path, i, "imports") for i in imports_for(self.parsed, path, lines_taken)
                )
        return ranges

    def segments(self, flags: _Flags) -> list[SliceSegment]:
        sources: dict[str, list[str]] = {}

        def lines_of(path: str) -> list[str]:
            return sources.setdefault(path, split_lines(self.parsed.source_of(path).expose()))

        merged = merge_ranges(self.ranges(flags), lines_of)
        segments: list[SliceSegment] = []
        for path, lines_range, kinds in merged:
            lines = lines_of(path)
            trimmed = trim_blank(lines, lines_range)
            if trimmed is None:
                continue
            if path == self.primary.path and trimmed.contains(self.primary.start_line):
                role = SegmentRole.PRIMARY
            elif kinds == {"imports"}:
                role = SegmentRole.IMPORTS
            else:
                role = SegmentRole.CONTEXT
            segments.append(
                SliceSegment(
                    path=path,
                    region=CodeRegion(start_line=trimmed.start, end_line=trimmed.end),
                    text=RawCode("\n".join(lines[trimmed.start - 1 : trimmed.end])),
                    role=role,
                )
            )
        return segments

    def coherent(self, segments: list[SliceSegment]) -> bool:
        """Whether every file's slice parses with no more errors than the whole file has."""
        return is_coherent(self.parsed, segments, self.language)

    def shrink(self, flags: _Flags) -> _Flags | None:
        """The next state of the shrink table, or ``None`` when nothing is left to cut."""
        if flags.imports:
            return replace(flags, imports=False)
        windows = any(u.function is None and u.node is not None for u in self.units)
        if flags.window > 0 and windows:
            return replace(flags, window=flags.window // 2)
        done = flags.elided | flags.refused
        order = sorted(
            (n for n, u in enumerate(self.units) if u.can_elide and n not in done),
            key=lambda n: (-(self.units[n].anchor.end - self.units[n].anchor.start), n),
        )
        for number in order:
            trial = replace(flags, elided=flags.elided | {number})
            if self.coherent(self.segments(trial)):
                return trial
            flags = replace(flags, refused=flags.refused | {number})
        return None


class EnclosingFunctionStrategy:
    """Cuts the function around each location, with the context needed to parse and to read it."""

    name = SliceStrategy.ENCLOSING_FUNCTION

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The slice for ``candidate``, or ``SlicingError`` with the reason it cannot be made."""
        return self.build_with_stats(candidate, parsed, budget=budget)[0]

    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]:
        """``build`` and the statistics of the stubs: what was left out, and why (E11-02)."""
        primary = candidate.locations[0]
        excluded, reason = parsed.is_excluded(primary.path)
        if excluded:
            raise SlicingError(reason)
        language = supported_language(parsed, primary.path)
        units = _units(parsed, candidate)
        job = _Job(parsed, units, primary, language)
        labels = numbered_labels(sorted({unit.path for unit in units}))
        flags = _Flags(imports=True, window=_window_for(budget))
        truncated = False
        while True:
            segments = job.segments(flags)
            if not job.coherent(segments):
                raise SlicingError("not_coherent")
            used = estimate(assemble(segments, (), language=language, labels=labels))
            if used <= budget.max_tokens:
                stub_set = build_stubs(
                    segments,
                    parsed,
                    candidate_path=primary.path,
                    candidate_line=primary.start_line,
                    budget_tokens=budget.max_tokens - used,
                )
                stub_set, total = fit_stubs(
                    stub_set,
                    segments,
                    language=language,
                    labels=labels,
                    max_tokens=budget.max_tokens,
                )
                slice_ = CodeSlice(
                    id=slice_id_for(candidate, segments),
                    candidate_id=candidate.id,
                    language=language,
                    strategy=self.name,
                    segments=tuple(segments),
                    stubs=stub_set.stubs,
                    token_estimate=max(total, used),
                    truncated=truncated,
                )
                return slice_, stub_set.stats
            step = job.shrink(flags)
            if step is None:
                raise SlicingError("over_budget")
            flags, truncated = step, True


def _units(parsed: ParseIndex, candidate: Candidate) -> list[_Unit]:
    units: list[_Unit] = []
    for number, location in enumerate(candidate.locations):
        if parsed.is_excluded(location.path)[0]:
            continue
        try:
            file = parsed.parsed_of(location.path)
        except KeyError:
            continue
        if file.tree is None or file.language not in SUPPORTED:
            continue
        units.append(_unit(parsed, file, location, primary=number == 0))
    return units


def _unit(parsed: ParseIndex, file: ParsedFile, location: Location, *, primary: bool) -> _Unit:
    found = node_for_lines(file, location.start_line, location.end_line)
    statement = statement_of(found)
    function = parsed.enclosing_function(location)
    if function is not None and found is not None:
        node: Node | None = found
        while node is not None and not is_function_of(
            node, function.full.start_line, function.header.start_line, function.full.end_line
        ):
            node = node.parent
        if node is not None:
            return _Unit(
                location.path,
                location,
                node,
                statement if statement != node else None,
                function,
                Lines(function.full.start_line, function.full.end_line),
                Lines(function.full.start_line, function.header.end_line),
            )
    if statement is None:
        if primary:
            raise SlicingError("no_enclosing_code")
        return _Unit(location.path, location, None, None, None, _lines_of(location), None)
    member = unit_of(statement)
    return _Unit(location.path, location, member, statement, None, span(member), None)


def _code(unit: _Unit, flags: _Flags, number: int, language: Language) -> list[Lines]:
    node = unit.node
    if number in flags.elided and node is not None:
        return _elided(unit, language)
    if unit.function is None and node is not None:
        return [_window(unit, flags.window)]
    return [unit.anchor]


# --- helpers ----------------------------------------------------------------------------------


def _lines_of(location: Location) -> Lines:
    return Lines(location.start_line, location.end_line)


def _window(unit: _Unit, size: int) -> Lines:
    """Whole top-level statements around the unit, reaching ``size`` lines either side."""
    node = unit.node
    assert node is not None  # noqa: S101 - callers pass units with a node
    parent = node.parent
    if parent is None:
        return unit.anchor
    low = unit.anchor.start - size
    high = unit.anchor.end + size
    start, end = unit.anchor.start, unit.anchor.end
    for sibling in parent.named_children:
        sibling_lines = span(sibling)
        if sibling_lines.end >= low and sibling_lines.start <= high:
            start = min(start, sibling_lines.start)
            end = max(end, sibling_lines.end)
    return Lines(start, end)


def _elided(unit: _Unit, language: Language) -> list[Lines]:
    node = unit.node
    assert node is not None  # noqa: S101 - callers pass units with a node
    kept: set[int]
    if unit.statement is not None:
        kept = kept_lines(node, unit.statement, language, signature=unit.signature)
    else:
        kept = set(range(unit.location.start_line, unit.location.end_line + 1))
        if unit.signature is not None:
            kept.update(range(unit.signature.start, unit.signature.end + 1))
            body = body_of(node)
            closing = closer_line(body, language) if body is not None else None
            if closing is not None:
                kept.add(closing.start)
    inside = {line for line in kept if unit.anchor.contains(line)}
    return runs(inside) or [unit.anchor]
