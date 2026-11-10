"""Building a slice out of chosen statements: the engine of the path strategies (E11-03).

Owning epic: E11.

A path strategy decides *which statements matter* and states them as ``Anchor`` values, each with
a rank (0 is the sink, a larger number is further from it). This module turns the anchors into a
``CodeSlice`` the same way for all of them, so the rules that protect the reader live in one place:

* **Control ancestors are always kept.** Every anchor brings the compound statements around it, the
  early-exit guards before it and the signature of its function (``FunctionFlow.keep_lines``).
  Dropping an anchor drops only what no other anchor needs; the candidate's own statement is
  protected, and so is everything that controls it. This rule is not subject to budget shrinking:
  a slice that kept an assignment but not the ``if`` around it would show a guarded sink as
  unguarded.
* **Over budget, the furthest statements go first.** In a fixed order: the imports, then anchors by
  rank, furthest first, ties broken by path and line. If only protected anchors are left and the
  slice still does not fit, the strategy refuses (``over_budget``).
* **Never a broken slice.** The result must parse. A compound statement that was taken for its
  header only and does not parse is taken whole; if that fails too the strategy refuses
  (``not_coherent``).
* **Excluded files are skipped.** An anchor in a never-send, vendored or generated file is not cut;
  the recall record counts it as not included.

Everything is a pure function of its inputs (invariant I5).
"""

from bisect import bisect_left
from dataclasses import dataclass, replace
from typing import Literal

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
    SlicePurpose,
    SliceRecall,
    SliceSegment,
    SliceStrategy,
    Stub,
)
from codekavach.core.models.text import split_lines
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
from codekavach.privacy.slicing.defuse import statement_header
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.shape import (
    SUPPORTED,
    Lines,
    first,
    kept_lines,
    last,
    node_for_lines,
    runs,
    statement_of,
    unit_of,
)
from codekavach.privacy.slicing.strategies.enclosing import slice_id_for
from codekavach.privacy.slicing.stubs import StubSet, StubStats, build_stubs, fit_stubs

_LOG = get_logger("codekavach.privacy.slicing")

AnchorKind = Literal["step", "defuse"]


@dataclass(frozen=True, slots=True)
class Anchor:
    """A statement a strategy wants in the slice, and how far it is from the sink."""

    location: Location
    rank: int
    kind: AnchorKind = "step"
    protected: bool = False


@dataclass(frozen=True, slots=True)
class PathPlan:
    """What a strategy asks the builder for."""

    strategy: SliceStrategy
    anchors: tuple[Anchor, ...]
    purpose: SlicePurpose = SlicePurpose.TRIAGE
    fallback_reason: str | None = None
    path_steps: tuple[Location, ...] = ()
    defuse_found: int = 0
    extra_stubs: tuple[Stub, ...] = ()
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Resolved:
    """An anchor, or several anchors on one statement, resolved to the lines they need."""

    path: str
    lines: frozenset[int]
    context: tuple[Lines, ...]
    anchors: tuple[Anchor, ...]

    @property
    def rank(self) -> int:
        return min(anchor.rank for anchor in self.anchors)

    @property
    def protected(self) -> bool:
        return any(anchor.protected for anchor in self.anchors)

    @property
    def top(self) -> int:
        return min(self.lines)


def _module_level(parsed: ParseIndex, location: Location, *, whole: bool) -> _Resolved | None:
    file = parsed.parsed_of(location.path)
    statement = statement_of(node_for_lines(file, location.start_line, location.end_line))
    if statement is None:
        return None
    lines = kept_lines(unit_of(statement), statement, file.language, signature=None)
    del whole  # a module-level statement is always taken whole
    return _Resolved(location.path, frozenset(lines), (), ())


def _resolve(
    parsed: ParseIndex, anchor: Anchor, language: Language, *, whole: bool
) -> _Resolved | None:
    location = anchor.location
    if parsed.is_excluded(location.path)[0]:
        return None
    try:
        file = parsed.parsed_of(location.path)
    except KeyError:
        return None
    if file.tree is None or file.language not in SUPPORTED or file.language is not language:
        return None
    flow = parsed.defuse_of(location.path).flow_for(location)
    if flow is None:
        found = _module_level(parsed, location, whole=whole)
        return None if found is None else replace(found, anchors=(anchor,))
    index = flow.statement_at(location.start_line)
    if index is None:
        return None
    return _Resolved(
        location.path,
        frozenset(flow.keep_lines(index, whole=whole)),
        tuple(context_ranges(file, flow.node)),
        (anchor,),
    )


def _merged(resolved: list[_Resolved]) -> list[_Resolved]:
    """Anchors on the same lines become one entry that remembers all of them."""
    by_lines: dict[tuple[str, frozenset[int]], _Resolved] = {}
    for item in resolved:
        key = (item.path, item.lines)
        known = by_lines.get(key)
        by_lines[key] = (
            item if known is None else replace(known, anchors=known.anchors + item.anchors)
        )
    return list(by_lines.values())


# --- Python: a block that opens must not be left empty ----------------------------------------


def _blocks(root: Node, language: Language) -> list[tuple[int, int, int, Lines | None]]:
    """``(header line, block first, block last, header of the block's first statement)``."""
    found: list[tuple[int, int, int, Lines | None]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        for child in node.children:
            if child.type != "block":
                continue
            statements = [c for c in child.named_children if c.type != "comment"]
            header = statement_header(statements[0], language) if statements else None
            found.append((first(node), first(child), last(child), header))
    return found


def close_blocks(blocks: list[tuple[int, int, int, Lines | None]], lines: set[int]) -> set[int]:
    """Add the first statement of every block whose header is taken but none of its body is."""
    result = set(lines)
    changed = True
    while changed:
        changed = False
        ordered = sorted(result)
        for header, begin, end, opening in blocks:
            if header not in result or opening is None:
                continue
            at = bisect_left(ordered, begin)
            if at < len(ordered) and ordered[at] <= end:
                continue
            result.update(range(opening.start, opening.end + 1))
            changed = True
            ordered = sorted(result)
    return result


@dataclass(slots=True)
class _Plan:
    """The mutable state of one build."""

    parsed: ParseIndex
    candidate: Candidate
    primary: Location
    language: Language
    steps: dict[str, set[int]]
    block_cache: dict[str, list[tuple[int, int, int, Lines | None]]]

    def ranges(self, active: list[_Resolved], *, imports: bool) -> list[Range]:
        by_path: dict[str, set[int]] = {}
        for item in active:
            by_path.setdefault(item.path, set()).update(item.lines)
        ranges: list[Range] = []
        for path in sorted(by_path):
            file = self.parsed.parsed_of(path)
            lines = by_path[path]
            if file.language is Language.PYTHON and file.tree is not None:
                blocks = self.block_cache.get(path)
                if blocks is None:
                    blocks = _blocks(file.tree.root_node, file.language)
                    self.block_cache[path] = blocks
                lines = close_blocks(blocks, lines)
            taken = runs(lines)
            ranges.extend(Range(path, run, "code") for run in taken)
            if imports:
                ranges.extend(
                    Range(path, i, "imports") for i in imports_for(self.parsed, path, taken)
                )
        for item in active:
            ranges.extend(Range(item.path, c, "context") for c in item.context)
        return ranges

    def segments(self, active: list[_Resolved], *, imports: bool) -> list[SliceSegment]:
        sources: dict[str, list[str]] = {}

        def lines_of(path: str) -> list[str]:
            return sources.setdefault(path, split_lines(self.parsed.source_of(path).expose()))

        segments: list[SliceSegment] = []
        for path, span_lines, kinds in merge_ranges(self.ranges(active, imports=imports), lines_of):
            lines = lines_of(path)
            trimmed = trim_blank(lines, span_lines)
            if trimmed is None:
                continue
            if path == self.primary.path and trimmed.contains(self.primary.start_line):
                role = SegmentRole.PRIMARY
            elif any(trimmed.contains(line) for line in self.steps.get(path, ())):
                role = SegmentRole.TAINT_STEP
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


def _recall(
    plan: PathPlan, segments: list[SliceSegment], active: list[_Resolved]
) -> SliceRecall | None:
    """How many path steps lie in the segments, and how many def-use predecessors were kept."""
    if not plan.path_steps and plan.defuse_found == 0:
        return None
    included = sum(
        1
        for step in plan.path_steps
        if any(
            segment.path == step.path and segment.region.contains_line(step.start_line)
            for segment in segments
        )
    )
    defuse = sum(1 for item in active for a in item.anchors if a.kind == "defuse")
    found = max(plan.defuse_found, defuse)
    return SliceRecall(
        path_steps_total=len(plan.path_steps),
        path_steps_included=included,
        defuse_found=found,
        defuse_included=min(defuse, found),
    )


def build_path_slice(
    candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget, plan: PathPlan
) -> tuple[CodeSlice, StubStats]:
    """The slice of ``plan`` for ``candidate``, or ``SlicingError`` with the reason it cannot be.

    The candidate's own statement is always an anchor and is protected, whatever the plan says.
    """
    primary = candidate.locations[0]
    excluded, reason = parsed.is_excluded(primary.path)
    if excluded:
        raise SlicingError(reason)
    language = supported_language(parsed, primary.path)
    own = Anchor(primary, 0, "step", protected=True)
    anchors = (own, *plan.anchors)
    for whole in (False, True):
        resolved = [r for a in anchors if (r := _resolve(parsed, a, language, whole=whole))]
        if not any(a.protected for r in resolved for a in r.anchors):
            raise SlicingError("no_enclosing_code")
        result = _fit(candidate, parsed, budget, plan, _merged(resolved), language, primary)
        if result is not None:
            return result
    raise SlicingError("not_coherent")


def _fit(  # noqa: PLR0917 - one call site; the pieces of one build
    candidate: Candidate,
    parsed: ParseIndex,
    budget: SliceBudget,
    plan: PathPlan,
    resolved: list[_Resolved],
    language: Language,
    primary: Location,
) -> tuple[CodeSlice, StubStats] | None:
    steps: dict[str, set[int]] = {}
    for item in resolved:
        for a in item.anchors:
            if a.kind == "step":
                steps.setdefault(a.location.path, set()).add(a.location.start_line)
    state = _Plan(parsed, candidate, primary, language, steps, {})
    active = sorted(resolved, key=lambda r: (r.path, r.top))
    imports = True
    truncated = plan.truncated
    while True:
        segments = state.segments(active, imports=imports)
        labels = numbered_labels(sorted({s.path for s in segments}))
        used = estimate(assemble(segments, (), language=language, labels=labels))
        if used <= budget.max_tokens:
            break
        truncated = True
        if imports:
            imports = False
            continue
        droppable = [r for r in active if not r.protected]
        if not droppable:
            raise SlicingError("over_budget")
        victim = max(droppable, key=lambda r: (r.rank, r.path, -r.top))
        active.remove(victim)
    if not is_coherent(parsed, segments, language):
        return None
    stub_set = build_stubs(
        segments,
        parsed,
        candidate_path=primary.path,
        candidate_line=primary.start_line,
        budget_tokens=budget.max_tokens - used,
    )
    if plan.extra_stubs:
        known = {stub.symbol for stub in stub_set.stubs}
        extra = tuple(s for s in plan.extra_stubs if s.symbol not in known)
        stub_set = StubSet(stubs=extra + stub_set.stubs, stats=stub_set.stats)
    stub_set, total = fit_stubs(
        stub_set, segments, language=language, labels=labels, max_tokens=budget.max_tokens
    )
    slice_ = CodeSlice(
        id=slice_id_for(candidate, segments, plan.strategy),
        candidate_id=candidate.id,
        language=language,
        strategy=plan.strategy,
        segments=tuple(segments),
        stubs=stub_set.stubs,
        token_estimate=max(total, used),
        truncated=truncated,
        purpose=plan.purpose,
        fallback_reason=plan.fallback_reason,  # type: ignore[arg-type]
        recall=_recall(plan, segments, active),
    )
    return slice_, stub_set.stats
