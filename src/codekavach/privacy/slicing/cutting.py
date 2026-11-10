"""Cutting a slice out of line ranges: merging, trimming, imports and the coherence check.

Owning epic: E11. Shared by every strategy (E11-01 enclosing function, E11-03 path strategies).

A strategy decides which lines of which files to take; this module turns ranges into whole
segments the same way for all of them. Ranges of one file that overlap, touch or are separated by
blank lines only become one range; blank lines at the edges are trimmed; the imports a taken
range uses are found from the symbol table; and a set of segments is *coherent* when each file's
slice parses with no more errors than the whole file has. Everything is a pure function of its
input (invariant I5).
"""

from collections.abc import Callable
from dataclasses import dataclass

from tree_sitter import Node

from codekavach.core.models import Language, SegmentRole, SliceSegment
from codekavach.parsing import parse
from codekavach.parsing.models import TIMED_OUT, ParsedFile
from codekavach.privacy.slicing.assemble import file_text
from codekavach.privacy.slicing.base import SlicingError
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.shape import (
    IMPORT_TYPES,
    SUPPORTED,
    Lines,
    first,
    kept_lines,
    last,
    node_for_lines,
    runs,
    span,
    statement_of,
)


@dataclass(frozen=True, slots=True)
class Range:
    """A range of whole lines of one file and why it was taken."""

    path: str
    lines: Lines
    kind: str  # "code", "context" or "imports"


def is_coherent(parsed: ParseIndex, segments: list[SliceSegment], language: Language) -> bool:
    """Whether every file's slice parses with no more errors than the whole file has."""
    if sum(1 for segment in segments if segment.role is SegmentRole.PRIMARY) != 1:
        return False
    for path in sorted({segment.path for segment in segments}):
        baseline = max(parsed.parsed_of(path).error_count, 0)
        text = file_text([s for s in segments if s.path == path], language)
        result = parse(path, language, text)
        if result.error_count == TIMED_OUT or result.error_count > baseline:
            return False
    return True


def imports_for(parsed: ParseIndex, path: str, taken: list[Lines]) -> list[Lines]:
    """Top-level import statements that bind a name used inside the taken ranges."""
    file = parsed.parsed_of(path)
    table = parsed.symbols_of(path)
    if not table.imports:
        return []
    used = {
        text
        for location, text in file.identifiers()
        if any(lines.contains(location.start_line) for lines in taken)
    }
    found: list[Lines] = []
    for reference in table.imports:
        if reference.bound is None or reference.bound not in used:
            continue
        node = node_for_lines(file, reference.location.start_line, reference.location.end_line)
        statement = statement_of(node)
        if (
            statement is None
            or statement.parent is None
            or statement.parent.type not in {"module", "program"}
            or statement.type not in IMPORT_TYPES
        ):
            continue
        lines = span(statement)
        if not any(shares(lines, other) for other in taken):
            found.append(lines)
    return found


def shares(first_lines: Lines, second_lines: Lines) -> bool:
    """Whether two line ranges overlap."""
    return first_lines.start <= second_lines.end and second_lines.start <= first_lines.end


def blank_between(lines: list[str], before: Lines, after: Lines) -> bool:
    """Whether only blank lines separate ``before`` from ``after`` (so there is no real gap)."""
    return all(
        not lines[number - 1].strip()
        for number in range(before.end + 1, after.start)
        if 1 <= number <= len(lines)
    )


def merge_ranges(
    ranges: list[Range], lines_of: Callable[[str], list[str]]
) -> list[tuple[str, Lines, set[str]]]:
    """Merge ranges of one file that overlap, touch or are separated by blank lines only."""
    merged: list[tuple[str, Lines, set[str]]] = []
    for item in sorted(ranges, key=lambda r: (r.path, r.lines.start, r.lines.end)):
        if merged and merged[-1][0] == item.path:
            path, lines, kinds = merged[-1]
            if blank_between(lines_of(path), lines, item.lines):
                merged[-1] = (
                    path,
                    Lines(lines.start, max(lines.end, item.lines.end)),
                    kinds | {item.kind},
                )
                continue
        merged.append((item.path, item.lines, {item.kind}))
    return merged


def trim_blank(lines: list[str], span_lines: Lines) -> Lines | None:
    """``span_lines`` without blank lines at either edge and inside the file; ``None`` if empty."""
    start = max(1, span_lines.start)
    end = min(len(lines), span_lines.end)
    while start <= end and not lines[start - 1].strip():
        start += 1
    while end >= start and not lines[end - 1].strip():
        end -= 1
    return Lines(start, end) if start <= end else None


def supported_language(parsed: ParseIndex, path: str) -> Language:
    """The language of ``path`` when it can be sliced; ``SlicingError`` otherwise."""
    try:
        file = parsed.parsed_of(path)
    except KeyError:
        # The path passed the exclusion check, so the scan knows it; it just was not parsed.
        raise SlicingError("unsupported_language") from None
    if file.language not in SUPPORTED:
        raise SlicingError("unsupported_language")
    if file.tree is None:
        raise SlicingError("not_coherent")
    return file.language


def context_ranges(file: ParsedFile, node: Node) -> list[Lines]:
    """Header and closing lines of everything around ``node``, not ``node`` itself."""
    if file.tree is None:
        return []
    own = set(range(first(node), max(first(node), last(node)) + 1))
    keep = kept_lines(file.tree.root_node, node, file.language, signature=None)
    return runs(keep - own)
