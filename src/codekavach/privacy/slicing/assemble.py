"""Putting a slice's segments and stubs into one text.

Owning epic: E11.

The order is a pure function of the input, because the payload hash and the verdict cache depend on
it (invariant I5): segments are sorted by ``(path, start_line)``, never by the order in which a
strategy found them; stubs follow, sorted by ``(path, line, symbol)``.

Each file starts with a comment line carrying its label (``# file_1``). The label comes from a
callback supplied by the caller, so this module never touches the vault or the pseudonym
generator (the seam with E09). Two segments of one file that are not adjacent are separated by an
elision marker; segments of different files are separated by a blank line.
"""

from collections.abc import Callable, Iterable, Sequence

from codekavach.core.models import Language, SliceSegment, Stub
from codekavach.privacy.slicing.elide import comment_prefix, elision_marker

Labels = Callable[[str], str]


def numbered_labels(paths: Iterable[str]) -> Labels:
    """Labels ``file_1``, ``file_2`` ... in sorted path order; the stand-in used for budgeting."""
    order = {path: f"file_{number}" for number, path in enumerate(sorted(set(paths)), start=1)}
    return order.__getitem__


def ordered(segments: Iterable[SliceSegment]) -> list[SliceSegment]:
    """Segments in the deterministic order of the assembled text."""
    return sorted(segments, key=lambda segment: (segment.path, segment.region.start_line))


def file_text(segments: Sequence[SliceSegment], language: Language) -> str:
    """The segments of one file as source text, with markers between the gaps; no label.

    This is what the strategies re-parse to prove that a slice is syntactically coherent.
    """
    marker = elision_marker(language)
    lines: list[str] = []
    previous_end: int | None = None
    for segment in sorted(segments, key=lambda item: item.region.start_line):
        if previous_end is not None and segment.region.start_line > previous_end + 1:
            lines.append(marker)
        lines.append(segment.text.expose())
        previous_end = segment.region.end_line
    return "\n".join(lines)


def assemble(
    segments: Iterable[SliceSegment],
    stubs: Iterable[Stub] = (),
    *,
    language: Language,
    labels: Labels,
) -> str:
    """The text of a slice: labelled files in path order, then the stubs."""
    prefix = comment_prefix(language)
    by_path: dict[str, list[SliceSegment]] = {}
    for segment in ordered(segments):
        by_path.setdefault(segment.path, []).append(segment)
    blocks = [
        f"{prefix} {labels(path)}\n{file_text(group, language)}" for path, group in by_path.items()
    ]
    ordered_stubs = sorted(stubs, key=lambda stub: (stub.path or "", stub.line or 0, stub.symbol))
    if ordered_stubs:
        blocks.append("\n".join(stub.signature.expose() for stub in ordered_stubs))
    return "\n\n".join(blocks)
