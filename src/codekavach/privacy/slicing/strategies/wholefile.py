"""The whole-file unit of privacy levels L1 and L2 (E25-02).

Owning epic: E25.

L1 and L2 send code without minimisation (``docs/adr/0010-privacy-level-semantics.md``): the unit is
every file the candidate touches, in full, with blank lines trimmed at the edges. Nothing is cut,
so the result parses exactly as the file does, and callees defined in another file are still
summarised as stubs.

A file that is never sent, vendored, generated or minified is refused at once, like every other
strategy. When the files do not fit ``privacy.slice.max_tokens`` the strategy refuses with the
curable reason ``over_budget``: the selector then falls back to the enclosing function and the
slice records ``fallback_reason = "over_budget"``, so a report can say how many L1 or L2 units
were whole files and how many were cut down to fit.
"""

from codekavach.core.models import (
    Candidate,
    CodeRegion,
    CodeSlice,
    RawCode,
    SegmentRole,
    SliceSegment,
    SliceStrategy,
)
from codekavach.core.models.text import split_lines
from codekavach.privacy.slicing.assemble import assemble, numbered_labels
from codekavach.privacy.slicing.base import SlicingError
from codekavach.privacy.slicing.budget import SliceBudget, estimate
from codekavach.privacy.slicing.cutting import supported_language, trim_blank
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.shape import Lines
from codekavach.privacy.slicing.strategies.enclosing import slice_id_for
from codekavach.privacy.slicing.stubs import StubStats, build_stubs, fit_stubs


def _paths(candidate: Candidate, parsed: ParseIndex) -> list[str]:
    """The distinct files of the candidate that may be sent and were parsed, primary first."""
    seen: list[str] = []
    for location in candidate.locations:
        path = location.path
        if path in seen or parsed.is_excluded(path)[0] or not parsed.has_parsed(path):
            continue
        seen.append(path)
    return seen


class WholeFileStrategy:
    """Takes every file of the candidate in full."""

    name = SliceStrategy.WHOLE_FILE

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The slice for ``candidate``, or ``SlicingError`` with the reason it cannot be made."""
        return self.build_with_stats(candidate, parsed, budget=budget)[0]

    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]:
        """``build`` and the statistics of the stubs."""
        primary = candidate.locations[0]
        excluded, reason = parsed.is_excluded(primary.path)
        if excluded:
            raise SlicingError(reason)
        language = supported_language(parsed, primary.path)
        segments: list[SliceSegment] = []
        for path in _paths(candidate, parsed):
            lines = split_lines(parsed.source_of(path).expose())
            whole = trim_blank(lines, Lines(1, max(len(lines), 1)))
            if whole is None:
                continue
            segments.append(
                SliceSegment(
                    path=path,
                    region=CodeRegion(start_line=whole.start, end_line=whole.end),
                    text=RawCode("\n".join(lines[whole.start - 1 : whole.end])),
                    role=SegmentRole.PRIMARY if path == primary.path else SegmentRole.CONTEXT,
                )
            )
        if not segments:
            raise SlicingError("no_enclosing_code")
        labels = numbered_labels(sorted(s.path for s in segments))
        used = estimate(assemble(segments, (), language=language, labels=labels))
        if used > budget.max_tokens:
            raise SlicingError("over_budget")
        stub_set = build_stubs(
            segments,
            parsed,
            candidate_path=primary.path,
            candidate_line=primary.start_line,
            budget_tokens=budget.max_tokens - used,
        )
        stub_set, total = fit_stubs(
            stub_set, segments, language=language, labels=labels, max_tokens=budget.max_tokens
        )
        slice_ = CodeSlice(
            id=slice_id_for(candidate, segments, self.name),
            candidate_id=candidate.id,
            language=language,
            strategy=self.name,
            segments=tuple(segments),
            stubs=stub_set.stubs,
            token_estimate=max(total, used),
            truncated=False,
        )
        return slice_, stub_set.stats
