"""Helpers for the payload tests (E09-05): slices built by hand and a redaction of their layout.

Not a ``codekavach`` module, so it has no "Owning epic" line.
"""

from collections.abc import Sequence

from codekavach.core.models import (
    CodeRegion,
    CodeSlice,
    Language,
    PrivacyLevel,
    RawCode,
    SegmentRole,
    SliceSegment,
    SliceStrategy,
    Stub,
    StubReason,
)
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.pseudonymise.engine import Pseudonymiser
from codekavach.privacy.redact.redactor import RedactionResult
from tests.support.factories import CANDIDATE_ID, SLICE_ID

SALT = ScanSalt(bytes(range(32)))


def segment(
    path: str, start: int, lines: Sequence[str], role: SegmentRole = SegmentRole.CONTEXT
) -> SliceSegment:
    """A segment of whole lines starting at file line ``start``."""
    return SliceSegment(
        path=path,
        region=CodeRegion(start_line=start, end_line=start + len(lines) - 1),
        text=RawCode("\n".join(lines)),
        role=role,
    )


def stub(symbol: str, signature: str, *, path: str | None = None, line: int | None = None) -> Stub:
    """A stub of a callee left out of the slice."""
    return Stub(
        symbol=symbol,
        signature=RawCode(signature),
        reason=StubReason.CROSS_FILE_CALLEE,
        path=path,
        line=line,
    )


def slice_of(
    *segments: SliceSegment,
    stubs: Sequence[Stub] = (),
    language: Language = Language.PYTHON,
) -> CodeSlice:
    """A slice of ``segments``; the first has the primary role unless one is given."""
    if not any(s.role is SegmentRole.PRIMARY for s in segments):
        first = segments[0]
        segments = (first.evolve(role=SegmentRole.PRIMARY), *segments[1:])
    return CodeSlice(
        id=SLICE_ID,
        candidate_id=CANDIDATE_ID,
        language=language,
        strategy=SliceStrategy.ENCLOSING_FUNCTION,
        segments=tuple(segments),
        stubs=tuple(stubs),
        token_estimate=64,
    )


def unredacted(
    slice_: CodeSlice, level: PrivacyLevel = PrivacyLevel.L3, engine: Pseudonymiser | None = None
) -> RedactionResult:
    """A redaction that found nothing: the layout text as it is."""
    layout = (engine or Pseudonymiser()).layout(slice_, level)
    return RedactionResult(text=layout.text)
