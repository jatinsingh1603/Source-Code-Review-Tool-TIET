"""``detect_all``: run every detector, then floor, mask and resolve.

Owning epic: E08.

**Recall over precision.** ``privacy.detect.min_confidence`` defaults to ``LOW``. For redaction a
false positive costs one placeholder where a harmless literal was, which the evaluation measures
as a utility cost; a false negative is a leaked credential. A contributor will be tempted to
raise the floor for cleaner output: do not, without the measured leakage and utility numbers
(E08-04's harness) that justify it.

Order of work: existing placeholders are masked (so detectors never see ``email`` inside
``<PII:email:2>``, and repeated redaction changes nothing); every detector runs; spans below the
floor are dropped; spans are clipped so none reaches into a masked token; overlaps are resolved.

Fail closed (I4): a detector that raises, or returns something that is not a span of a kind it
declared inside the text, aborts detection with a ``RedactionError`` carrying the detector's id
and nothing else. The report keeps **counts only**, never a value.
"""

from typing import Any, ClassVar

from pydantic import Field

from codekavach.config.models.root import Settings
from codekavach.core.log import get_logger
from codekavach.core.models import DataClassification, KavachModel, Language, RawCode, RepoPath
from codekavach.privacy.detect.base import Detector, TypedSpan
from codekavach.privacy.detect.mask import (
    PLACEHOLDER_MASK_PATTERN,
    mask_placeholders,
    placeholder_regions,
)
from codekavach.privacy.detect.overlap import remainders, resolve_overlaps
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.errors import RedactionError

_log = get_logger("codekavach.privacy.detect")


class DetectionReport(KavachModel):
    """What detection did, as numbers: per-detector hit counts and the effect of each step."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    per_detector: tuple[tuple[str, int], ...] = ()
    below_floor: int = Field(default=0, ge=0)
    downgraded: int = Field(default=0, ge=0)
    clipped_by_placeholders: int = Field(default=0, ge=0)
    spans_out: int = Field(default=0, ge=0)


def _run_one(
    detector: Detector, text: RawCode, byte_length: int, path: RepoPath, language: Language
) -> list[TypedSpan]:
    try:
        found = list(detector.detect(text, path=path, language=language))
    except Exception:  # noqa: BLE001 - a plugin may raise anything; its message may quote the text
        _log.warning("detector_failed", detector=detector.id)
        raise RedactionError(f"detector {detector.id} failed") from None
    returned: list[Any] = found  # a plugin may return anything
    for span in returned:
        if not isinstance(span, TypedSpan) or span.kind not in detector.kinds:
            raise RedactionError(f"detector {detector.id} returned an unusable span")
        if span.end_byte > byte_length:
            raise RedactionError(f"detector {detector.id} returned a span beyond the text")
    return found


def detect_with_report(
    text: RawCode,
    *,
    path: RepoPath,
    language: Language,
    settings: Settings,
    registry: DetectorRegistry,
) -> tuple[tuple[TypedSpan, ...], DetectionReport]:
    """Detect in ``text`` and return the resolved spans with a counts-only report."""
    raw = text.expose()
    masked = raw
    regions: tuple[tuple[int, int], ...] = ()
    if PLACEHOLDER_MASK_PATTERN.search(raw):
        masked = mask_placeholders(raw)
        regions = placeholder_regions(raw)
    seen = RawCode(masked)
    byte_length = len(masked.encode("utf-8", errors="surrogatepass"))
    floor = settings.privacy.detect.min_confidence

    counts: list[tuple[str, int]] = []
    kept: list[TypedSpan] = []
    below_floor = 0
    downgraded = 0
    for detector in registry.all():
        found = _run_one(detector, seen, byte_length, path, language)
        counts.append((detector.id, len(found)))
        for span in found:
            downgraded += span.downgraded
            if span.confidence < floor:
                below_floor += 1
            else:
                kept.append(span)

    clipped = 0
    if regions:
        clipped_spans: list[TypedSpan] = []
        for span in kept:
            if any(start < span.end_byte and span.start_byte < end for start, end in regions):
                clipped += 1
                clipped_spans.extend(remainders(span, regions, minimum=1))
            else:
                clipped_spans.append(span)
        kept = clipped_spans

    resolved = resolve_overlaps(kept)
    report = DetectionReport(
        per_detector=tuple(counts),
        below_floor=below_floor,
        downgraded=downgraded,
        clipped_by_placeholders=clipped,
        spans_out=len(resolved),
    )
    return resolved, report


def detect_all(
    text: RawCode,
    *,
    path: RepoPath,
    language: Language,
    settings: Settings,
    registry: DetectorRegistry,
) -> tuple[TypedSpan, ...]:
    """The resolved, ascending, non-overlapping spans of ``text``."""
    return detect_with_report(
        text, path=path, language=language, settings=settings, registry=registry
    )[0]
