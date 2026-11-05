"""Detector test doubles (E08-01): small, deterministic stand-ins for the real detectors.

``ValueDetector`` reports every occurrence of fixed strings; ``RegexDetector`` reports every match
of a pattern compiled with ``safe_compile``; the rest misbehave on purpose. The ``make_*``
functions are entry-point targets (``tests.support.fake_detectors:make_valid``) for the plugin
discovery tests.
"""

import re
from collections.abc import Callable, Sequence

from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode, RepoPath
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.safe_regex import safe_compile


def _byte_offset(text: str, index: int) -> int:
    return len(text[:index].encode("utf-8"))


class ValueDetector:
    """Reports every occurrence of each value, as ``kind``/``subtype`` at ``confidence``."""

    def __init__(
        self,
        detector_id: str,
        kind: PlaceholderKind,
        subtype: str,
        values: Sequence[str],
        confidence: Confidence = Confidence.HIGH,
    ) -> None:
        self.id = detector_id
        self.kinds = frozenset({kind})
        self._kind = kind
        self._subtype = subtype
        self._values = tuple(values)
        self._confidence = confidence
        self.seen: list[str] = []

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> list[TypedSpan]:
        raw = text.expose()
        self.seen.append(raw)
        spans: list[TypedSpan] = []
        for value in self._values:
            start = raw.find(value)
            while start != -1:
                begin = _byte_offset(raw, start)
                spans.append(
                    TypedSpan(
                        kind=self._kind,
                        subtype=self._subtype,
                        start_byte=begin,
                        end_byte=begin + len(value.encode("utf-8")),
                        confidence=self._confidence,
                        detector=self.id,
                    )
                )
                start = raw.find(value, start + 1)
        return spans


class RegexDetector:
    """Reports every match of ``pattern`` (compiled through ``safe_compile``)."""

    def __init__(
        self,
        detector_id: str,
        kind: PlaceholderKind,
        subtype: str,
        pattern: str,
        confidence: Confidence = Confidence.MEDIUM,
    ) -> None:
        self.id = detector_id
        self.kinds = frozenset({kind})
        self._kind = kind
        self._subtype = subtype
        self._pattern = safe_compile(pattern)
        self._confidence = confidence

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> list[TypedSpan]:
        raw = text.expose()
        data = raw.encode("utf-8")
        return [
            TypedSpan(
                kind=self._kind,
                subtype=self._subtype,
                start_byte=match.start(),
                end_byte=match.end(),
                confidence=self._confidence,
                detector=self.id,
            )
            for match in re.finditer(self._pattern.pattern.encode("utf-8"), data)
        ]


class FixedDetector:
    """Returns the spans it was given, whatever the text."""

    def __init__(
        self,
        detector_id: str,
        kinds: frozenset[PlaceholderKind],
        spans: Sequence[TypedSpan],
    ) -> None:
        self.id = detector_id
        self.kinds = kinds
        self._spans = tuple(spans)

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> list[TypedSpan]:
        return list(self._spans)


class RaisingDetector:
    """Raises an error whose message quotes the text, as a careless plugin might."""

    id = "test.raising"
    kinds = frozenset({PlaceholderKind.SECRET})

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> list[TypedSpan]:
        raise ValueError(f"cannot read {text.expose()}")


def make_valid() -> ValueDetector:
    """Entry-point target: a valid plugin detector."""
    return ValueDetector("plugin.valid", PlaceholderKind.TERM, "domain", ["plugin-term"])


def make_without_detect() -> object:
    """Entry-point target: an object that is not a detector."""

    class Incomplete:
        id = "plugin.incomplete"
        kinds = frozenset({PlaceholderKind.TERM})

    return Incomplete()


def make_bad_id() -> ValueDetector:
    """Entry-point target: a detector whose id breaks the pattern."""
    return ValueDetector("Bad Id!", PlaceholderKind.TERM, "domain", ["x"])


def make_empty_kinds() -> object:
    """Entry-point target: a detector that declares no kind."""
    detector = ValueDetector("plugin.nokinds", PlaceholderKind.TERM, "domain", ["x"])
    detector.kinds = frozenset()
    return detector


Factory = Callable[[], object]
