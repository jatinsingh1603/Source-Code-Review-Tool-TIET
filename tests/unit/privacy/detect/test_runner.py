"""``detect_all``: floor, masking, clipping, fail-closed and the report (E08-01)."""

import pytest

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all, detect_with_report
from codekavach.privacy.errors import RedactionError
from codekavach.privacy.redact.numbering import PlaceholderNumbering
from codekavach.privacy.redact.redactor import Redactor
from tests.support.fake_detectors import FixedDetector, RaisingDetector, ValueDetector

SECRET, PII, TERM = PlaceholderKind.SECRET, PlaceholderKind.PII, PlaceholderKind.TERM
PATH = "src/app.py"
SALT = ScanSalt.from_hex("33" * 32)  # pragma: allowlist secret


def settings(floor: str = "low") -> Settings:
    return Settings.model_validate({"privacy": {"detect": {"min_confidence": floor}}})


def span(kind: PlaceholderKind, subtype: str, start: int, end: int, conf: Confidence) -> TypedSpan:
    return TypedSpan(
        kind=kind,
        subtype=subtype,
        start_byte=start,
        end_byte=end,
        confidence=conf,
        detector="test.fixed",
    )


def run(text: str, registry: DetectorRegistry, floor: str = "low") -> tuple[TypedSpan, ...]:
    return detect_all(
        RawCode(text),
        path=PATH,
        language=Language.PYTHON,
        settings=settings(floor),
        registry=registry,
    )


def test_the_default_floor_is_low_so_recall_wins() -> None:
    assert Settings().privacy.detect.min_confidence is Confidence.LOW
    assert Settings().privacy.pii_locales == ["intl", "in"]


def test_detectors_run_and_their_spans_are_resolved() -> None:
    registry = DetectorRegistry(
        [
            ValueDetector("test.email", PII, "email", ["a@b.test"]),
            ValueDetector("test.term", TERM, "domain", ["bonus"], Confidence.MEDIUM),
        ]
    )
    spans = run("mail a@b.test about the bonus", registry)
    assert [(s.subtype, s.start_byte, s.end_byte) for s in spans] == [
        ("email", 5, 13),
        ("domain", 24, 29),
    ]


@pytest.mark.parametrize(
    ("floor", "kept"),
    [("low", 3), ("medium", 2), ("high", 1)],
)
def test_the_confidence_floor_drops_weaker_spans(floor: str, kept: int) -> None:
    registry = DetectorRegistry(
        [
            ValueDetector("test.hi", PII, "email", ["AAAA"], Confidence.HIGH),
            ValueDetector("test.mid", PII, "ipv4", ["BBBB"], Confidence.MEDIUM),
            ValueDetector("test.lo", PII, "iban", ["CCCC"], Confidence.LOW),
        ]
    )
    assert len(run("AAAA BBBB CCCC", registry, floor)) == kept


def test_the_report_carries_counts_only() -> None:
    registry = DetectorRegistry(
        [
            ValueDetector("test.hi", PII, "email", ["AAAA"], Confidence.HIGH),
            ValueDetector("test.lo", PII, "iban", ["AAAA", "BBBB"], Confidence.LOW),
        ]
    )
    spans, report = detect_with_report(
        RawCode("AAAA BBBB"),
        path=PATH,
        language=Language.PYTHON,
        settings=settings("medium"),
        registry=registry,
    )
    assert report.per_detector == (("test.hi", 1), ("test.lo", 2))
    assert (report.below_floor, report.spans_out, len(spans)) == (2, 1, 1)
    assert "AAAA" not in report.model_dump_json()
    assert "BBBB" not in repr(report)


def test_existing_placeholders_are_masked_before_detectors_run() -> None:
    detector = ValueDetector("test.word", PII, "email", ["email", "SECRET"])
    text = 'a = "<SECRET:aws_access_key:1>" and <PII:email:2> and email'
    spans = run(text, DetectorRegistry([detector]))
    assert [text[s.start_byte : s.end_byte] for s in spans] == ["email"]
    assert spans[0].start_byte == text.rindex("email")
    assert "SECRET" not in detector.seen[0]
    assert len(detector.seen[0]) == len(text)


def test_a_span_that_reaches_into_a_placeholder_is_clipped_to_the_free_bytes() -> None:
    text = "pre<PII:email:1>post"
    fixed = FixedDetector(
        "test.fixed", frozenset({SECRET}), [span(SECRET, "jwt", 0, 20, Confidence.HIGH)]
    )
    spans = run(text, DetectorRegistry([fixed]))
    assert [(s.start_byte, s.end_byte) for s in spans] == [(0, 3), (16, 20)]


def test_redacting_twice_is_idempotent_end_to_end() -> None:
    registry = DetectorRegistry([ValueDetector("test.key", SECRET, "jwt", ["TOPSECRETVALUE"])])
    numbering = PlaceholderNumbering(SALT)
    first_spans = run("k = TOPSECRETVALUE", registry)
    first = Redactor().redact("k = TOPSECRETVALUE", first_spans, numbering=numbering)
    second_spans = run(first.text, registry)
    second = Redactor().redact(first.text, second_spans, numbering=numbering)
    assert second_spans == ()
    assert second.text == first.text
    assert second.placeholders == first.placeholders


# --- fail closed (I4) ----------------------------------------------------------------------


def test_a_detector_that_raises_aborts_detection_without_quoting_the_text() -> None:
    text = "password=hunter2-this-must-not-leak"
    with pytest.raises(RedactionError) as caught:
        run(text, DetectorRegistry([RaisingDetector()]))
    assert "hunter2" not in str(caught.value)
    assert "test.raising" in str(caught.value)
    assert caught.value.__cause__ is None


def test_a_span_beyond_the_text_aborts_detection() -> None:
    fixed = FixedDetector(
        "test.fixed", frozenset({SECRET}), [span(SECRET, "jwt", 0, 500, Confidence.HIGH)]
    )
    with pytest.raises(RedactionError):
        run("short", DetectorRegistry([fixed]))


def test_a_span_of_an_undeclared_kind_aborts_detection() -> None:
    fixed = FixedDetector(
        "test.fixed", frozenset({PII}), [span(SECRET, "jwt", 0, 3, Confidence.HIGH)]
    )
    with pytest.raises(RedactionError):
        run("abcdef", DetectorRegistry([fixed]))


def test_a_detector_that_returns_something_else_aborts_detection() -> None:
    class Junk:
        id = "test.junk"
        kinds = frozenset({SECRET})

        def detect(self, text: RawCode, *, path: str, language: Language) -> list[object]:
            return ["not a span"]

    with pytest.raises(RedactionError):
        run("abc", DetectorRegistry([Junk()]))  # type: ignore[list-item]


def test_no_detectors_means_no_spans_not_an_error() -> None:
    assert run("anything", DetectorRegistry()) == ()
