"""Regression guards for I4 and I6 in the redaction framework (E08-01).

Each test fails if the invariant is weakened: if a privacy-step failure returned partial text
instead of raising (I4), or if a value reached an exception message, a ``repr``, a report or the
numbering object (I6). The behavioural detail lives in ``tests/unit/privacy``.
"""

import pytest

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_with_report
from codekavach.privacy.errors import RedactionError
from codekavach.privacy.redact.numbering import PlaceholderNumbering
from codekavach.privacy.redact.redactor import Redactor
from tests.support.fake_detectors import RaisingDetector, ValueDetector
from tests.support.synthetic import AWS_EXAMPLE_ACCESS_KEY_ID

SECRET = PlaceholderKind.SECRET
SALT = ScanSalt.from_hex("44" * 32)  # pragma: allowlist secret
TEXT = f'key = "{AWS_EXAMPLE_ACCESS_KEY_ID}"  # café\n'


def span(start: int, end: int) -> TypedSpan:
    return TypedSpan(
        kind=SECRET,
        subtype="aws_access_key",
        start_byte=start,
        end_byte=end,
        confidence=Confidence.HIGH,
        detector="test.a",
    )


@pytest.mark.privacy
def test_i4_a_failing_detector_aborts_instead_of_returning_the_other_detectors_spans() -> None:
    registry = DetectorRegistry(
        [
            ValueDetector("test.ok", SECRET, "aws_access_key", [AWS_EXAMPLE_ACCESS_KEY_ID]),
            RaisingDetector(),
        ]
    )
    with pytest.raises(RedactionError):
        detect_with_report(
            RawCode(TEXT),
            path="a.py",
            language=Language.PYTHON,
            settings=Settings(),
            registry=registry,
        )


@pytest.mark.privacy
@pytest.mark.parametrize(
    "bad",
    [span(0, 10_000), span(len(TEXT.encode()) - 2, len(TEXT.encode()) - 1), span(5, 5 + 20)],
    ids=["beyond-text", "inside-a-character", "overlap-with-next"],
)
def test_i4_a_bad_span_never_yields_partial_text(bad: TypedSpan) -> None:
    spans = [bad, span(10, 30)] if bad.start_byte == 5 else [bad]
    with pytest.raises(RedactionError):
        Redactor().redact(TEXT, spans, numbering=PlaceholderNumbering(SALT))


@pytest.mark.privacy
def test_i6_no_value_reaches_an_error_a_repr_or_a_report() -> None:
    numbering = PlaceholderNumbering(SALT)
    registry = DetectorRegistry(
        [ValueDetector("test.ok", SECRET, "aws_access_key", [AWS_EXAMPLE_ACCESS_KEY_ID])]
    )
    spans, report = detect_with_report(
        RawCode(TEXT),
        path="a.py",
        language=Language.PYTHON,
        settings=Settings(),
        registry=registry,
    )
    result = Redactor().redact(TEXT, spans, numbering=numbering)
    visible = [repr(numbering), repr(spans), repr(report), report.model_dump_json(), repr(result)]
    assert all(AWS_EXAMPLE_ACCESS_KEY_ID not in text for text in visible)
    assert AWS_EXAMPLE_ACCESS_KEY_ID not in result.text
    with pytest.raises(RedactionError) as caught:
        Redactor().redact(TEXT, [span(0, 10_000)], numbering=numbering)
    assert AWS_EXAMPLE_ACCESS_KEY_ID not in str(caught.value)


@pytest.mark.privacy
def test_i6_the_numbering_cannot_be_built_without_a_scan_salt() -> None:
    with pytest.raises(TypeError):
        PlaceholderNumbering(None)  # type: ignore[arg-type]


@pytest.mark.privacy
def test_i5_the_same_salt_and_input_give_the_same_placeholders() -> None:
    spans = [span(7, 7 + len(AWS_EXAMPLE_ACCESS_KEY_ID))]
    first = Redactor().redact(TEXT, spans, numbering=PlaceholderNumbering(SALT))
    second = Redactor().redact(TEXT, spans, numbering=PlaceholderNumbering(SALT))
    assert first == second
