"""The detector prefilters never hide a value (E12-02b, invariant I4's recall side).

Every claim of ``Needs`` and of ``AssignmentDetector.may_match`` is *necessary*: where the pattern
matches, the prefilter says it may. Three checks hold that down. The patterns themselves are
checked against the prefilter on generated text (a match with ``may_match`` false is a leak). The
whole detection is compared with and without prefiltering on every detector-corpus file and on
generated text. And the runner's handling of a prefilter that says no, or that raises, is checked
with a spy.
"""

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.pii.builtin import pii_detectors
from codekavach.privacy.detect.pii.formats import NEEDS, PII_FORMATS, PiiDetector
from codekavach.privacy.detect.prefilter import Needs, TextFacts
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_with_report
from codekavach.privacy.detect.secrets.assignment import AssignmentDetector, is_credential_name
from codekavach.privacy.detect.secrets.builtin import register_secret_detectors
from tests.support.corpus import CORPUS_ROOT

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "detect"
SAMPLES = [
    "user@example.com",  # pragma: allowlist secret
    "ravi.k@okaxis",  # pragma: allowlist secret
    "192.168.10.200",  # pragma: allowlist secret
    "4111 1111 1111 1111",  # pragma: allowlist secret
    "ABCDE1234F",  # pragma: allowlist secret
    "9876543210",  # pragma: allowlist secret
    "98765 43210",  # pragma: allowlist secret
    "+14155552671",  # pragma: allowlist secret
    "GB82WEST12345698765432",  # pragma: allowlist secret
    "aa:bb:cc:dd:ee:ff",  # pragma: allowlist secret
    "2001:db8::1",  # pragma: allowlist secret
    "fe80::1ff:fe23:4567:890a",  # pragma: allowlist secret
    "dob = '1990-01-31'",  # pragma: allowlist secret
    "date_of_birth: 31/01/1990",  # pragma: allowlist secret
    "passport = 'A1234567'",  # pragma: allowlist secret
    'password = "hunter2hunter2"',  # pragma: allowlist secret
    "api_key = 'abcd1234efgh5678'",  # pragma: allowlist secret
    'apiKey: "abcd1234efgh5678"',  # pragma: allowlist secret
    "SIGNING_KEY=abcdefgh12345678",  # pragma: allowlist secret
    "authToken => 'zzzzzzzzzz'",  # pragma: allowlist secret
    "29AABCT1332L1ZV",  # pragma: allowlist secret
    "HDFC0001234",  # pragma: allowlist secret
    "1234 5678 9012",  # pragma: allowlist secret
    "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
    "0x1F",  # pragma: allowlist secret
    "v1.2.3.4",  # pragma: allowlist secret
    "a=b",  # pragma: allowlist secret
    "x: y",  # pragma: allowlist secret
    '"',  # pragma: allowlist secret
    "'",  # pragma: allowlist secret
    "\n",  # pragma: allowlist secret
    " ",  # pragma: allowlist secret
    "+",  # pragma: allowlist secret
    "@",  # pragma: allowlist secret
    ":",  # pragma: allowlist secret
    "-",  # pragma: allowlist secret
    "0",  # pragma: allowlist secret
    "7",  # pragma: allowlist secret
    "é",  # pragma: allowlist secret
    "İ",  # pragma: allowlist secret
]
TEXTS = st.lists(
    st.one_of(
        st.sampled_from(SAMPLES), st.text(max_size=12), st.from_regex(r"[0-9A-Za-z:.@+\- ]{0,20}")
    ),
    max_size=14,
).map("".join)
RELAXED = settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


def registry() -> DetectorRegistry:
    built = register_secret_detectors(DetectorRegistry())
    for detector in pii_detectors(("intl", "in", "passport")):
        built.register(detector)
    return built


def key(span: TypedSpan) -> tuple[object, ...]:
    return (span.kind, span.subtype, span.start_byte, span.end_byte, span.confidence, span.detector)


def both(text: str) -> tuple[tuple[object, ...], tuple[object, ...], object, object]:
    args = {
        "path": "a.txt",
        "language": Language.UNKNOWN,
        "settings": Settings(),
        "registry": registry(),
    }
    on, report_on = detect_with_report(RawCode(text), prefilter=True, **args)  # type: ignore[arg-type]
    off, report_off = detect_with_report(RawCode(text), prefilter=False, **args)  # type: ignore[arg-type]
    return tuple(map(key, on)), tuple(map(key, off)), report_on, report_off


def corpus_files() -> list[Path]:
    roots = [CORPUS_ROOT, FIXTURES / "secrets"]
    return sorted(p for root in roots for p in root.rglob("*.txt") if p.is_file())


# --- the patterns -----------------------------------------------------------------------------


def test_every_pii_format_declares_what_it_needs() -> None:
    assert set(NEEDS) == {item.subtype for item in PII_FORMATS}


@pytest.mark.parametrize("item", PII_FORMATS, ids=lambda item: item.subtype)
@given(text=TEXTS)
@RELAXED
def test_where_a_pii_pattern_matches_its_prefilter_says_so(item: object, text: str) -> None:
    pii_format = item
    if pii_format.compiled().search(text):  # type: ignore[attr-defined]
        assert PiiDetector(pii_format).may_match(TextFacts(text))  # type: ignore[arg-type]


@given(text=TEXTS)
@RELAXED
def test_where_a_credential_name_is_assigned_the_assignment_prefilter_says_so(text: str) -> None:
    detector = AssignmentDetector()
    if detector.detect(RawCode(text), path="a.py", language=Language.PYTHON):
        assert detector.may_match(TextFacts(text))


@pytest.mark.parametrize(
    "name",
    ["password", "dbPassword", "PWD", "client-secret", "apiKey", "API_KEY", "access_key",
     "privateKey", "session-key", "SIGNING_KEY", "authToken", "credential", "passwd", "apikey"],
)  # fmt: skip
def test_every_credential_name_style_passes_the_assignment_prefilter(name: str) -> None:
    assert is_credential_name(name)
    assert AssignmentDetector().may_match(TextFacts(f'x = {name} + "{name}"'))


def test_text_without_a_credential_word_is_skipped_by_the_assignment_prefilter() -> None:
    assert not AssignmentDetector().may_match(TextFacts("def total(a, b):\n    return a + b\n"))


def test_an_empty_needs_always_holds_and_each_condition_can_fail() -> None:
    assert Needs().met(TextFacts(""))
    assert not Needs(chars=("@",)).met(TextFacts("none"))
    assert not Needs(words=("dob",)).met(TextFacts("none"))
    assert not Needs(core=r"\d{4}").met(TextFacts("a1b2c3"))
    assert Needs(chars=("@",), words=("dob",), core=r"\d").met(TextFacts("DOB 1 @"))


# --- the whole detection ----------------------------------------------------------------------


@pytest.mark.parametrize("path", corpus_files(), ids=lambda path: path.name)
def test_detection_is_identical_with_and_without_prefiltering_on_the_corpus(path: Path) -> None:
    on, off, report_on, report_off = both(path.read_text(encoding="utf-8"))
    assert on == off
    assert report_on == report_off  # the counts, too: a skipped detector reports zero


@given(text=TEXTS)
@RELAXED
def test_detection_is_identical_with_and_without_prefiltering_on_generated_text(text: str) -> None:
    on, off, report_on, report_off = both(text)
    assert on == off
    assert report_on == report_off


# --- the runner -------------------------------------------------------------------------------


class Spy:
    kinds = frozenset({PlaceholderKind.SECRET})

    def __init__(self, identifier: str, answer: object) -> None:
        self.id = identifier
        self.answer = answer
        self.calls = 0

    def may_match(self, facts: TextFacts) -> object:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def detect(self, text: RawCode, *, path: str, language: Language) -> list[TypedSpan]:
        self.calls += 1
        return [
            TypedSpan(
                kind=PlaceholderKind.SECRET,
                subtype="generic_credential",
                start_byte=0,
                end_byte=1,
                confidence=Confidence.HIGH,
                detector=self.id,
            )
        ]


def run(spy: Spy, *, prefilter: bool = True) -> tuple[int, int]:
    _, report = detect_with_report(
        RawCode("abc"),
        path="a.txt",
        language=Language.UNKNOWN,
        settings=Settings(),
        registry=DetectorRegistry([spy]),
        prefilter=prefilter,
    )
    return spy.calls, dict(report.per_detector)[spy.id]


def test_a_detector_whose_prefilter_says_no_is_not_run_and_reports_zero() -> None:
    assert run(Spy("spy.no", False)) == (0, 0)


def test_a_detector_whose_prefilter_says_yes_is_run() -> None:
    assert run(Spy("spy.yes", True)) == (1, 1)


def test_turning_the_prefilter_off_runs_every_detector() -> None:
    assert run(Spy("spy.off", False), prefilter=False) == (1, 1)


def test_a_prefilter_that_raises_never_hides_the_detector() -> None:
    assert run(Spy("spy.boom", RuntimeError("quotes the text"))) == (1, 1)


def test_only_an_exact_false_skips_a_detector() -> None:
    answers: tuple[object, ...] = (None, 0, "", [])
    for answer in answers:
        assert run(Spy("spy.odd", answer)) == (1, 1)  # a plugin's slip never hides a value
