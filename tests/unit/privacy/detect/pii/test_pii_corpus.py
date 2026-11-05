"""The PII and term corpus cases: the real detectors reproduce their labels, and nothing leaks."""

import json

import pytest

from codekavach.core.models import PlaceholderKind
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.vocabulary import PII_SUBTYPES
from codekavach.privacy.redact.numbering import PlaceholderNumbering
from codekavach.privacy.redact.redactor import Redactor
from tests.support.corpus import CORPUS_ROOT, case_names, load_case
from tests.support.real_detectors import CORPUS_PREFIXES, real_detected, real_resolved

REAL_CASES = [name for name in case_names() if name.startswith(CORPUS_PREFIXES)]


def key(span: TypedSpan) -> tuple[object, ...]:
    return (span.kind, span.subtype, span.start_byte, span.end_byte, span.confidence)


@pytest.mark.parametrize("name", REAL_CASES)
def test_the_real_detectors_reproduce_the_labels_of_the_case(name: str) -> None:
    case = load_case(name)
    assert [key(s) for s in real_detected(case.text)] == [key(s) for s in case.detected]
    assert [key(s) for s in real_resolved(case.text)] == [key(s) for s in case.expected]


def test_every_pii_subtype_has_a_positive_and_a_negative_case() -> None:
    names = set(REAL_CASES)
    for subtype in PII_SUBTYPES:
        assert any(n.startswith(f"pii_{subtype}_positive") for n in names), subtype
        assert f"pii_{subtype}_negative" in names, subtype


def test_every_positive_case_finds_its_subtype_and_every_negative_case_finds_nothing() -> None:
    for name in REAL_CASES:
        expected = load_case(name).expected
        if name.endswith("_negative"):
            assert expected == (), name
        else:
            assert expected, name
        if name.startswith("pii_") and name.endswith("_positive"):
            subtype = name.removeprefix("pii_").removesuffix("_positive")
            assert {s.subtype for s in expected} == {subtype}, name


def test_the_vendor_test_card_is_in_the_corpus_at_low_confidence() -> None:
    (span,) = load_case("pii_credit_card_vendor_test_number").expected
    assert span.confidence.value == "low"


def test_the_aadhaar_shaped_number_that_fails_verhoeff_is_in_the_corpus_and_finds_nothing() -> None:
    case = load_case("pii_aadhaar_number_negative")
    assert case.text == "aadhaar: 234123412347\n"
    assert case.expected == ()


def test_term_cases_cover_each_matching_mode() -> None:
    modes = {"plain_substring", "camel_case", "snake_case", "hyphen", "case_folding", "multibyte"}
    assert {n.removeprefix("terms_").removesuffix("_positive") for n in REAL_CASES} >= modes
    for name in REAL_CASES:
        if name.startswith("terms_") and name.endswith("_positive"):
            assert {s.kind for s in load_case(name).expected} == {PlaceholderKind.TERM}


def test_a_term_label_never_holds_the_term() -> None:
    for name in REAL_CASES:
        text = (CORPUS_ROOT / f"{name}.labels.json").read_text(encoding="utf-8").lower()
        assert "festival" not in text
        assert json.loads(text)["expected"] is not None


def test_the_customers_json_example_redacts_to_the_issue_text() -> None:
    case = load_case("pii_customers_json")
    result = Redactor().redact(
        case.text,
        list(real_resolved(case.text)),
        numbering=PlaceholderNumbering(ScanSalt.generate()),
    )
    assert result.text == (
        '{"pan": "<PII:pan_number:1>", "aadhaar": "<PII:aadhaar_number:1>", '
        '"upi": "<PII:upi_id:1>", "mobile": "<PII:indian_mobile:1>"}\n'
    )
    for value in ("ABCPD1234K", "234123412346", "ravi", "9812345678"):
        assert value not in result.text
