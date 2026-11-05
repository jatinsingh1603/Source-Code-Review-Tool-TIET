"""The personal-data formats: positive and near miss each, the locales, the Aadhaar property."""

from itertools import pairwise

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode
from codekavach.privacy.detect.pii import formats
from codekavach.privacy.detect.pii.builtin import pii_detectors, register_pii_detectors
from codekavach.privacy.detect.pii.checksums import luhn, verhoeff
from codekavach.privacy.detect.pii.filters import PII_FILTER_NAMES
from codekavach.privacy.detect.pii.formats import (
    PII_FORMATS,
    PiiDetector,
    PiiFormat,
    UnknownLocale,
    format_subtypes,
    formats_for,
    normalise_locales,
    valid_aadhaar,
    valid_date_of_birth,
    valid_indian_mobile,
)
from codekavach.privacy.detect.registry import DetectorRegistry
from codekavach.privacy.detect.runner import detect_all
from codekavach.privacy.detect.vocabulary import PII_SUBTYPES
from tests.support.synthetic import synthetic_value

ALL_LOCALES = ("intl", "in", "passport")


def sv(subtype: str, index: int = 0) -> str:
    return synthetic_value("pii", subtype, index)


def format_of(subtype: str) -> PiiFormat:
    return next(item for item in PII_FORMATS if item.subtype == subtype)


def found(
    text: str, subtype: str, *, path: str = "src/app.py", **options: object
) -> list[tuple[str, bool, str]]:
    """``(confidence, downgraded, value)`` for each span of ``subtype``'s detector in ``text``."""
    detector = PiiDetector(format_of(subtype), **options)  # type: ignore[arg-type]
    data = text.encode()
    spans = detector.detect(RawCode(text), path=path, language=Language.PYTHON)
    return [
        (s.confidence.value, s.downgraded, data[s.start_byte : s.end_byte].decode()) for s in spans
    ]


# subtype -> (text around the value, index of the synthetic value, expected confidence)
POSITIVES = {
    "aadhaar_number": ('"aadhaar": "{}"', 0, "high"),
    "pan_number": ('"pan": "{}"', 0, "high"),
    "ifsc_code": ("ifsc = '{}'", 0, "medium"),
    "upi_id": ('"upi": "{}"', 0, "medium"),
    "indian_mobile": ('"mobile": "{}"', 1, "medium"),
    "gstin": ("gstin = '{}'", 0, "high"),
    "email": ("owner = '{}'", 0, "high"),
    "phone_intl": ("call {}", 0, "medium"),
    "credit_card": ("card = '{}'", 1, "high"),
    "iban": ("iban = '{}'", 0, "high"),
    "ipv4": ("host = '{}'", 1, "medium"),
    "ipv6": ("host = '{}'", 1, "medium"),
    "mac_address": ("mac = '{}'", 0, "medium"),
    "date_of_birth": ("dob = '{}'", 0, "medium"),
    "passport_number": ("passport_no = '{}'", 0, "low"),
}


def test_every_vocabulary_subtype_has_a_format_a_positive_and_a_near_miss() -> None:
    assert format_subtypes() == PII_SUBTYPES
    assert set(POSITIVES) == PII_SUBTYPES
    assert set(NEAR_MISSES) == PII_SUBTYPES


@pytest.mark.parametrize("subtype", sorted(POSITIVES))
def test_the_synthetic_value_is_found_whole_with_its_confidence(subtype: str) -> None:
    template, index, confidence = POSITIVES[subtype]
    value = sv(subtype, index)
    assert found(template.format(value), subtype) == [(confidence, False, value)]


def _card_with_prefix(prefix: str) -> str:
    body = prefix + "9" * (15 - len(prefix))
    return body + next(str(d) for d in range(10) if luhn(body + str(d)))


def _valid_aadhaar_with_leading(first: str) -> str:
    body = first + "3412341234"
    return body + next(str(d) for d in range(10) if verhoeff(body + str(d)))


# subtype -> a text with the right shape that its check or structure rejects
NEAR_MISSES = {
    "aadhaar_number": 'x = "234123412347"',  # fails Verhoeff (the corpus case of the issue)
    "pan_number": 'pan = "ABCXD1234K"',  # 4th character is not a holder type
    "ifsc_code": 'ifsc = "WXYZ1123456"',  # fifth character is not 0
    "upi_id": 'upi = "r@examplebank"',  # one-character local part
    "indian_mobile": 'm = "5812345678"',  # starts with 5
    "gstin": 'g = "27ABCPD1234K1Z2"',  # wrong check character
    "email": 'e = "user@.com"',
    "phone_intl": 'p = "+2101234567"',  # +210 is not an assigned calling code
    "credit_card": 'c = "4999 9999 9999 9997"',  # fails Luhn
    "iban": 'i = "GB82WEST12345698765433"',  # fails mod 97
    "ipv4": 'h = "256.1.1.1"',
    "ipv6": 'h = "12:30:45"',  # a time, not an address
    "mac_address": 'm = "00:00:5e:00:53"',  # five groups
    "date_of_birth": 'created_at = "1990-05-14"',  # a date, but not near a birth identifier
    "passport_number": 'ticket = "K1234567"',  # no passport identifier
}


@pytest.mark.parametrize("subtype", sorted(NEAR_MISSES))
def test_a_near_miss_produces_no_span(subtype: str) -> None:
    assert found(NEAR_MISSES[subtype], subtype) == []


@pytest.mark.parametrize(
    "text",
    [
        f'x = "{_valid_aadhaar_with_leading("1")}"',  # leading 1
        f'x = "{_valid_aadhaar_with_leading("0")}"',  # leading 0
    ],
)
def test_an_aadhaar_with_a_leading_zero_or_one_is_rejected_even_when_the_checksum_passes(
    text: str,
) -> None:
    assert verhoeff(text.split('"')[1])
    assert found(text, "aadhaar_number") == []


def test_all_same_and_sequential_digits_are_rejected_even_if_the_checksum_would_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(formats, "verhoeff", lambda digits: True)
    assert not valid_aadhaar("222222222222")
    assert not valid_aadhaar("234567890123")  # each digit one more than the last
    assert not valid_aadhaar("987654321098")  # each digit one fewer
    assert valid_aadhaar("234123412346")


def test_the_worked_example_of_the_issue_yields_four_spans() -> None:
    text = (
        '{"pan": "ABCPD1234K", "aadhaar": "234123412346", '
        '"upi": "ravi@examplebank", "mobile": "+919812345678"}'
    )
    detectors = register_pii_detectors(DetectorRegistry(), ["in"])
    spans = detect_all(
        RawCode(text),
        path="customers.json",
        language=Language.JSON,
        settings=Settings(),
        registry=detectors,
    )
    data = text.encode()
    assert [
        (s.subtype, s.confidence.value, data[s.start_byte : s.end_byte].decode())
        for s in sorted(spans, key=lambda s: s.start_byte)
    ] == [
        ("pan_number", "high", "ABCPD1234K"),
        ("aadhaar_number", "high", "234123412346"),
        ("upi_id", "medium", "ravi@examplebank"),
        ("indian_mobile", "medium", "+919812345678"),
    ]


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("+91 98123 45678", True),
        ("+91-9812345678", True),
        ("09812345678", True),
        ("6000000001", True),
        ("98123 45678", True),
        ("5812345678", False),
        ("981234567", False),
        ("+9198123456", False),
    ],
)
def test_indian_mobile_validator(value: str, ok: bool) -> None:
    assert valid_indian_mobile(value) is ok


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("1990-05-14", True),
        ("14/05/1990", True),
        ("05/14/1990", True),  # month first
        ("14.05.1990", True),
        ("1990/05/14", True),
        ("31/02/1990", False),  # no such day
        ("1800-01-01", False),
        ("1990-13-01", False),
    ],
)
def test_date_of_birth_validator(value: str, ok: bool) -> None:
    assert valid_date_of_birth(value) is ok


def test_a_date_of_birth_needs_a_birth_identifier_among_the_subtokens() -> None:
    for name in ("dob", "birthDate", "date_of_birth", "BIRTHDAY", "customer.birth"):
        assert found(f'{name} = "1990-05-14"', "date_of_birth") == [("medium", False, "1990-05-14")]
    assert found('"dob": "14/05/1990"', "date_of_birth") == [("medium", False, "14/05/1990")]
    assert found('dobbing = "1990-05-14"', "date_of_birth") == []  # one subtoken, not "dob"
    assert found('issued = "1990-05-14"', "date_of_birth") == []


def test_the_span_of_a_dated_value_covers_the_date_only() -> None:
    text = 'dob = "1990-05-14"'
    (detected,) = PiiDetector(format_of("date_of_birth")).detect(
        RawCode(text), path="a.py", language=Language.PYTHON
    )
    assert text.encode()[detected.start_byte : detected.end_byte] == b"1990-05-14"


def test_offsets_are_utf8_bytes() -> None:
    value = sv("pan_number")
    text = f'café = "日本"  # \U0001f600\npan = "{value}"'
    (span,) = PiiDetector(format_of("pan_number")).detect(
        RawCode(text), path="a.py", language=Language.PYTHON
    )
    assert text.encode()[span.start_byte : span.end_byte].decode() == value


# --- locales --------------------------------------------------------------------------------

INDIAN = {"aadhaar_number", "pan_number", "ifsc_code", "upi_id", "indian_mobile", "gstin"}
INTERNATIONAL = {
    "email", "phone_intl", "credit_card", "iban", "ipv4", "ipv6", "mac_address", "date_of_birth",
}  # fmt: skip


def subtypes(locales: list[str]) -> set[str]:
    return {item.subtype for item in formats_for(locales)}


def test_intl_enables_the_international_set_and_in_the_indian_set() -> None:
    assert subtypes(["intl"]) == INTERNATIONAL
    assert subtypes(["in"]) == INDIAN
    assert subtypes(["intl", "in"]) == INTERNATIONAL | INDIAN
    assert subtypes([]) == set()


def test_the_passport_detector_is_off_unless_the_locale_list_asks_for_it() -> None:
    assert "passport_number" not in subtypes(["intl", "in"])
    assert subtypes(["passport"]) == {"passport_number"}
    assert "passport_number" in subtypes(list(ALL_LOCALES))


def test_the_default_locales_leave_passport_off() -> None:
    default = Settings().privacy.pii_locales
    assert default == ["intl", "in"]
    assert {d.format.subtype for d in pii_detectors(default)} == INDIAN | INTERNATIONAL


def test_an_unknown_locale_is_an_error_not_a_silent_no_op() -> None:
    with pytest.raises(UnknownLocale, match="eu"):
        normalise_locales(["intl", "eu"])
    with pytest.raises(UnknownLocale):
        formats_for(["IN"])
    with pytest.raises(UnknownLocale):
        pii_detectors(["us"])


def test_a_disabled_locale_finds_nothing() -> None:
    text = f'a = "{sv("pan_number")}"; e = "{sv("email")}"'
    registry = register_pii_detectors(DetectorRegistry(), ["intl"])
    spans = detect_all(
        RawCode(text),
        path="a.py",
        language=Language.PYTHON,
        settings=Settings(),
        registry=registry,
    )
    assert {s.subtype for s in spans} == {"email"}


def test_detectors_have_pii_ids_and_the_pii_kind() -> None:
    for detector in pii_detectors(ALL_LOCALES):
        assert detector.id == f"pii.{detector.format.subtype}"
        assert detector.kinds == frozenset({PlaceholderKind.PII})
    assert len(pii_detectors(ALL_LOCALES)) == len(PII_SUBTYPES)


def test_a_detector_refuses_an_unknown_filter_name() -> None:
    with pytest.raises(ValueError, match="unknown filter"):
        PiiDetector(format_of("email"), disabled_filters=["no_such_filter"])
    PiiDetector(format_of("email"), disabled_filters=PII_FILTER_NAMES)


def test_reprs_hold_no_value() -> None:
    value = sv("pan_number")
    detector = PiiDetector(format_of("pan_number"))
    (span,) = detector.detect(RawCode(f'p = "{value}"'), path="a.py", language=Language.PYTHON)
    assert value not in repr(detector)
    assert value not in repr(span)


def test_every_pattern_compiles_through_safe_compile() -> None:
    for item in PII_FORMATS:
        assert item.compiled().pattern == item.regex
        assert item.confidence in {Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW}


# --- the Aadhaar property -------------------------------------------------------------------


@given(st.text(alphabet="0123456789", min_size=12, max_size=12))
def test_property_the_aadhaar_detector_fires_iff_verhoeff_passes_and_the_leading_digit_is_2_to_9(
    digits: str,
) -> None:
    """With the filters off, the only other rule is the all-same / sequential rejection."""
    fires = bool(found(f'x = "{digits}"', "aadhaar_number", disabled_filters=PII_FILTER_NAMES))
    expected = verhoeff(digits) and digits[0] in "23456789" and not _is_run_like(digits)
    assert fires is expected


def _is_run_like(digits: str) -> bool:
    if len(set(digits)) == 1:
        return True
    steps = {(int(b) - int(a)) % 10 for a, b in pairwise(digits)}
    return steps in ({1}, {9})


def test_an_unknown_locale_in_the_settings_fails_at_load_time() -> None:
    with pytest.raises(ValidationError, match="unknown locale"):
        Settings.model_validate({"privacy": {"pii_locales": ["intl", "eu"]}})
    with pytest.raises(ValidationError, match="locale"):
        Settings.model_validate({"privacy": {"pii_locales": ["IN"]}})
    accepted = Settings.model_validate({"privacy": {"pii_locales": ["in", "passport"]}})
    assert accepted.privacy.pii_locales == ["in", "passport"]
