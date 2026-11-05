"""Each false-positive filter of the PII detectors fails when it is removed."""

import pytest

from codekavach.core.models import Language, RawCode
from codekavach.privacy.detect.pii.checksums import verhoeff
from codekavach.privacy.detect.pii.filters import (
    PII_FILTER_NAMES,
    PII_FILTERS,
    PiiFilterContext,
    Verdict,
    first_match,
)
from codekavach.privacy.detect.pii.formats import PII_FORMATS, PiiDetector
from tests.support.synthetic import synthetic_value


def run(
    subtype: str, text: str, path: str = "src/app.py", disabled: tuple[str, ...] = ()
) -> list[tuple[str, bool, str]]:
    pii_format = next(item for item in PII_FORMATS if item.subtype == subtype)
    data = text.encode()
    spans = PiiDetector(pii_format, disabled_filters=disabled).detect(
        RawCode(text), path=path, language=Language.PYTHON
    )
    return [
        (s.confidence.value, s.downgraded, data[s.start_byte : s.end_byte].decode()) for s in spans
    ]


def verhoeff_valid(prefix: str, width: int = 12) -> str:
    """The first digit string that starts with ``prefix`` and passes Verhoeff."""
    for tail in range(10 ** (width - len(prefix))):
        candidate = prefix + str(tail).zfill(width - len(prefix))
        if verhoeff(candidate):
            return candidate
    raise AssertionError("no Verhoeff-valid number found")


def periodic_aadhaar() -> str:
    """A Verhoeff-valid 12-digit number made of one 4-digit block repeated three times."""
    for block in range(2000, 10000):
        candidate = str(block) * 3
        if verhoeff(candidate) and len(set(candidate)) > 2:
            return candidate
    raise AssertionError("no periodic number found")


def a_timestamp() -> str:
    """A Verhoeff-valid ``YYYYMMDDHHMM`` (the first one in January 2024)."""
    for day in range(1, 29):
        for hour in range(24):
            for minute in range(60):
                candidate = f"202401{day:02d}{hour:02d}{minute:02d}"
                if verhoeff(candidate):
                    return candidate
    raise AssertionError("no timestamp found")


def test_every_filter_is_named_and_the_names_are_unique() -> None:
    assert len(PII_FILTER_NAMES) == len(PII_FILTERS) == 6
    assert {
        "timestamp_like", "version_like", "fixture_sequence", "reserved_address",
        "example_email_domain", "card_test_number",
    } == PII_FILTER_NAMES  # fmt: skip


def test_timestamp_like() -> None:
    stamp = a_timestamp()
    assert verhoeff(stamp)
    assert run("aadhaar_number", f'created = "{stamp}"') == []
    assert [
        v for _, _, v in run("aadhaar_number", f'created = "{stamp}"', disabled=("timestamp_like",))
    ] == [stamp]


def test_a_number_that_is_not_a_timestamp_is_kept() -> None:
    value = synthetic_value("pii", "aadhaar_number")
    assert [v for _, _, v in run("aadhaar_number", f'a = "{value}"')] == [value]


def test_version_like() -> None:
    value = synthetic_value("pii", "aadhaar_number")
    for context in ("version", "build", "release", "rev", "Version:", "build ="):
        assert run("aadhaar_number", f"{context} {value}") == [], context
        assert run("aadhaar_number", f"{context} {value}", disabled=("version_like",)), context
    assert run("aadhaar_number", f"aadhaar {value}")  # a different word is not a version


def test_fixture_sequence_applies_only_in_example_paths() -> None:
    value = periodic_aadhaar()
    text = f'account = "{value}"'
    for path in ("tests/data/accounts.py", "src/fixtures/a.py", "docs/examples/a.md"):
        assert run("aadhaar_number", text, path) == [], path
        assert run("aadhaar_number", text, path, disabled=("fixture_sequence",)), path
    assert run("aadhaar_number", text, "src/accounts.py")  # production code keeps it


def test_fixture_sequence_covers_mobile_numbers_and_spares_other_digits() -> None:
    assert run("indian_mobile", 'm = "9812398123"', "tests/a.py") == []
    assert run("indian_mobile", 'm = "9812398123"', "tests/a.py", disabled=("fixture_sequence",))
    assert run("indian_mobile", 'm = "9812345678"', "tests/a.py")


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",  # noqa: S104 - the literal the filter is about
        "127.0.0.1",
        "192.0.2.17",  # TEST-NET-1
        "198.51.100.4",  # TEST-NET-2
        "203.0.113.200",  # TEST-NET-3
    ],
)
def test_reserved_ipv4_addresses_are_dropped(address: str) -> None:
    assert run("ipv4", f'h = "{address}"') == []
    assert [v for _, _, v in run("ipv4", f'h = "{address}"', disabled=("reserved_address",))] == [
        address
    ]


def test_reserved_ipv6_documentation_addresses_are_dropped() -> None:
    assert run("ipv6", 'h = "2001:db8::17"') == []
    assert run("ipv6", 'h = "2001:db8::17"', disabled=("reserved_address",))
    assert run("ipv6", 'h = "fd00:1234:5678::17"')


def test_other_addresses_are_kept() -> None:
    for address in ("10.24.8.17", "8.8.4.4", "192.0.3.1", "127.0.0.2"):
        assert [v for _, _, v in run("ipv4", f'h = "{address}"')] == [address]


@pytest.mark.parametrize("address", ["a@example.com", "A.B@Example.ORG", "ops@localhost"])
def test_example_email_domains_are_dropped(address: str) -> None:
    assert run("email", f"to = '{address}'") == []
    assert [
        v for _, _, v in run("email", f"to = '{address}'", disabled=("example_email_domain",))
    ] == [address]


def test_other_email_domains_are_kept() -> None:
    for address in ("a@example.test", "a@notexample.com", "a@bank.example.com"):
        assert [v for _, _, v in run("email", f"to = '{address}'")] == [address]


def test_a_vendor_test_card_is_reported_at_low_confidence_not_dropped() -> None:
    value = synthetic_value("pii", "credit_card", 0)  # 4111 1111 1111 1111
    assert run("credit_card", f'c = "{value}"') == [("low", True, value)]
    assert run("credit_card", f'c = "{value}"', disabled=("card_test_number",)) == [
        ("high", False, value)
    ]
    other = synthetic_value("pii", "credit_card", 1)
    assert run("credit_card", f'c = "{other}"') == [("high", False, other)]


def test_unknown_names_are_refused_and_context_is_per_subtype() -> None:
    context = PiiFilterContext(path="a.py", subtype="email", before="", after="")
    with pytest.raises(ValueError, match="unknown filter"):
        first_match("a@example.com", context, frozenset({"nope"}))
    assert first_match("a@example.com", context) is not None
    other = PiiFilterContext(path="a.py", subtype="iban", before="", after="")
    assert first_match("a@example.com", other) is None  # a filter only sees its own subtypes


def test_every_filter_has_a_verdict() -> None:
    assert {rule.name: rule.verdict for rule in PII_FILTERS}[
        "card_test_number"
    ] is Verdict.DOWNGRADE
    assert all(
        rule.verdict is Verdict.DROP for rule in PII_FILTERS if rule.name != "card_test_number"
    )
