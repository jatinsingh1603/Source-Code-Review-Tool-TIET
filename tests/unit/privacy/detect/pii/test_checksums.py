"""Verhoeff, Luhn, IBAN mod 97 and GSTIN against published or constructed vectors."""

import doctest

import pytest

from codekavach.privacy.detect.pii import checksums
from codekavach.privacy.detect.pii.checksums import (
    gstin_check,
    gstin_check_character,
    iban_mod97,
    luhn,
    verhoeff,
)


def test_the_docstring_examples_run() -> None:
    assert doctest.testmod(checksums).failed == 0


@pytest.mark.parametrize(
    ("digits", "ok"),
    [
        ("2363", True),  # the published worked example: 236 has check digit 3
        ("123451", True),
        ("758722", True),
        ("234123412346", True),  # the constructed Aadhaar-shaped number of the issue
        ("2364", False),
        ("123450", False),
        ("758721", False),
        ("234123412347", False),
        ("2363 ", False),
        ("23a3", False),
        ("", False),
        ("٢٣٦٣", False),  # Arabic-Indic digits are not digits here
    ],
)
def test_verhoeff(digits: str, ok: bool) -> None:
    assert verhoeff(digits) is ok


def test_verhoeff_detects_every_single_digit_error_and_adjacent_transposition() -> None:
    valid = "234123412346"
    for position in range(len(valid)):
        for replacement in "0123456789":
            if replacement != valid[position]:
                changed = valid[:position] + replacement + valid[position + 1 :]
                assert not verhoeff(changed)
    for position in range(len(valid) - 1):
        if valid[position] != valid[position + 1]:
            swapped = (
                valid[:position] + valid[position + 1] + valid[position] + valid[position + 2 :]
            )
            assert not verhoeff(swapped)


@pytest.mark.parametrize(
    ("digits", "ok"),
    [
        ("79927398713", True),  # the example in the algorithm's description
        ("4111111111111111", True),  # a payment-gateway test number
        ("378282246310005", True),
        ("79927398710", False),
        ("4111111111111112", False),
        ("0", False),
        ("", False),
        ("4111 1111", False),
    ],
)
def test_luhn(digits: str, ok: bool) -> None:
    assert luhn(digits) is ok


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("GB82WEST12345698765432", True),  # the IBAN standard's own examples
        ("GB82 WEST 1234 5698 7654 32", True),
        ("DE89370400440532013000", True),
        ("gb82west12345698765432", True),
        ("GB82WEST12345698765433", False),
        ("DE89370400440532013001", False),  # pragma: allowlist secret
        ("GB82", False),
        ("GB82WEST1234569876543!", False),
        ("", False),
    ],
)
def test_iban_mod97(value: str, ok: bool) -> None:
    assert iban_mod97(value) is ok


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("27AAPFU0939F1ZV", True),  # the sample GSTIN that GST guidance circulates
        ("27AAPFU0939F1ZW", False),
        ("27AAPFU0939F1Z", False),  # 14 characters
        ("27AAPFU0939F1ZVV", False),  # 16 characters
        ("27aapfu0939f1zv", False),  # the check is over upper-case base 36
        ("", False),
    ],
)
def test_gstin_check(value: str, ok: bool) -> None:
    assert gstin_check(value) is ok


def test_gstin_check_character_is_defined_for_fourteen_base36_characters_only() -> None:
    assert gstin_check_character("27AAPFU0939F1Z") == "V"
    assert gstin_check_character("27AAPFU0939F1") is None
    assert gstin_check_character("27AAPFU0939F1!") is None
