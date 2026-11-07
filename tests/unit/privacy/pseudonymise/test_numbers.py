"""Unit tests for ``generalise_number`` (E09-03): the keep-list, the coarsening table and the worked
examples of the issue."""

import pytest

from codekavach.privacy.pseudonymise.numbers import NumberContext, NumberSite, generalise_number

COMPARISON = NumberSite.COMPARISON
ARG = NumberSite.PUBLIC_ARGUMENT
CONST = NumberSite.CONSTANT_ASSIGNMENT
INDEX = NumberSite.INDEX
OTHER = NumberSite.OTHER


@pytest.mark.parametrize(
    ("value", "site", "name"),
    [
        ("5432", CONST, "PORT"),
        ("0o777", ARG, "chmod"),
        ("2048", CONST, "KEY_SIZE"),
        ("3", COMPARISON, "attempts"),
        ("30", COMPARISON, "timeout_seconds"),
        ("10", COMPARISON, "rounds"),
        ("404", COMPARISON, "status_code"),
        ("7", INDEX, None),
        ("1024", COMPARISON, "buf_len"),
        ("256", COMPARISON, "keysize"),
        ("0", OTHER, None),
        ("1", OTHER, None),
        ("0.0", OTHER, None),
        ("1.0", OTHER, None),
    ],
)
def test_security_relevant_numbers_are_kept(value: str, site: NumberSite, name: str | None) -> None:
    assert generalise_number(value, NumberContext(site, name)) == value


@pytest.mark.parametrize(
    ("value", "site", "name", "expected"),
    [
        ("250000", OTHER, None, "100000"),
        ("0.0725", OTHER, None, "0.01"),
        ("250000", CONST, "festival_bonus_cap", "100000"),
        ("250000", COMPARISON, "balance", "100000"),
        ("250000", COMPARISON, "max_price", "100000"),
        ("3", OTHER, None, "1"),
        ("-4500", OTHER, None, "-1000"),
        ("5432", COMPARISON, "balance", "1000"),
        ("5432", ARG, "sleep", "1000"),
        ("1e6", OTHER, None, "1000000"),
        ("0x1F", OTHER, None, "10"),
        ("12.5", OTHER, None, "10"),
        ("250000L", OTHER, None, "100000"),
        ("100", INDEX, None, "100"),
        ("16", INDEX, None, "10"),
        ("1234", INDEX, None, "1000"),
        ("98765", INDEX, None, "10000"),
        ("not-a-number", OTHER, None, "0"),
    ],
)
def test_other_numbers_are_coarsened_to_their_magnitude(
    value: str, site: NumberSite, name: str | None, expected: str
) -> None:
    assert generalise_number(value, NumberContext(site, name)) == expected


def test_zero_and_one_are_kept_at_every_site() -> None:
    for site in NumberSite:
        assert generalise_number("0", NumberContext(site)) == "0"
        assert generalise_number("1", NumberContext(site)) == "1"


def test_default_context_coarsens() -> None:
    assert generalise_number("250000", NumberContext()) == "100000"


def test_the_issue_worked_examples() -> None:
    assert generalise_number("3", NumberContext(COMPARISON, "attempts")) == "3"
    assert generalise_number("2048", NumberContext(CONST, "KEY_SIZE")) == "2048"
    assert generalise_number("5432", NumberContext(CONST, "PORT")) == "5432"
    assert generalise_number("0o777", NumberContext(ARG, "chmod")) == "0o777"
    assert generalise_number("0.0725", NumberContext(CONST, "interest_rate")) == "0.01"
    assert generalise_number("250000", NumberContext(CONST, "festival_bonus_cap")) == "100000"
