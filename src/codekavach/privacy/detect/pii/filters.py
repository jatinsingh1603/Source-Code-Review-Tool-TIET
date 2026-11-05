"""False-positive filters for the personal-data detectors, each testable and disableable.

Owning epic: E08.

A filter looks at one candidate that already passed its format's check and says "this is not
personal data" (``DROP``) or "this is documented test data" (``DOWNGRADE``: the span is kept at
``LOW`` and marked ``downgraded``, so the auditor still sees it and the recall-first posture
holds). Every filter has a name; a detector takes ``disabled_filters`` so a test can switch one
off and see the value come back.

Rules:

* ``timestamp_like`` (Aadhaar): twelve digits that read as ``YYYYMMDDHHMM`` or
  ``YYMMDDHHMMSS`` are a timestamp.
* ``version_like`` (Aadhaar): the number follows ``version``, ``build``, ``release`` or ``rev``.
* ``fixture_sequence`` (Aadhaar, Indian mobile): in a test, fixture, example or docs path, digits
  that repeat a short block (``123412341234``) are a made-up account sequence.
* ``reserved_address`` (IPv4, IPv6): ``0.0.0.0``, ``127.0.0.1``, ``::``, ``::1`` and the
  documentation ranges of RFC 5737 and RFC 3849.
* ``example_email_domain`` (email): the domain is ``example.com``, ``example.org`` or ``localhost``.
* ``card_test_number`` (``DOWNGRADE``, credit card): a number the card networks and payment
  gateways publish for testing.

This module performs no network operation.
"""

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from typing import Final

from codekavach.privacy.detect.secrets.filters import Verdict

__all__ = [
    "PII_FILTERS",
    "PII_FILTER_NAMES",
    "PiiFilter",
    "PiiFilterContext",
    "Verdict",
    "first_match",
]

_EXAMPLE_DIRECTORIES: Final = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture", "testdata"}
    | {"example", "examples", "samples", "sample", "docs", "doc"}
)
_VERSION_WORDS: Final = re.compile(
    r"""(?i)(?:version|ver|build|release|rev|revision)[\s:=_"'.\-]*$"""
)
_DOCUMENTATION_V4: Final = tuple(
    ipaddress.ip_network(block) for block in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
_DOCUMENTATION_V6: Final = ipaddress.ip_network("2001:db8::/32")
_EXAMPLE_DOMAINS: Final = frozenset({"example.com", "example.org", "localhost"})

# Numbers the networks and gateways publish for testing (Stripe, PayPal, Braintree and the
# networks' own documentation). They pass Luhn on purpose.
_TEST_CARDS: Final = frozenset(
    (
        "4111111111111111", "4012888888881881", "4222222222222", "4242424242424242",
        "4000056655665556", "5555555555554444", "5105105105105100", "5200828282828210",
        "2223003122003222", "378282246310005", "371449635398431", "378734493671000",
        "6011111111111117", "6011000990139424", "30569309025904", "38520000023237",
        "3530111333300000", "3566002020360505", "3056930009020004", "36227206271667",
        "6200000000000005",
    )
)  # fmt: skip


@dataclass(frozen=True)
class PiiFilterContext:
    """What a filter may look at: the path, the subtype and the text around the value."""

    path: str
    subtype: str
    before: str
    after: str


@dataclass(frozen=True)
class PiiFilter:
    """A named rule for some subtypes: ``applies(value, context)`` says it matches."""

    name: str
    subtypes: frozenset[str]
    verdict: Verdict
    applies: Callable[[str, PiiFilterContext], bool]


def _digits(value: str) -> str:
    return "".join(char for char in value if char.isdigit())


def _is_datetime(year: int, month: int, day: int, hour: int, minute: int) -> bool:
    if not 1970 <= year <= 2100 or hour > 23 or minute > 59:
        return False
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


def _is_timestamp(value: str, _context: PiiFilterContext) -> bool:
    """``YYYYMMDDHHMM`` or ``YYMMDDHHMMSS`` with every field in range."""
    d = _digits(value)
    if len(d) != 12:
        return False
    fields = [int(d[i : i + 2]) for i in range(0, 12, 2)]
    long_year = fields[0] * 100 + fields[1]
    return _is_datetime(long_year, fields[2], fields[3], fields[4], fields[5]) or _is_datetime(
        2000 + fields[0], fields[1], fields[2], fields[3], fields[4]
    )


def _is_version(_value: str, context: PiiFilterContext) -> bool:
    return _VERSION_WORDS.search(context.before) is not None


def _in_example_path(path: str) -> bool:
    return any(part.lower() in _EXAMPLE_DIRECTORIES for part in path.replace("\\", "/").split("/"))


def _is_periodic(digits: str) -> bool:
    return any(
        all(digits[i] == digits[i + period] for i in range(len(digits) - period))
        for period in range(1, len(digits) // 2 + 1)
    )


def _is_fixture_sequence(value: str, context: PiiFilterContext) -> bool:
    return _in_example_path(context.path) and _is_periodic(_digits(value))


def _is_reserved_address(value: str, context: PiiFilterContext) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return str(address) in {"0.0.0.0", "127.0.0.1"} or any(  # noqa: S104 - a literal to skip
            address in block for block in _DOCUMENTATION_V4
        )
    return address in {ipaddress.IPv6Address("::"), ipaddress.IPv6Address("::1")} or (
        address in _DOCUMENTATION_V6
    )


def _is_example_domain(value: str, _context: PiiFilterContext) -> bool:
    return value.rpartition("@")[2].lower() in _EXAMPLE_DOMAINS


def _is_test_card(value: str, _context: PiiFilterContext) -> bool:
    return _digits(value) in _TEST_CARDS


PII_FILTERS: Final[tuple[PiiFilter, ...]] = (
    PiiFilter("timestamp_like", frozenset({"aadhaar_number"}), Verdict.DROP, _is_timestamp),
    PiiFilter("version_like", frozenset({"aadhaar_number"}), Verdict.DROP, _is_version),
    PiiFilter(
        "fixture_sequence",
        frozenset({"aadhaar_number", "indian_mobile"}),
        Verdict.DROP,
        _is_fixture_sequence,
    ),
    PiiFilter("reserved_address", frozenset({"ipv4", "ipv6"}), Verdict.DROP, _is_reserved_address),
    PiiFilter("example_email_domain", frozenset({"email"}), Verdict.DROP, _is_example_domain),
    PiiFilter("card_test_number", frozenset({"credit_card"}), Verdict.DOWNGRADE, _is_test_card),
)
PII_FILTER_NAMES: Final = frozenset(rule.name for rule in PII_FILTERS)


def first_match(
    value: str, context: PiiFilterContext, disabled: frozenset[str] = frozenset()
) -> PiiFilter | None:
    """The first enabled filter for ``context.subtype`` that applies to ``value``, or ``None``.

    Raises:
        ValueError: ``disabled`` names a filter that does not exist.
    """
    unknown = disabled - PII_FILTER_NAMES
    if unknown:
        raise ValueError(f"unknown filter names: {sorted(unknown)}")
    for rule in PII_FILTERS:
        if (
            rule.name not in disabled
            and context.subtype in rule.subtypes
            and rule.applies(value, context)
        ):
            return rule
    return None
