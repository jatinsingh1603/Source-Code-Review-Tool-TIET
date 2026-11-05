"""Personal-data formats and their detector: Indian and international identifiers.

Owning epic: E08.

One :class:`PiiFormat` per subtype says what the value looks like (a regular expression compiled
through ``safe_compile``), which check it must pass (a checksum or a structural validator) and
which locale enables it. :class:`PiiDetector` runs one format and applies the false-positive
filters of ``pii.filters``; ``pii.builtin`` registers one detector per enabled format, so the
detector ids are ``pii.<subtype>``.

Confidence: ``HIGH`` where a checksum or a closed structure confirms the value (Aadhaar with
Verhoeff, PAN with its holder-type letter, GSTIN, cards with Luhn and an issuer prefix, IBAN
with mod 97, email); ``MEDIUM`` where only the shape is known (UPI, Indian mobile, IPv4, IPv6,
MAC, international phone, IFSC, date of birth); ``LOW`` for the passport number. A value that
fails its check produces no span at all.

Locales (``privacy.pii_locales``): ``intl`` enables the international set, ``in`` the Indian
set, and ``passport`` the conservative passport-number detector, which is off unless the list
asks for it. An unknown locale is a configuration error (:class:`UnknownLocale`), never a
silent no-op.

A span carries offsets, never the value. Nothing here opens a connection.
"""

import ipaddress
import re
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date
from functools import cache
from itertools import pairwise
from typing import Final

from codekavach.config.models.privacy import PII_LOCALES
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode, RepoPath
from codekavach.parsing.subtokens import split_subtokens
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.offsets import ByteOffsets
from codekavach.privacy.detect.pii.checksums import gstin_check, iban_mod97, luhn, verhoeff
from codekavach.privacy.detect.pii.filters import (
    PII_FILTER_NAMES,
    PiiFilterContext,
    Verdict,
    first_match,
)
from codekavach.privacy.detect.safe_regex import safe_compile
from codekavach.privacy.detect.vocabulary import PII_SUBTYPES

LOCALE_INTL: Final = "intl"
LOCALE_INDIA: Final = "in"
LOCALE_PASSPORT: Final = "passport"
_CONTEXT_CHARS: Final = 48

Validator = Callable[[str], bool]


class UnknownLocale(ValueError):  # noqa: N818 - a locale is "unknown", not an "error" of a kind
    """A ``privacy.pii_locales`` entry that no format set answers to."""


def normalise_locales(locales: Iterable[str]) -> frozenset[str]:
    """The set of ``locales``.

    Raises:
        UnknownLocale: an entry is not one of :data:`PII_LOCALES`.
    """
    chosen = frozenset(locales)
    unknown = chosen - frozenset(PII_LOCALES)
    if unknown:
        raise UnknownLocale(
            f"unknown pii locale(s) {sorted(unknown)}; the known ones are {list(PII_LOCALES)}"
        )
    return chosen


@dataclass(frozen=True)
class PiiFormat:
    """One personal-data format.

    ``regex`` finds candidates; ``validator`` (when given) receives the value and must accept
    it. ``value_group`` names the group that is the value (the whole match by default), and
    ``name_words`` (when given) requires the identifier in the ``name`` group to have one of
    these subtokens, which is how a date of birth is told from any other date.
    """

    subtype: str
    regex: str
    validator: Validator | None
    locales: frozenset[str]
    confidence: Confidence
    value_group: str | int = 0
    name_words: frozenset[str] = field(default_factory=frozenset)
    flags: int = 0

    def compiled(self) -> re.Pattern[str]:
        """The pattern, compiled through ``safe_compile`` (cached)."""
        return _compile(self.regex, self.flags)


@cache
def _compile(regex: str, flags: int) -> re.Pattern[str]:
    return safe_compile(regex, flags)


# --- validators -----------------------------------------------------------------------------


def _digits(value: str) -> str:
    return "".join(char for char in value if char.isdigit())


def _is_run(digits: str) -> bool:
    """True for all-same digits or a run that goes up (or down) by one each step."""
    if len(set(digits)) == 1:
        return True
    steps = {(int(b) - int(a)) % 10 for a, b in pairwise(digits)}
    return steps in ({1}, {9})


def valid_aadhaar(value: str) -> bool:
    """12 digits, first digit 2 to 9, Verhoeff check, not all-same and not sequential."""
    digits = _digits(value)
    return (
        len(digits) == 12 and digits[0] in "23456789" and verhoeff(digits) and not _is_run(digits)
    )


_E164_TWO: Final = frozenset(
    (
        "20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45",
        "46", "47", "48", "49", "51", "52", "53", "54", "55", "56", "57", "58", "60", "61",
        "62", "63", "64", "65", "66", "81", "82", "84", "86", "90", "91", "92", "93", "94",
        "95", "98",
    )
)  # fmt: skip
_E164_THREE_RANGES: Final = (
    (211, 213), (216, 216), (218, 218), (220, 258), (260, 269), (290, 291), (297, 299),
    (350, 359), (370, 389), (420, 421), (423, 423), (500, 509), (590, 599), (670, 670),
    (672, 683), (685, 692), (850, 850), (852, 853), (855, 856), (880, 880), (886, 886),
    (960, 968), (970, 977), (992, 996), (998, 998),
)  # fmt: skip


def plausible_country_code(digits: str) -> bool:
    """True when ``digits`` begins with an assigned E.164 country calling code.

    The table is the assigned codes as of the ITU list; it rejects the unassigned prefixes
    (``+0``, ``+210``, ``+259``, ``+800``-ish test ranges) that a random digit string hits.
    """
    if digits[:1] in {"1", "7"}:
        return True
    if digits[:2] in _E164_TWO:
        return True
    return len(digits) >= 3 and any(
        low <= int(digits[:3]) <= high for low, high in _E164_THREE_RANGES
    )


def valid_phone_intl(value: str) -> bool:
    """E.164: ``+``, 8 to 15 digits in all, and a plausible country calling code."""
    digits = _digits(value)
    return value.startswith("+") and 8 <= len(digits) <= 15 and plausible_country_code(digits)


def valid_indian_mobile(value: str) -> bool:
    """A 10-digit number starting 6 to 9, after an optional ``+91`` or ``0``."""
    digits = _digits(value)
    if value.lstrip().startswith("+91"):
        digits = digits[2:]
    elif digits.startswith("0"):
        digits = digits[1:]
    return len(digits) == 10 and digits[0] in "6789"


_CARD_ISSUERS: Final = (
    (re.compile(r"4"), frozenset({13, 16, 19})),  # Visa
    (re.compile(r"5[1-5]|2(?:2[2-9]\d|[3-6]\d\d|7[01]\d|720)"), frozenset({16})),  # Mastercard
    (re.compile(r"3[47]"), frozenset({15})),  # American Express
    (re.compile(r"6011|65|64[4-9]"), frozenset({16, 17, 18, 19})),  # Discover
    (re.compile(r"30[0-5]|3095|3[689]"), frozenset({14, 15, 16, 17, 18, 19})),  # Diners
    (re.compile(r"35(?:2[89]|[3-8]\d)"), frozenset({16, 17, 18, 19})),  # JCB
    (re.compile(r"62"), frozenset({16, 17, 18, 19})),  # UnionPay
    (re.compile(r"60|65|81|82|508"), frozenset({16})),  # RuPay
    (re.compile(r"50|5[6-8]|6[0-9]"), frozenset({13, 14, 15, 16, 17, 18, 19})),  # Maestro
)


def card_issuer_ok(digits: str) -> bool:
    """True when ``digits`` has a known issuer prefix with a length that issuer uses."""
    return any(len(digits) in lengths and prefix.match(digits) for prefix, lengths in _CARD_ISSUERS)


def valid_credit_card(value: str) -> bool:
    """13 to 19 digits, a known issuer prefix and length, and a Luhn check."""
    digits = _digits(value)
    return 13 <= len(digits) <= 19 and card_issuer_ok(digits) and luhn(digits)


# ISO 13616 country code -> total IBAN length (the registry entries in common use).
_IBAN_LENGTHS: Final = {
    entry[:2]: int(entry[3:])
    for entry in (
        "AD:24", "AE:23", "AL:28", "AT:20", "AZ:28", "BA:20", "BE:16", "BG:22", "BH:22",
        "BR:29", "BY:28", "CH:21", "CR:22", "CY:28", "CZ:24", "DE:22", "DK:18", "DO:28",
        "EE:20", "EG:29", "ES:24", "FI:18", "FO:18", "FR:27", "GB:22", "GE:22", "GI:23",
        "GL:18", "GR:27", "GT:28", "HR:21", "HU:28", "IE:22", "IL:23", "IQ:23", "IS:26",
        "IT:27", "JO:30", "KW:30", "KZ:20", "LB:28", "LC:32", "LI:21", "LT:20", "LU:20",
        "LV:21", "MC:27", "MD:24", "ME:22", "MK:19", "MR:27", "MT:31", "MU:30", "NL:18",
        "NO:15", "PK:24", "PL:28", "PS:29", "PT:25", "QA:29", "RO:24", "RS:22", "SA:24",
        "SC:31", "SE:24", "SI:19", "SK:24", "SM:27", "ST:25", "SV:28", "TL:23", "TN:24",
        "TR:26", "UA:29", "VA:22", "VG:24", "XK:20",
    )
}  # fmt: skip


def valid_iban(value: str) -> bool:
    """A known country code with that country's length, and the mod 97 check."""
    compact = value.replace(" ", "")
    return _IBAN_LENGTHS.get(compact[:2]) == len(compact) and iban_mod97(compact)


def valid_gstin(value: str) -> bool:
    """15 characters with the documented check character."""
    return gstin_check(value)


def valid_ipv6(value: str) -> bool:
    """Parses as an IPv6 address and has at least three hexadecimal digits."""
    if sum(char != ":" for char in value) < 3:
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def valid_date_of_birth(value: str) -> bool:
    """A real calendar date, in a year from 1900 to 2100, day-first or month-first."""
    parts = [int(part) for part in re.split(r"[/.\-]", value)]
    if len(parts) != 3:
        return False
    if parts[0] > 31:
        year, first, second = parts
        candidates = [(year, first, second)]
    else:
        first, second, year = parts
        candidates = [(year, second, first), (year, first, second)]
    for candidate_year, month, day in candidates:
        if 1900 <= candidate_year <= 2100:
            try:
                date(candidate_year, month, day)
            except ValueError:
                continue
            return True
    return False


# --- formats --------------------------------------------------------------------------------

_NOT_ALNUM_BEFORE = r"(?<![A-Za-z0-9])"
_NOT_ALNUM_AFTER = r"(?![A-Za-z0-9])"
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_DATE = (
    r"(?:(?:19|20)\d{2}[/.\-](?:0?[1-9]|1[0-2])[/.\-](?:0?[1-9]|[12]\d|3[01])"
    r"|(?:0?[1-9]|[12]\d|3[01])[/.\-](?:0?[1-9]|[12]\d|3[01])[/.\-](?:19|20)\d{2})"
)
_NAMED_ASSIGNMENT = (
    r"""(?<![\w.\-])(?P<name>[A-Za-z_][\w.\-]{0,63})["']?[ \t]*(?::=|=>|:|=)[ \t]*["']?"""
)
_INDIA = frozenset({LOCALE_INDIA})
_INTL = frozenset({LOCALE_INTL})
_PASSPORT = frozenset({LOCALE_PASSPORT})

PII_FORMATS: Final[tuple[PiiFormat, ...]] = (
    PiiFormat(
        "aadhaar_number",
        r"(?<![\w.+\-])(?<!\d[ \-])[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}(?!\w|[ \-]\d|\.\d)",
        valid_aadhaar,
        _INDIA,
        Confidence.HIGH,
    ),
    PiiFormat(
        "pan_number",
        _NOT_ALNUM_BEFORE + r"[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]" + _NOT_ALNUM_AFTER,
        None,
        _INDIA,
        Confidence.HIGH,
    ),
    PiiFormat(
        "ifsc_code",
        _NOT_ALNUM_BEFORE + r"[A-Z]{4}0[A-Z0-9]{6}" + _NOT_ALNUM_AFTER,
        None,
        _INDIA,
        Confidence.MEDIUM,
    ),
    PiiFormat(
        "upi_id",
        r"(?<![\w.%+\-])[A-Za-z0-9._\-]{2,64}@(?!localhost\b)[A-Za-z][A-Za-z0-9]{1,31}(?![\w\-]|\.\w)",
        None,
        _INDIA,
        Confidence.MEDIUM,
    ),
    PiiFormat(
        "indian_mobile",
        r"(?<![\w+.\-])(?:\+91[ \-]?|0)?(?:[6-9]\d{9}|[6-9]\d{4}[ \-]\d{5})(?!\w|\.\d)",
        valid_indian_mobile,
        _INDIA,
        Confidence.MEDIUM,
    ),
    PiiFormat(
        "gstin",
        _NOT_ALNUM_BEFORE
        + r"(?:0[1-9]|[12]\d|3[0-8]|9[79])[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]"
        + _NOT_ALNUM_AFTER,
        valid_gstin,
        _INDIA,
        Confidence.HIGH,
    ),
    PiiFormat(
        "email",
        r"(?<![\w.%+\-])[A-Za-z0-9._%+\-]{1,64}@"
        r"(?:(?:[A-Za-z0-9\-]{1,63}\.){1,8}[A-Za-z]{2,24}|localhost)(?![\w\-])",
        None,
        _INTL,
        Confidence.HIGH,
    ),
    PiiFormat(
        "phone_intl",
        r"(?<![\w+])\+[1-9](?:[ \-]?\d){6,14}(?!\w|[ \-]\d)",
        valid_phone_intl,
        _INTL,
        Confidence.MEDIUM,
    ),
    PiiFormat(
        "credit_card",
        r"(?<![\w.\-])(?<!\d[ \-])\d(?:[ \-]?\d){12,18}(?!\w|[ \-]\d|\.\d)",
        valid_credit_card,
        _INTL,
        Confidence.HIGH,
    ),
    PiiFormat(
        "iban",
        _NOT_ALNUM_BEFORE
        + r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?"
        + _NOT_ALNUM_AFTER,
        valid_iban,
        _INTL,
        Confidence.HIGH,
    ),
    PiiFormat(
        "ipv4",
        rf"(?<![\w.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\w|\.\d)",
        None,
        _INTL,
        Confidence.MEDIUM,
    ),
    PiiFormat(
        "ipv6",
        r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:.])",
        valid_ipv6,
        _INTL,
        Confidence.MEDIUM,
    ),
    PiiFormat(
        "mac_address",
        r"(?<![\w:\-])[0-9A-Fa-f]{2}([:\-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:\-])",
        None,
        _INTL,
        Confidence.MEDIUM,
    ),
    PiiFormat(
        "date_of_birth",
        _NAMED_ASSIGNMENT + rf"(?P<value>{_DATE})(?!\w)",
        valid_date_of_birth,
        _INTL,
        Confidence.MEDIUM,
        value_group="value",
        name_words=frozenset({"dob", "birth", "birthday", "birthdate"}),
    ),
    PiiFormat(
        "passport_number",
        _NAMED_ASSIGNMENT + r"(?P<value>(?=[A-Z0-9]*\d)[A-Z0-9]{6,9})" + _NOT_ALNUM_AFTER,
        None,
        _PASSPORT,
        Confidence.LOW,
        value_group="value",
        name_words=frozenset({"passport"}),
    ),
)


def format_subtypes() -> frozenset[str]:
    """The subtypes the formats use (a walking test asserts each is in the closed vocabulary)."""
    used = frozenset(item.subtype for item in PII_FORMATS)
    unknown = used - PII_SUBTYPES
    if unknown:
        raise ValueError(f"formats use subtypes outside the vocabulary: {sorted(unknown)}")
    return used


def formats_for(locales: Collection[str]) -> tuple[PiiFormat, ...]:
    """The formats that ``locales`` enable.

    Raises:
        UnknownLocale: ``locales`` holds an entry that is not a known locale.
    """
    chosen = normalise_locales(locales)
    return tuple(item for item in PII_FORMATS if item.locales & chosen)


class PiiDetector:
    """The ``pii.<subtype>`` detector of one :class:`PiiFormat`.

    ``disabled_filters`` switches false-positive filters off by name (a test uses it to show
    the value comes back); an unknown name raises ``ValueError``.
    """

    kinds = frozenset({PlaceholderKind.PII})

    def __init__(self, pii_format: PiiFormat, *, disabled_filters: Iterable[str] = ()) -> None:
        self.format = pii_format
        self.id = f"pii.{pii_format.subtype}"
        self._pattern = pii_format.compiled()
        self._disabled = frozenset(disabled_filters)
        unknown = self._disabled - PII_FILTER_NAMES
        if unknown:
            raise ValueError(f"unknown filter names: {sorted(unknown)}")

    def __repr__(self) -> str:
        return f"PiiDetector(id={self.id!r})"

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> Sequence[TypedSpan]:
        """Every value of this format in ``text`` that passes its check and the filters."""
        raw = text.expose()
        pii_format = self.format
        offsets: ByteOffsets | None = None
        spans: list[TypedSpan] = []
        for match in self._pattern.finditer(raw):
            value = match.group(pii_format.value_group)
            if pii_format.name_words and not _has_word(match.group("name"), pii_format.name_words):
                continue
            if pii_format.validator is not None and not pii_format.validator(value):
                continue
            start, end = match.span(pii_format.value_group)
            line_start = raw.rfind("\n", 0, start) + 1
            context = PiiFilterContext(
                path=path,
                subtype=pii_format.subtype,
                before=raw[max(line_start, start - _CONTEXT_CHARS) : start],
                after=raw[end : end + _CONTEXT_CHARS].split("\n", 1)[0],
            )
            rule = first_match(value, context, self._disabled)
            if rule is not None and rule.verdict is Verdict.DROP:
                continue
            downgraded = rule is not None and pii_format.confidence is not Confidence.LOW
            offsets = offsets or ByteOffsets(raw)
            spans.append(
                TypedSpan(
                    kind=PlaceholderKind.PII,
                    subtype=pii_format.subtype,
                    start_byte=offsets.at(start),
                    end_byte=offsets.at(end),
                    confidence=Confidence.LOW if rule is not None else pii_format.confidence,
                    detector=self.id,
                    downgraded=downgraded,
                )
            )
        return spans


def _has_word(name: str, words: frozenset[str]) -> bool:
    return any(part.lower() in words for part in split_subtokens(name))
