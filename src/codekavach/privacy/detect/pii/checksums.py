"""Check-digit functions for the personal-data formats: Verhoeff, Luhn, IBAN mod 97, GSTIN.

Owning epic: E08.

Each function is pure, takes a string and returns whether the check passes. The test vectors in
the docstrings are synthetic or published in the standard's own documentation, never an issued
identifier; ``tests/unit/privacy/detect/pii/test_checksums.py`` runs them.

A format that defines a checksum is what keeps its detector usable: without it a pattern for
twelve digits fires on every timestamp and account sequence in a banking code base.
"""

from typing import Final

_VERHOEFF_D: Final = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P: Final = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_BASE36: Final = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def verhoeff(digits: str) -> bool:
    """True when ``digits`` (check digit last) satisfies the Verhoeff checksum.

    The checksum is the one Aadhaar numbers use; it detects every single-digit error and every
    adjacent transposition. Vectors from the algorithm's published description: ``2363``,
    ``123451`` and ``758722`` pass; ``2364``, ``123450`` and ``758721`` fail.

    >>> verhoeff("2363"), verhoeff("2364")
    (True, False)
    """
    if not digits or not digits.isascii() or not digits.isdigit():
        return False
    state = 0
    for position, digit in enumerate(reversed(digits)):
        state = _VERHOEFF_D[state][_VERHOEFF_P[position % 8][int(digit)]]
    return state == 0


def luhn(digits: str) -> bool:
    """True when ``digits`` (check digit last) satisfies the Luhn mod 10 checksum.

    Payment card numbers use it. The vector ``79927398713`` passes (the example in the
    algorithm's description) and ``79927398710`` fails; the payment-gateway test number
    ``4111111111111111`` passes.

    >>> luhn("79927398713"), luhn("79927398710")
    (True, False)
    """
    if len(digits) < 2 or not digits.isascii() or not digits.isdigit():
        return False
    total = 0
    for position, digit in enumerate(reversed(digits)):
        value = int(digit)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def iban_mod97(value: str) -> bool:
    """True when the IBAN ``value`` satisfies the ISO 7064 mod 97-10 check.

    Spaces are ignored and case is folded. The first four characters move to the end, letters
    become ``10`` to ``35``, and the number must leave remainder ``1`` modulo 97. The IBAN
    standard's own examples pass: ``GB82WEST12345698765432`` and ``DE89370400440532013000``;
    the first with its last digit changed (``GB82WEST12345698765433``) fails.

    >>> iban_mod97("GB82 WEST 1234 5698 7654 32"), iban_mod97("GB82WEST12345698765433")
    (True, False)
    """
    compact = value.replace(" ", "").upper()
    if not 5 <= len(compact) <= 34 or not compact.isascii() or not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(char, 36)) for char in rearranged)
    return int(number) % 97 == 1


def gstin_check_character(first_fourteen: str) -> str | None:
    """The check character of a GSTIN whose first 14 characters are ``first_fourteen``.

    Each character is its base-36 value, multiplied by 1 at even positions and by 2 at odd
    ones; the quotient and the remainder of each product by 36 are summed, and the check
    character is ``(36 - sum % 36) % 36`` in base 36. ``None`` for anything that is not 14
    base-36 characters.
    """
    if len(first_fourteen) != 14 or any(char not in _BASE36 for char in first_fourteen):
        return None
    total = 0
    for position, char in enumerate(first_fourteen):
        product = _BASE36.index(char) * (1 if position % 2 == 0 else 2)
        total += product // 36 + product % 36
    return _BASE36[(36 - total % 36) % 36]


def gstin_check(value: str) -> bool:
    """True when the 15-character GSTIN ``value`` ends in the correct check character.

    ``27AAPFU0939F1ZV`` is the sample number that GST guidance circulates and passes; the same
    text with the last character changed (``27AAPFU0939F1ZW``) fails.

    >>> gstin_check("27AAPFU0939F1ZV"), gstin_check("27AAPFU0939F1ZW")
    (True, False)
    """
    if len(value) != 15:
        return False
    expected = gstin_check_character(value[:14])
    return expected is not None and expected == value[14]
