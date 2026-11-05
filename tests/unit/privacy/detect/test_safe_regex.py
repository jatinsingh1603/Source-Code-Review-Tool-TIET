"""``safe_compile`` rejects nested unbounded quantifiers (E08-01, CWE-1333)."""

import re
import time

import pytest

from codekavach.privacy.detect.safe_regex import UnsafePattern, safe_compile

NESTED = [
    "(a+)+",
    "(a*)*",
    "(?:x+y?)*",
    "(.*a)+",
    "((a)+b)*",
    "(a|b+)*",
    "(?:a+){2,}",
    "(?=(a+)+)b",
    "(a{1,})+",
    r"(\w+\s?)*$",
    "(?:(?:a+)b)+",
    "(?P<name>a+)+",
    "(?>a+)+",
]
SAFE = [
    "a+",
    "(ab)+",
    "[a-z]{1,10}(?:x+)",
    "(a{1,5})+",
    r"(?:\d{3}-)+",
    "AKIA[0-9A-Z]{16}",
    "(?i)abc*d+",
    "(a+)b(c+)",
    "(?:a|b)*",
    r"(\w+@)?x",
    r"[A-Za-z0-9_-]{20,}",
]


@pytest.mark.parametrize("pattern", NESTED)
def test_nested_unbounded_quantifiers_are_rejected(pattern: str) -> None:
    with pytest.raises(UnsafePattern):
        safe_compile(pattern)


@pytest.mark.parametrize("pattern", SAFE)
def test_ordinary_patterns_compile(pattern: str) -> None:
    assert safe_compile(pattern).pattern == pattern


def test_flags_are_passed_through() -> None:
    assert safe_compile("abc", re.IGNORECASE).flags & re.IGNORECASE


def test_an_invalid_pattern_raises_the_regex_error() -> None:
    with pytest.raises(re.error):
        safe_compile("(unclosed")


def test_an_unsafe_pattern_really_is_slow_and_the_rejected_form_is_not() -> None:
    """The reason for the rule: the same input that stalls ``(a+)+$`` is instant for ``a+$``."""
    evil = "a" * 26 + "!"
    started = time.perf_counter()
    assert re.compile("a+$").search(evil) is None
    assert time.perf_counter() - started < 0.5
    with pytest.raises(UnsafePattern):
        safe_compile("(a+)+$")


def test_the_error_does_not_quote_the_pattern() -> None:
    with pytest.raises(UnsafePattern) as caught:
        safe_compile("(secretish+)+")
    assert "secretish" not in str(caught.value)
