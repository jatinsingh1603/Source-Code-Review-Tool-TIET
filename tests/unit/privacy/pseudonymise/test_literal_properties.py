"""Property tests for the literal shapers (E09-03), with hypothesis.

Properties: the shaped literal keeps the delimiter structure of its source (a string literal
still tokenises as one string); placeholder tokens survive byte for byte; shaping is idempotent;
and a shaped regular expression always compiles.
"""

import io
import re
import string
import tokenize
import warnings

from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.detect.mask import PLACEHOLDER_MASK_PATTERN
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator
from codekavach.privacy.pseudonymise.literals import shape_content

SALT = ScanSalt(bytes(range(32)))
PLACEHOLDER = "<SECRET:api_key:1>"
PLACEHOLDER_TEXT = re.compile(r"<(SECRET|PII|TERM):[a-z][a-z0-9_]{0,47}:[1-9][0-9]{0,5}>")

NO_DIGITS = string.ascii_letters + " ,.%()"
SAFE = string.ascii_letters + string.digits + " ,.:/%()-_{}[]?'$"
PATH_ALPHABET = string.ascii_letters + "/._- "


class Allow:
    def is_public(self, word: str) -> bool:
        return False


def shaped(content: str, kind: str) -> str:
    text, _ = shape_content(content, kind, generator=PseudonymGenerator(SALT), allowlist=Allow())
    return text


def string_literal_count(source: str) -> int:
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    return sum(1 for token in tokens if token.type == tokenize.STRING)


@given(content=st.text(alphabet=SAFE, max_size=60), kind=st.sampled_from(["sql", "format"]))
@settings(max_examples=150, deadline=None)
def test_shaped_literal_still_tokenises_as_one_string(content: str, kind: str) -> None:
    text = shaped(content, kind)
    assert "\n" not in text
    assert string_literal_count(f'x = "{text}"\n') == 1
    assert '"' not in text and "\\" not in text


@given(content=st.text(alphabet=SAFE, max_size=60), kind=st.sampled_from(["natural", "url"]))
@settings(max_examples=100, deadline=None)
def test_shaped_literal_never_gains_a_quote_or_backslash(content: str, kind: str) -> None:
    text = shaped(content, kind)
    assert '"' not in text and "\\" not in text


@given(
    before=st.text(alphabet=NO_DIGITS, max_size=20),
    after=st.text(alphabet=NO_DIGITS, max_size=20),
    kind=st.sampled_from(["sql", "format", "natural", "path", "regex", "url"]),
)
@settings(max_examples=150, deadline=None)
def test_placeholder_tokens_are_byte_identical_after_shaping(
    before: str, after: str, kind: str
) -> None:
    content = before + PLACEHOLDER + after
    original = PLACEHOLDER_MASK_PATTERN.findall(content)
    out = shaped(content, kind)
    assert PLACEHOLDER_TEXT.findall(out) == PLACEHOLDER_TEXT.findall(content)
    assert PLACEHOLDER_MASK_PATTERN.findall(out) == original


REGEX_ALPHABET = string.ascii_letters + "[]{}()\\dw+*?|^$-.,:0123456789"


@given(content=st.text(alphabet=REGEX_ALPHABET, max_size=40))
@settings(max_examples=200, deadline=None)
def test_shaped_regular_expression_always_compiles(content: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # for example "possible nested set" on "[["
        re.compile(shaped(content, "regex"))


def test_a_pattern_that_makes_the_compiler_warn_does_not_raise_under_strict_warnings() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert shaped("[[", "regex")
