"""``secret.entropy``: charset-aware thresholds, the worked examples and the monotone decision."""

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import Confidence, Language, RawCode
from codekavach.privacy.detect.secrets.entropy import (
    ALPHABETS,
    EntropyDetector,
    classify,
    exceeds_threshold,
    is_high_entropy,
    shannon_entropy,
)
from tests.support.synthetic import synthetic_value

DEADBEEF = "deadbeef" * 4
RANDOM_HEX = "3f9a1c7e5b2d8046a1c93e7f50b2d8a4"  # pragma: allowlist secret


def run(text: str, path: str = "src/app.py") -> list[str]:
    data = text.encode()
    spans = EntropyDetector().detect(RawCode(text), path=path, language=Language.PYTHON)
    return [data[s.start_byte : s.end_byte].decode() for s in spans]


def test_entropy_of_known_strings() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy("ab" * 8) == pytest.approx(1.0)
    assert shannon_entropy("0123456789abcdef") == pytest.approx(math.log2(16))


def test_regression_deadbeef_repeated_to_32_characters_is_not_reported() -> None:
    assert len(DEADBEEF) == 32
    assert shannon_entropy(DEADBEEF) < 3.2
    assert not is_high_entropy(DEADBEEF)
    assert run(f'seed = "{DEADBEEF}"') == []


def test_regression_a_random_32_character_hex_string_is_reported() -> None:
    assert shannon_entropy(RANDOM_HEX) >= 3.2
    assert is_high_entropy(RANDOM_HEX)
    assert run(f'seed = "{RANDOM_HEX}"') == [RANDOM_HEX]


def test_the_threshold_table_matches_the_issue() -> None:
    table = {a.name: (a.min_length, a.threshold) for a in ALPHABETS}
    assert table == {
        "hex": (32, 3.2),
        "base58": (25, 4.2),
        "alphanumeric": (16, 3.8),
        "base64url": (20, 4.5),
        "base64": (20, 4.5),
    }


@pytest.mark.parametrize(
    ("value", "alphabet"),
    [
        (RANDOM_HEX, "hex"),
        (synthetic_value("secret", "high_entropy_string", 1), "base64"),
        (synthetic_value("secret", "high_entropy_string", 2), "base64url"),
        (synthetic_value("secret", "high_entropy_string", 3), "alphanumeric"),
        (synthetic_value("secret", "high_entropy_string", 4), "base58"),
    ],
)
def test_each_alphabet_is_detected_and_each_sample_is_reported(value: str, alphabet: str) -> None:
    found = classify(value)
    assert found is not None
    assert found.name == alphabet
    assert is_high_entropy(value)


@pytest.mark.parametrize(
    "value",
    [
        "a" * 40,  # one symbol
        "abcd" * 10,  # four symbols: 2.0 bits, under every threshold
        "ab12" * 8,  # four symbols in a 32-character hex-looking string
    ],
)
def test_low_entropy_strings_are_not_reported_whatever_the_alphabet(value: str) -> None:
    assert not is_high_entropy(value)


def test_too_short_for_the_alphabet_is_not_reported() -> None:
    assert classify(RANDOM_HEX[:31]) is not None  # still long enough for the alphanumeric rule
    assert (
        classify("3f9a1c7e5b2d804") is None  # pragma: allowlist secret
    )  # 15 characters: shorter than every rule  # pragma: allowlist secret
    assert not is_high_entropy("3f9a1c7e5b2d804")  # pragma: allowlist secret


def test_a_hex_string_shorter_than_32_falls_through_to_the_wider_alphabet() -> None:
    value = "3f9a1c7e5b2d8046a1c93e7f50b2"  # 28 hex characters  # pragma: allowlist secret
    found = classify(value)
    assert found is not None
    assert found.name == "alphanumeric"


def test_the_decision_does_not_depend_on_the_value_only_on_alphabet_and_entropy() -> None:
    hex_rule = ALPHABETS[0]
    assert exceeds_threshold(hex_rule, 3.2)
    assert not exceeds_threshold(hex_rule, 3.199)


@given(
    index=st.integers(min_value=0, max_value=len(ALPHABETS) - 1),
    low=st.floats(min_value=0.0, max_value=8.0, allow_nan=False),
    high=st.floats(min_value=0.0, max_value=8.0, allow_nan=False),
)
def test_property_the_decision_is_monotone_in_entropy_for_every_alphabet(
    index: int, low: float, high: float
) -> None:
    alphabet = ALPHABETS[index]
    low, high = sorted((low, high))
    if exceeds_threshold(alphabet, low):
        assert exceeds_threshold(alphabet, high)


@given(
    st.sampled_from(
        ["0123456789abcdef", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]
    ),
    st.integers(min_value=32, max_value=64),
    st.data(),
)
def test_property_at_a_fixed_length_a_higher_entropy_string_is_never_rejected(
    alphabet: str, length: int, data: st.DataObject
) -> None:
    first = data.draw(st.text(alphabet=alphabet, min_size=length, max_size=length))
    second = data.draw(st.text(alphabet=alphabet, min_size=length, max_size=length))
    # Within one alphabet class the rule is "entropy at least the threshold", so a string with
    # at least as much entropy is accepted whenever the other is. Compare only strings the
    # classifier puts in the same class.
    if classify(first) is classify(second) and shannon_entropy(first) <= shannon_entropy(second):
        assert not is_high_entropy(first) or is_high_entropy(second)


def test_candidates_are_quoted_literals_and_config_values_not_identifiers_or_prose() -> None:
    value = synthetic_value("secret", "high_entropy_string", 3)
    assert run(f'x = "{value}"') == [value]
    assert run(f"x = '{value}'") == [value]
    assert run(f"x = `{value}`") == [value]
    assert run(f"build_ref: {value}\n", "deploy/app.yaml") == [value]
    assert run(f"SALT={value}\n", ".env") == [value]
    assert run(f"export SALT={value}\r\n", ".env") == [value]
    assert run(f"call({value})") == []  # an identifier-like token is not a literal
    assert run(f'x = "{value} and more words"') == []  # more than one token


def test_a_span_covers_the_value_and_not_the_quotes() -> None:
    value = synthetic_value("secret", "high_entropy_string", 3)
    text = f'k = "{value}"'
    (span,) = EntropyDetector().detect(RawCode(text), path="a.py", language=Language.PYTHON)
    assert (span.start_byte, span.end_byte) == (5, 5 + len(value))
    assert (span.confidence, span.subtype, span.downgraded) == (
        Confidence.LOW,
        "high_entropy_string",
        False,
    )


def test_offsets_are_utf8_bytes() -> None:
    value = synthetic_value("secret", "high_entropy_string", 3)
    text = f'café = "日本"  # \U0001f600\nk = "{value}"'
    assert run(text) == [value]


def test_an_unknown_disabled_filter_name_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="unknown filter"):
        EntropyDetector(disabled_filters=["no_such_filter"])
