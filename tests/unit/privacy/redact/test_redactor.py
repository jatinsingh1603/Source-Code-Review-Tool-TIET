"""``Redactor``: consistency, byte safety, fail-closed errors, corpus and properties (E08-01)."""

import json
from collections import Counter
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.models import Confidence, PlaceholderKind
from codekavach.core.models.payload import find_placeholders
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.overlap import resolve_overlaps
from codekavach.privacy.errors import RedactionError
from codekavach.privacy.redact.numbering import PlaceholderNumbering
from codekavach.privacy.redact.redactor import RedactionResult, Redactor
from tests.support.corpus import case_names, load_case
from tests.support.golden import assert_matches_golden

GOLDEN_ROOT = Path(__file__).resolve().parents[3] / "golden"
SALT = ScanSalt.from_hex("22" * 32)  # pragma: allowlist secret
PII, SECRET = PlaceholderKind.PII, PlaceholderKind.SECRET


def span(kind: PlaceholderKind, subtype: str, start: int, end: int) -> TypedSpan:
    return TypedSpan(
        kind=kind,
        subtype=subtype,
        start_byte=start,
        end_byte=end,
        confidence=Confidence.HIGH,
        detector="test.a",
    )


def redact(text: str, spans: list[TypedSpan]) -> RedactionResult:
    return Redactor().redact(text, spans, numbering=PlaceholderNumbering(SALT))


def assert_consistent(result: RedactionResult) -> None:
    """Declared placeholders equal what ``find_placeholders`` sees, including occurrences."""
    found = Counter(find_placeholders(result.text))
    declared = {ref.token: ref.occurrences for ref in result.placeholders}
    assert declared == dict(found)
    assert len(declared) == len(result.placeholders)


def test_a_span_is_replaced_by_its_typed_placeholder() -> None:
    result = redact("key = AKIAXXXX end", [span(SECRET, "aws_access_key", 6, 14)])
    assert result.text == "key = <SECRET:aws_access_key:1> end"
    assert result.spans_applied == 1
    (ref,) = result.placeholders
    assert (ref.kind, ref.subtype, ref.index, ref.occurrences) == (SECRET, "aws_access_key", 1, 1)
    assert_consistent(result)


def test_a_multi_line_secret_keeps_its_line_breaks_after_the_placeholder() -> None:
    key = "-----BEGIN PRIVATE KEY-----\r\nAAAA\nBBBB\n-----END PRIVATE KEY-----"
    text = f'KEY = """{key}"""\nnext = 1\n'
    start = text.index("-----BEGIN")
    result = redact(text, [span(SECRET, "private_key_block", start, start + len(key))])
    assert result.text == 'KEY = """<SECRET:private_key_block:1>\r\n\n\n"""\nnext = 1\n'
    assert result.text.count("\n") == text.count("\n")
    assert "AAAA" not in result.text
    assert_consistent(result)


def test_no_spans_returns_the_text_unchanged() -> None:
    result = redact("nothing to hide", [])
    assert (result.text, result.placeholders, result.spans_applied) == ("nothing to hide", (), 0)


def test_the_same_value_three_times_is_one_index_and_three_occurrences() -> None:
    text = "a=KEYONE b=KEYONE c=KEYONE"
    spans = [span(SECRET, "jwt", start, start + 6) for start in (2, 11, 20)]
    result = redact(text, spans)
    assert result.text == "a=<SECRET:jwt:1> b=<SECRET:jwt:1> c=<SECRET:jwt:1>"
    (ref,) = result.placeholders
    assert (ref.index, ref.occurrences) == (1, 3)
    assert_consistent(result)


def test_different_values_of_one_subtype_get_different_contiguous_indices() -> None:
    result = redact("AAAA BBBB AAAA CCCC", [span(PII, "email", s, s + 4) for s in (0, 5, 10, 15)])
    assert result.text == "<PII:email:1> <PII:email:2> <PII:email:1> <PII:email:3>"
    assert [(r.index, r.occurrences) for r in result.placeholders] == [(1, 2), (2, 1), (3, 1)]
    assert_consistent(result)


def test_indices_follow_text_order_not_input_order() -> None:
    result = redact("AAAA BBBB", [span(PII, "email", 5, 9), span(PII, "email", 0, 4)])
    assert result.text == "<PII:email:1> <PII:email:2>"


def test_numbering_is_shared_across_calls_within_a_scan() -> None:
    numbering = PlaceholderNumbering(SALT)
    first = Redactor().redact("AAAA", [span(PII, "email", 0, 4)], numbering=numbering)
    second = Redactor().redact(
        "x BBBB AAAA", [span(PII, "email", 2, 6), span(PII, "email", 7, 11)], numbering=numbering
    )
    assert first.text == "<PII:email:1>"
    assert second.text == "x <PII:email:2> <PII:email:1>"


# --- bytes ---------------------------------------------------------------------------------


def test_offsets_are_utf8_bytes_with_multibyte_and_astral_characters() -> None:
    text = "café 日本 \U0001f600 KEYKEY \U0001f600"
    start = len(text[: text.index("KEYKEY")].encode("utf-8"))
    result = redact(text, [span(SECRET, "jwt", start, start + 6)])
    assert result.text == "café 日本 \U0001f600 <SECRET:jwt:1> \U0001f600"


def test_a_span_that_ends_inside_a_multibyte_character_raises_and_returns_nothing() -> None:
    text = "abécd"  # the e-acute is bytes 2 and 3
    with pytest.raises(RedactionError):
        redact(text, [span(PII, "email", 0, 3)])


def test_a_span_that_starts_inside_a_multibyte_character_raises() -> None:
    with pytest.raises(RedactionError):
        redact("abécd", [span(PII, "email", 3, 5)])


def test_a_span_inside_an_astral_character_raises() -> None:
    with pytest.raises(RedactionError):
        redact("x\U0001f600y", [span(PII, "email", 2, 4)])


def test_a_span_on_character_boundaries_around_multibyte_text_is_fine() -> None:
    result = redact("éé", [span(PII, "email", 0, 2)])
    assert result.text == "<PII:email:1>é"


@pytest.mark.parametrize(
    "spans",
    [
        [span(PII, "email", 0, 99)],
        [span(PII, "email", 5, 12)],
        [span(PII, "email", 0, 4), span(PII, "ipv4", 2, 6)],
    ],
    ids=["beyond-the-end", "starts-beyond", "overlap"],
)
def test_bad_spans_raise_redaction_error(spans: list[TypedSpan]) -> None:
    with pytest.raises(RedactionError):
        redact("short text", spans)


def test_error_messages_never_quote_the_text() -> None:
    leaky_text = "AKIA-this-must-not-appear"
    with pytest.raises(RedactionError) as caught:
        redact(leaky_text, [span(SECRET, "aws_access_key", 0, 999)])
    assert leaky_text not in str(caught.value)
    assert "AKIA" not in str(caught.value)


def test_text_that_cannot_be_encoded_fails_closed() -> None:
    with pytest.raises(RedactionError):
        redact("lone surrogate \ud800 here", [])


def test_a_token_already_in_the_text_is_never_reused_for_a_new_value() -> None:
    with pytest.raises(RedactionError):
        redact("old <PII:email:1> new AAAA", [span(PII, "email", 22, 26)])


def test_a_text_that_was_redacted_before_is_declared_consistently() -> None:
    result = redact("a <PII:email:1> b <PII:email:1>", [])
    assert result.text == "a <PII:email:1> b <PII:email:1>"
    (ref,) = result.placeholders
    assert ref.occurrences == 2
    assert_consistent(result)


def test_repr_of_the_result_holds_no_text() -> None:
    result = redact("AKIAXXXX in code", [span(SECRET, "aws_access_key", 0, 8)])
    assert "code" not in repr(result)
    assert "AKIAXXXX" not in repr(result)


# --- the corpus ----------------------------------------------------------------------------


@pytest.mark.parametrize("name", case_names())
def test_every_corpus_case_redacts_consistently(name: str) -> None:
    case = load_case(name)
    result = redact(case.text, list(resolve_overlaps(case.detected)))
    assert_consistent(result)
    for expected in case.expected:
        value = case.text.encode("utf-8")[expected.start_byte : expected.end_byte].decode("utf-8")
        assert value not in result.text
    assert result.spans_applied == len(case.expected)


@pytest.mark.parametrize("name", case_names())
def test_the_corpus_labels_describe_the_expanded_text(name: str) -> None:
    case = load_case(name)
    data = case.text.encode("utf-8")
    for span_ in (*case.detected, *case.expected):
        assert 0 <= span_.start_byte < span_.end_byte <= len(data)
        data[span_.start_byte : span_.end_byte].decode("utf-8")  # a character boundary
    assert tuple(resolve_overlaps(case.detected)) == tuple(
        sorted(case.expected, key=lambda s: (s.start_byte, s.end_byte))
    )


@pytest.mark.parametrize("name", case_names())
def test_golden_redaction_result_for_the_corpus(name: str) -> None:
    case = load_case(name)
    result = redact(case.text, list(resolve_overlaps(case.detected)))
    document = {
        "text": result.text,
        "placeholders": [ref.model_dump(mode="json") for ref in result.placeholders],
        "spans_applied": result.spans_applied,
    }
    assert_matches_golden(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        GOLDEN_ROOT / "detect" / f"{name}.redacted.json",
    )


def test_the_connection_string_example_is_one_placeholder_over_the_whole_url() -> None:
    case = load_case("connection_string_aws")
    result = redact(case.text, list(resolve_overlaps(case.detected)))
    assert "<SECRET:connection_string:1>" in result.text
    assert "aws_access_key" not in result.text
    assert "AKIA" not in result.text


# --- properties ----------------------------------------------------------------------------

PLAIN = st.text(alphabet="abc xyz\né日", max_size=12)
HIDDEN = st.text(alphabet="XYZ", min_size=1, max_size=6)


@st.composite
def texts_with_spans(draw: st.DrawFn) -> tuple[str, list[TypedSpan]]:
    """Plain segments (no X, Y or Z) alternating with hidden ones (only X, Y, Z)."""
    parts: list[str] = [draw(PLAIN)]
    spans: list[TypedSpan] = []
    position = len(parts[0].encode("utf-8"))
    for _ in range(draw(st.integers(min_value=0, max_value=6))):
        hidden = draw(HIDDEN)
        length = len(hidden.encode("utf-8"))
        spans.append(span(PII, "email", position, position + length))
        plain = draw(PLAIN)
        parts.extend([hidden, plain])
        position += length + len(plain.encode("utf-8"))
    return "".join(parts), spans


@settings(max_examples=300, deadline=None)
@given(texts_with_spans())
def test_property_hidden_bytes_are_gone_and_declarations_are_exact(
    case: tuple[str, list[TypedSpan]],
) -> None:
    text, spans = case
    result = redact(text, spans)
    assert not set("XYZ") & set(result.text)
    assert_consistent(result)
    assert result.spans_applied == len(spans)
    assert sum(ref.occurrences for ref in result.placeholders) == len(spans)


@settings(max_examples=200, deadline=None)
@given(texts_with_spans())
def test_property_redacting_an_already_redacted_text_changes_nothing(
    case: tuple[str, list[TypedSpan]],
) -> None:
    text, spans = case
    once = redact(text, spans)
    twice = redact(once.text, [])
    assert twice.text == once.text
    assert twice.placeholders == once.placeholders
