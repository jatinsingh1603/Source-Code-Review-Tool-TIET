"""Masking placeholders before detection (E08-01)."""

from hypothesis import given
from hypothesis import strategies as st

from codekavach.privacy.detect.mask import FILLER, mask_placeholders, placeholder_regions


def test_tokens_become_spaces_of_the_same_length() -> None:
    text = 'a = "<SECRET:aws_access_key:1>" + <PII:email:12>'
    masked = mask_placeholders(text)
    assert len(masked) == len(text)
    assert "SECRET" not in masked
    assert "email" not in masked
    assert masked == 'a = "' + FILLER * 25 + '" + ' + FILLER * 14


def test_text_without_tokens_is_returned_unchanged() -> None:
    text = "no tokens here <NOT:a:token> <SECRET:Upper:1> <PII:email:0>"
    assert mask_placeholders(text) == text


def test_masking_twice_changes_nothing() -> None:
    once = mask_placeholders("x <TERM:domain:3> y")
    assert mask_placeholders(once) == once


def test_regions_are_utf8_byte_ranges() -> None:
    text = "café \U0001f600 <PII:email:1> tail"
    ((start, end),) = placeholder_regions(text)
    assert text.encode("utf-8")[start:end] == b"<PII:email:1>"


def test_regions_of_text_without_tokens_are_empty() -> None:
    assert placeholder_regions("plain") == ()


@given(st.text(max_size=80))
def test_masking_keeps_the_length_in_characters_and_bytes(text: str) -> None:
    masked = mask_placeholders(text)
    assert len(masked) == len(text)
    assert len(masked.encode("utf-8", errors="surrogatepass")) == len(
        text.encode("utf-8", errors="surrogatepass")
    )
