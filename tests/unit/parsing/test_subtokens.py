"""``split_subtokens`` and ``normalise_subtoken`` (E07-03)."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.parsing.subtokens import normalise_subtoken, split_subtokens

ROWS: list[tuple[str, tuple[str, ...]]] = [
    ("accountIDForKYC_2", ("account", "ID", "For", "KYC", "2")),
    ("__init__", ("init",)),
    ("HTTPServer", ("HTTP", "Server")),
    ("camelCase", ("camel", "Case")),
    ("PascalCase", ("Pascal", "Case")),
    ("snake_case", ("snake", "case")),
    ("SCREAMING_SNAKE_CASE", ("SCREAMING", "SNAKE", "CASE")),
    ("kebab-case", ("kebab", "case")),
    ("x", ("x",)),
    ("A", ("A",)),
    ("a_b", ("a", "b")),
    ("aB", ("a", "B")),
    ("Ab", ("Ab",)),
    ("ABc", ("A", "Bc")),
    ("ID", ("ID",)),
    ("_private", ("private",)),
    ("trailing_", ("trailing",)),
    ("__dunder__", ("dunder",)),
    ("a__b", ("a", "b")),
    ("$jquery", ("jquery",)),
    ("value2", ("value", "2")),
    ("v2Value", ("v", "2", "Value")),
    ("a1b2", ("a", "1", "b", "2")),
    ("iOS", ("i", "OS")),
    ("getHTTPResponseCode", ("get", "HTTP", "Response", "Code")),
    ("parseXML2JSON", ("parse", "XML", "2", "JSON")),
    ("XMLHttpRequest", ("XML", "Http", "Request")),
    ("HTTP2Server", ("HTTP", "2", "Server")),
    ("MAX_RETRIES_5", ("MAX", "RETRIES", "5")),
    ("ünicodeName", ("ünicode", "Name")),
    ("ÉcoleNormale", ("École", "Normale")),
    ("_", ()),
    ("__", ()),
    ("$$", ()),
    ("", ()),
]


@pytest.mark.parametrize(("name", "expected"), ROWS, ids=[row[0] or "<empty>" for row in ROWS])
def test_split_subtokens_table(name: str, expected: tuple[str, ...]) -> None:
    assert split_subtokens(name) == expected


def test_the_table_has_at_least_25_rows() -> None:
    assert len(ROWS) >= 25


@pytest.mark.parametrize(
    ("raw", "folded"), [("KYC", "kyc"), ("Server", "server"), ("STRASSE", "strasse"), ("ß", "ss")]
)
def test_normalise_subtoken_case_folds(raw: str, folded: str) -> None:
    assert normalise_subtoken(raw) == folded


@given(st.text(max_size=40))
def test_split_is_deterministic_and_never_raises(name: str) -> None:
    assert split_subtokens(name) == split_subtokens(name)


@given(st.text(alphabet=st.characters(categories=("Lu", "Ll", "Nd")), max_size=40))
def test_subtokens_of_a_plain_identifier_rejoin_to_the_original(name: str) -> None:
    assert "".join(split_subtokens(name)) == name


@given(st.text(alphabet="abcXYZ019_-$", max_size=30))
def test_no_subtoken_is_empty_or_holds_a_separator(name: str) -> None:
    for token in split_subtokens(name):
        assert token
        assert not set(token) & set("_-$")
