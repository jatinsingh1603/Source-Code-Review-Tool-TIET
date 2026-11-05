"""``TypedSpan`` validation and the closed subtype vocabulary (E08-01)."""

import pytest
from pydantic import ValidationError

from codekavach.core.models import Confidence, PlaceholderKind
from codekavach.core.models.payload import format_placeholder
from codekavach.privacy.detect.base import SUBTYPE_PATTERN, TypedSpan
from codekavach.privacy.detect.vocabulary import (
    GENERIC_SUBTYPES,
    PII_SUBTYPES,
    SECRET_SUBTYPES,
    TERM_SUBTYPES,
    VOCABULARY,
    UnknownSubtype,
    is_specific,
    validate_subtype,
)

SECRET = PlaceholderKind.SECRET


def make(**overrides: object) -> TypedSpan:
    values: dict[str, object] = {
        "kind": SECRET,
        "subtype": "aws_access_key",
        "start_byte": 0,
        "end_byte": 20,
        "confidence": Confidence.HIGH,
        "detector": "secret.pattern",
    }
    values.update(overrides)
    return TypedSpan.model_validate(values)


def test_a_valid_span_is_built_and_is_hashable() -> None:
    span = make()
    assert span.length == 20
    assert {span, make()} == {span}


@pytest.mark.parametrize(
    "overrides",
    [
        {"start_byte": 5, "end_byte": 5},
        {"start_byte": 9, "end_byte": 3},
        {"start_byte": -1, "end_byte": 3},
        {"subtype": "not_in_the_vocabulary"},
        {"subtype": "email"},  # a real subtype, but of another kind
        {"subtype": "AWS_ACCESS_KEY"},
        {"subtype": "9starts_with_digit"},
        {"subtype": "a" * 49},
        {"subtype": ""},
        {"detector": "Bad Detector"},
        {"detector": ""},
    ],
)
def test_an_invalid_span_is_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        make(**overrides)


def test_the_rejection_of_a_subtype_does_not_echo_it() -> None:
    leaked = "AKIA_not_a_subtype_but_matched_text"
    with pytest.raises(ValidationError) as caught:
        make(subtype=leaked.lower())
    assert leaked.lower() not in str(caught.value)
    assert leaked.lower() not in repr(caught.value.errors(include_input=False))


def test_validate_subtype_raises_unknown_subtype_without_the_text() -> None:
    validate_subtype(SECRET, "aws_access_key")
    with pytest.raises(UnknownSubtype) as caught:
        validate_subtype(SECRET, "secret_value_here")
    assert "secret_value_here" not in str(caught.value)


def test_repr_of_a_span_holds_no_value_text() -> None:
    assert set(make().model_dump()) == {
        "kind",
        "subtype",
        "start_byte",
        "end_byte",
        "confidence",
        "detector",
        "downgraded",
    }


def test_the_vocabulary_covers_every_kind_and_term_has_one_subtype() -> None:
    assert set(VOCABULARY) == set(PlaceholderKind)
    assert {"domain"} == TERM_SUBTYPES
    assert {"aws_access_key", "jwt", "private_key_block", "connection_string"} <= SECRET_SUBTYPES
    assert {"email", "aadhaar_number", "pan_number", "credit_card", "iban"} <= PII_SUBTYPES


@pytest.mark.parametrize("kind", list(PlaceholderKind))
def test_every_subtype_fits_the_placeholder_grammar(kind: PlaceholderKind) -> None:
    for subtype in sorted(VOCABULARY[kind]):
        assert SUBTYPE_PATTERN.match(subtype), subtype
        assert format_placeholder(kind, subtype, 1).startswith(f"<{kind.value}:{subtype}:")


def test_subtypes_are_not_shared_between_kinds() -> None:
    assert SECRET_SUBTYPES.isdisjoint(PII_SUBTYPES)
    assert SECRET_SUBTYPES.isdisjoint(TERM_SUBTYPES)
    assert PII_SUBTYPES.isdisjoint(TERM_SUBTYPES)


def test_generic_subtypes_are_vocabulary_members_and_specificity_follows() -> None:
    every = SECRET_SUBTYPES | PII_SUBTYPES | TERM_SUBTYPES
    assert every >= GENERIC_SUBTYPES
    assert not is_specific("generic_credential")
    assert is_specific("aws_access_key")
