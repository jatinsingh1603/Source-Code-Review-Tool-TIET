import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, ValidationError

from codekavach.config import SecretRef, parse_secret_ref
from codekavach.config.keys import SECRET_REF_PATTERN, ParsedSecretRef, is_secret_ref
from codekavach.config.models.base import PrivacyLevelField, SectionModel
from codekavach.core.models import PrivacyLevel


class Holder(SectionModel):
    api_key: SecretRef


class LevelHolder(BaseModel):
    level: PrivacyLevelField


ACCEPTED = [
    ("env:ANTHROPIC_API_KEY", ParsedSecretRef("env", None, "ANTHROPIC_API_KEY")),
    ("keyring:codekavach/anthropic", ParsedSecretRef("keyring", "codekavach", "anthropic")),
    ("keyring:anthropic", ParsedSecretRef("keyring", "codekavach", "anthropic")),
    ("file:/run/secrets/openai_key", ParsedSecretRef("file", None, "/run/secrets/openai_key")),
    ("file:C:\\secrets\\k.txt", ParsedSecretRef("file", None, "C:\\secrets\\k.txt")),
    ("file:~/k", ParsedSecretRef("file", None, "~/k")),
    ("keyring:team.vault/ci@build", ParsedSecretRef("keyring", "team.vault", "ci@build")),
]

REJECTED = [
    "s" + "k-" + "a" * 40,
    "env:",
    "env:1BAD",
    "keyring:",
    "keyring:a/",
    "keyring:bad name",
    "file:relative/path",
    "file:" + "/" + "x" * 1024,
    "file:/a\x00b",
    "",
    "vault:x",
]


@pytest.mark.parametrize(("text", "expected"), ACCEPTED, ids=[t for t, _ in ACCEPTED])
def test_accepted(text: str, expected: ParsedSecretRef) -> None:
    assert parse_secret_ref(text) == expected
    assert is_secret_ref(text)
    assert Holder(api_key=text).api_key == text


def _error_text(text: str) -> str:
    with pytest.raises(ValidationError) as info:
        Holder(api_key=text)
    return str(info.value)


@pytest.mark.parametrize("text", REJECTED, ids=range(len(REJECTED)))
def test_rejected_without_echo(text: str) -> None:
    assert not is_secret_ref(text)
    rendered = _error_text(text)
    assert "[CK-CFG-011]" in rendered
    assert f"length {len(text)}" in rendered
    # The error depends only on the length: any other invalid text of that length renders
    # identically, so the rejected text itself cannot be in it.
    assert rendered == _error_text("#" * len(text))


def test_schema_carries_pattern() -> None:
    schema = Holder.model_json_schema()["properties"]["api_key"]
    assert schema["type"] == "string"
    assert schema["pattern"] == SECRET_REF_PATTERN


def test_privacy_level_field_is_case_insensitive() -> None:
    assert LevelHolder(level="l4").level is PrivacyLevel.L4  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        LevelHolder(level="L5")  # type: ignore[arg-type]


# No whitespace or control characters, so SectionModel's whitespace stripping cannot shorten it.
_visible = st.characters(codec="utf-8", blacklist_categories=["Zs", "Zl", "Zp", "Cc"])
_invalid_text = st.text(_visible, min_size=4, max_size=80).filter(lambda t: not is_secret_ref(t))


@given(_invalid_text)
def test_error_never_contains_rejected_text(text: str) -> None:
    assert _error_text(text) == _error_text("#" * len(text))
