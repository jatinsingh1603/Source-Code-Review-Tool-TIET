"""Secret references: the only way a secret may appear in configuration (ADR decision D4).

Owning epic: E03.

A reference names where a secret lives, never the secret itself:

- ``env:NAME``: an environment variable;
- ``keyring:SERVICE/USERNAME`` or ``keyring:USERNAME`` (service ``codekavach``): the OS keyring;
- ``file:PATH``: a file with an absolute POSIX or Windows path, or a path starting with ``~/``.

The most likely invalid value is a real key pasted into an ``api_key`` field, so validation
errors state only the length of the rejected text, never the text (CWE-532). The JSON Schema
carries ``SECRET_REF_PATTERN``; no runtime ``pattern=`` constraint is used, because Pydantic's
pattern error would echo the input. Declare ``SecretRef`` fields only on models with
``hide_input_in_errors=True`` (every ``SectionModel``); otherwise Pydantic itself prints the
rejected value as ``input_value``.
"""

import re
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import AfterValidator, WithJsonSchema

from codekavach.config.constants import KEYRING_SERVICE

SECRET_REF_PATTERN = (
    r"^(env:[A-Za-z_][A-Za-z0-9_]{0,127}"  # noqa: S105 - a regex, not a credential
    r"|keyring:[A-Za-z0-9._@-]{1,128}(/[A-Za-z0-9._@-]{1,128})?"
    r"|file:(/|~/|[A-Za-z]:[\\/]).+)$"
)
MAX_FILE_REF_LENGTH = 1024

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_KEYRING_PART = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")
_ABSOLUTE_FILE = re.compile(r"^(/|~/|[A-Za-z]:[\\/]).+$")

Scheme = Literal["env", "keyring", "file"]


@dataclass(frozen=True, slots=True)
class ParsedSecretRef:
    """The parts of a secret reference."""

    scheme: Scheme
    service: str | None
    locator: str


def _invalid(text: str) -> ValueError:
    return ValueError(
        "[CK-CFG-011] expected a secret reference (env:NAME, keyring:SERVICE/USERNAME or "
        f"file:/path); got a string of length {len(text)}"
    )


def parse_secret_ref(text: str) -> ParsedSecretRef:
    """Parse a reference into its parts.

    Raises:
        ValueError: ``text`` is not a valid reference; the message never contains the text.
    """
    scheme, separator, rest = text.partition(":")
    if not separator:
        raise _invalid(text)
    if scheme == "env" and _ENV_NAME.match(rest):
        return ParsedSecretRef("env", None, rest)
    if scheme == "keyring":
        service, slash, username = rest.partition("/")
        if not slash:
            service, username = KEYRING_SERVICE, rest
        if _KEYRING_PART.match(service) and _KEYRING_PART.match(username):
            return ParsedSecretRef("keyring", service, username)
    if (
        scheme == "file"
        and _ABSOLUTE_FILE.match(rest)
        and len(rest) <= MAX_FILE_REF_LENGTH
        and "\x00" not in rest
    ):
        return ParsedSecretRef("file", None, rest)
    raise _invalid(text)


def is_secret_ref(text: str) -> bool:
    """True when ``text`` is a valid secret reference."""
    try:
        parse_secret_ref(text)
    except ValueError:
        return False
    return True


def _validate(text: str) -> str:
    parse_secret_ref(text)
    return text


SecretRef = Annotated[
    str,
    AfterValidator(_validate),
    WithJsonSchema({"type": "string", "pattern": SECRET_REF_PATTERN}),
]
