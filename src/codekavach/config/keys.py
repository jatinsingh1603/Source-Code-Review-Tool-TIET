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

import importlib
import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import AfterValidator, SecretStr, WithJsonSchema

from codekavach.config.constants import KEYRING_SERVICE, MAX_SECRET_FILE_BYTES
from codekavach.config.errors import ConfigErrorCode, ConfigIssue, SecretResolutionError

if TYPE_CHECKING:
    from codekavach.config.models.llm import ProviderSettings

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


# --- resolution (E03-18) ---------------------------------------------------------------------
#
# Resolution is lazy (a scan on the mock provider never touches the keyring), returns a fresh
# ``SecretStr`` on every call, never caches, and never puts the value, its length, a prefix or a
# hash into an exception, a warning or a status.

KEYRING_UNAVAILABLE_HINT = (
    "no OS keyring is available in this session; use an env: or file: reference"
)
REPOSITORY_FILE_HINT = "secrets must not live in the repository being scanned"

DEFAULT_KEY_ENV: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "anthropic": ("ANTHROPIC_API_KEY",),
        "openai": ("OPENAI_API_KEY",),
        "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "xai": ("XAI_API_KEY",),
        "azure-openai": ("AZURE_OPENAI_API_KEY",),
        "github": ("GITHUB_TOKEN", "GH_TOKEN"),
    }
)
KEY_REQUIRED_KINDS = frozenset({"anthropic", "openai", "gemini", "xai", "azure-openai"})

SecretState = Literal["set", "not-set", "backend-unavailable", "error"]


@dataclass(frozen=True, slots=True)
class SecretStatus:
    """Whether a reference resolves; never carries anything derived from the value."""

    ref: str
    state: SecretState
    detail: str | None = None


class KeyringUnavailableError(Exception):
    """No usable OS keyring in this session."""


def _error(
    ref: str, message: str, *, hint: str | None = None, code: ConfigErrorCode | None = None
) -> SecretResolutionError:
    return SecretResolutionError.single(
        code or ConfigErrorCode.CK_CFG_012, message, source=ref, hint=hint
    )


def _from_env(locator: str, env: Mapping[str, str]) -> str | None:
    return env.get(locator) or None


def open_keyring(ref: str = "keyring") -> Any:
    """The ``keyring`` module, once its active backend is known to be usable and not plaintext.

    Imported lazily so that loading configuration never imports ``keyring``.

    Raises:
        KeyringUnavailableError: no backend can be initialised in this session.
        SecretResolutionError: CK-CFG-014 for a plaintext or failing backend.
    """
    try:
        keyring = importlib.import_module("keyring")
        backend = keyring.get_keyring()
    except Exception as exc:
        raise KeyringUnavailableError from exc
    backend_type = type(backend)
    if backend_type.__module__.startswith("keyrings.alt") or (
        backend_type.__module__ == "keyring.backends.fail" and backend_type.__name__ == "Keyring"
    ):
        raise _error(
            ref,
            "the active keyring backend stores secrets in plain text or cannot store them",
            hint=KEYRING_UNAVAILABLE_HINT,
            code=ConfigErrorCode.CK_CFG_014,
        )
    return keyring


def _from_keyring(ref: str, service: str, username: str) -> str | None:
    keyring = open_keyring(ref)
    errors = importlib.import_module("keyring.errors")
    try:
        value: str | None = keyring.get_password(service, username)
    except errors.KeyringError as exc:
        raise KeyringUnavailableError from exc
    return value or None


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _strip_one_newline(text: str) -> str:
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


def _from_file(
    ref: str, locator: str, project_root: Path | None, warnings: list[ConfigIssue] | None
) -> str | None:
    path = Path(locator).expanduser()
    if project_root is not None and _inside(path, project_root):
        raise _error(ref, "the secret file is inside the project", hint=REPOSITORY_FILE_HINT)
    if not path.exists():
        return None
    if not path.is_file():
        raise _error(ref, "the secret reference does not name a regular file")
    info = path.stat()
    if info.st_size > MAX_SECRET_FILE_BYTES:
        raise _error(ref, f"the secret file is larger than {MAX_SECRET_FILE_BYTES} bytes")
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise _error(ref, "the secret file is not valid UTF-8") from None
    if sys.platform != "win32" and stat.S_IMODE(info.st_mode) & 0o044 and warnings is not None:
        warnings.append(
            ConfigIssue(
                code=ConfigErrorCode.CK_CFG_013,
                severity="warning",
                message="the secret file is readable by group or others",
                source=ref,
                hint=f"run: chmod 600 {path}",
            )
        )
    return _strip_one_newline(text) or None


def _lookup(
    ref: str,
    env: Mapping[str, str] | None,
    project_root: Path | None,
    warnings: list[ConfigIssue] | None,
) -> str | None:
    """The raw value, or ``None`` when not set. Raises on errors and unavailable backends."""
    try:
        parsed = parse_secret_ref(ref)
    except ValueError:
        raise _error(ref, "malformed secret reference", code=ConfigErrorCode.CK_CFG_011) from None
    if parsed.scheme == "env":
        return _from_env(parsed.locator, os.environ if env is None else env)
    if parsed.scheme == "keyring":
        return _from_keyring(ref, parsed.service or KEYRING_SERVICE, parsed.locator)
    return _from_file(ref, parsed.locator, project_root, warnings)


def _unavailable(ref: str) -> SecretResolutionError:
    return _error(ref, "no OS keyring is available", hint=KEYRING_UNAVAILABLE_HINT)


def resolve_secret(
    ref: str,
    *,
    env: Mapping[str, str] | None = None,
    project_root: Path | None = None,
    warnings: list[ConfigIssue] | None = None,
) -> SecretStr:
    """Resolve one reference to a fresh ``SecretStr``.

    Raises:
        SecretResolutionError: CK-CFG-012 when not set or unreadable (including an unavailable
            keyring), CK-CFG-014 for a plaintext keyring backend, CK-CFG-011 when malformed.
    """
    try:
        value = _lookup(ref, env, project_root, warnings)
    except KeyringUnavailableError:
        raise _unavailable(ref) from None
    if value is None:
        raise _error(ref, "the secret reference is not set")
    return SecretStr(value)


def effective_key_refs(kind: str, explicit: str | None) -> tuple[str, ...]:
    """The references tried for a provider: the explicit one, or the conventional variables."""
    if explicit:
        return (explicit,)
    return tuple(f"env:{name}" for name in DEFAULT_KEY_ENV.get(kind, ()))


def resolve_provider_key(
    provider_id: str,
    provider: "ProviderSettings",
    *,
    env: Mapping[str, str] | None = None,
    project_root: Path | None = None,
    warnings: list[ConfigIssue] | None = None,
) -> SecretStr | None:
    """The API key of a provider, or ``None`` when its kind needs none and none is configured.

    Raises:
        SecretResolutionError: CK-CFG-012 when a key is required (or configured) but no
            candidate resolves; the message names the provider and the references tried.
    """
    kind = str(provider.kind)
    refs = effective_key_refs(kind, provider.api_key)
    for ref in refs:
        try:
            value = _lookup(ref, env, project_root, warnings)
        except KeyringUnavailableError:
            raise _unavailable(ref) from None
        if value is not None:
            return SecretStr(value)
    if kind not in KEY_REQUIRED_KINDS and provider.api_key is None:
        return None
    tried = ", ".join(refs) if refs else "no reference"
    raise _error(
        refs[0] if refs else f"llm.providers.{provider_id}",
        f"provider '{provider_id}' ({kind}): no API key. Tried {tried}. Set that variable, or "
        f"run 'codekavach config key set {provider_id}' and use "
        # pragma: allowlist nextline secret
        f'api_key = "keyring:codekavach/{provider_id}".',
    )


def secret_status(
    ref: str, *, env: Mapping[str, str] | None = None, project_root: Path | None = None
) -> SecretStatus:
    """Report whether ``ref`` resolves, without revealing anything about the value."""
    try:
        value = _lookup(ref, env, project_root, None)
    except KeyringUnavailableError:
        return SecretStatus(ref, "backend-unavailable", KEYRING_UNAVAILABLE_HINT)
    except SecretResolutionError as exc:
        return SecretStatus(ref, "error", exc.issues[0].message)
    return SecretStatus(ref, "set" if value is not None else "not-set")
