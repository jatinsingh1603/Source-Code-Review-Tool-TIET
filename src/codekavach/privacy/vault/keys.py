"""Where the vault's master key comes from.

Owning epic: E10.

Four sources, one result: 32 bytes wrapped in ``SecretBytes``.

- ``keyring``: a random key stored under the service ``codekavach-vault`` in the operating system
  credential store, one entry per vault (the account is the vault id kept in the header). Plain
  text keyring backends are refused.
- ``passphrase``: ``scrypt`` over the passphrase with the cost parameters and the per-vault salt
  recorded in the vault header, so a vault made under old parameters still opens after the
  defaults change. The passphrase comes from ``privacy.vault.passphrase`` (a secret reference) or
  from the ``prompt`` callable and is never stored.
- ``kms``: an external key-management service. Not available before E10-03.
- ``ephemeral``: a key that lives as long as the process, for tests; it refuses to run when the
  process is not under pytest.

The default scrypt cost is N=2**15, r=8, p=1: 32 MiB and about 0.1 s on a laptop, inside the
400 ms budget for opening a vault. A stronger cost is a header field away.
"""

import hashlib
import secrets
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar, Final, NoReturn

from codekavach.config import Settings
from codekavach.config.errors import ConfigError
from codekavach.config.keys import KeyringUnavailableError, open_keyring, resolve_secret
from codekavach.privacy.vault.crypto import KEY_BYTES
from codekavach.privacy.vault.errors import KeySourceUnavailable, VaultFormatError

KEYRING_SERVICE: Final = "codekavach-vault"
DEFAULT_SCRYPT_N: Final = 2**15
DEFAULT_SCRYPT_R: Final = 8
DEFAULT_SCRYPT_P: Final = 1
SCRYPT_SALT_BYTES: Final = 16
# A header is read before it is trusted: these caps stop a planted vault from asking for gigabytes.
_MAX_N: Final = 2**21
_MAX_R: Final = 32
_MAX_P: Final = 16
_MAX_MEMORY: Final = 2**30
_EPHEMERAL_KEYS: dict[str, bytes] = {}


class KeySource(StrEnum):
    """Where a master key comes from."""

    KEYRING = "keyring"
    PASSPHRASE = "passphrase"  # noqa: S105 - a source name, not a secret
    KMS = "kms"
    EPHEMERAL = "ephemeral"


class SecretBytes:
    """Key bytes that cannot be printed, logged, pickled or stored by accident."""

    __slots__ = ("_value",)
    __ck_never_persist__: ClassVar[bool] = True
    _value: bytes

    def __init__(self, value: bytes) -> None:
        if len(value) != KEY_BYTES:
            raise ValueError(f"a master key has exactly {KEY_BYTES} bytes")
        object.__setattr__(self, "_value", value)

    def reveal(self) -> bytes:
        """The key bytes; for the vault only."""
        return self._value

    def __repr__(self) -> str:
        return "SecretBytes(<redacted>)"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return "SecretBytes(<redacted>)"

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        raise AttributeError("SecretBytes is immutable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("a key cannot be pickled or copied")

    def __reduce_ex__(self, protocol: Any) -> NoReturn:
        raise TypeError("a key cannot be pickled or copied")

    def __copy__(self) -> NoReturn:
        raise TypeError("a key cannot be pickled or copied")

    def __deepcopy__(self, memo: Any) -> NoReturn:
        raise TypeError("a key cannot be pickled or copied")


@dataclass(frozen=True, slots=True)
class ScryptParams:
    """The cost parameters and salt of one passphrase-derived key; recorded in the header."""

    salt: bytes
    n: int = DEFAULT_SCRYPT_N
    r: int = DEFAULT_SCRYPT_R
    p: int = DEFAULT_SCRYPT_P

    def __post_init__(self) -> None:
        valid = (
            len(self.salt) >= SCRYPT_SALT_BYTES
            and 2 <= self.n <= _MAX_N
            and self.n & (self.n - 1) == 0
            and 1 <= self.r <= _MAX_R
            and 1 <= self.p <= _MAX_P
            and 128 * self.n * self.r <= _MAX_MEMORY
        )
        if not valid:
            raise VaultFormatError("the key derivation parameters of this vault are invalid")

    @classmethod
    def fresh(cls) -> "ScryptParams":
        """Current default cost with a new random salt."""
        return cls(salt=secrets.token_bytes(SCRYPT_SALT_BYTES))

    def to_json(self) -> dict[str, Any]:
        """The header form."""
        return {"kdf": "scrypt", "n": self.n, "r": self.r, "p": self.p, "salt": self.salt.hex()}

    @classmethod
    def from_json(cls, data: object) -> "ScryptParams":
        """Read the header form; anything unexpected is a format error."""
        try:
            if not isinstance(data, Mapping) or data["kdf"] != "scrypt":
                raise TypeError
            return cls(
                salt=bytes.fromhex(data["salt"]),
                n=int(data["n"]),
                r=int(data["r"]),
                p=int(data["p"]),
            )
        except (KeyError, TypeError, ValueError):
            raise VaultFormatError(
                "the key derivation parameters of this vault are invalid"
            ) from None


def derive_passphrase_key(passphrase: str, params: ScryptParams) -> SecretBytes:
    """The master key for ``passphrase`` under ``params``."""
    key = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=params.salt,
        n=params.n,
        r=params.r,
        p=params.p,
        maxmem=_MAX_MEMORY + 2**20,
        dklen=KEY_BYTES,
    )
    return SecretBytes(key)


def _from_keyring(account: str, *, create: bool) -> SecretBytes:
    try:
        keyring = open_keyring("keyring")
        stored = keyring.get_password(KEYRING_SERVICE, account)
        if stored is None and create:
            keyring.set_password(KEYRING_SERVICE, account, secrets.token_hex(KEY_BYTES))
            stored = keyring.get_password(KEYRING_SERVICE, account)
    except (KeyringUnavailableError, ConfigError):
        raise KeySourceUnavailable(
            "the OS keyring is not available or stores secrets in plain text"
        ) from None
    except Exception:  # noqa: BLE001 - any backend failure means unavailable; no detail is kept
        raise KeySourceUnavailable("the OS keyring refused the request") from None
    if stored is None:
        raise KeySourceUnavailable("the keyring has no key for this vault")
    try:
        return SecretBytes(bytes.fromhex(stored))
    except ValueError:
        raise KeySourceUnavailable("the keyring entry for this vault is not a vault key") from None


def _from_passphrase(
    settings: Settings | None,
    prompt: Callable[[], str] | None,
    kdf: ScryptParams | None,
    env: Mapping[str, str] | None,
) -> SecretBytes:
    if kdf is None:
        raise KeySourceUnavailable("a passphrase key needs the vault's key derivation parameters")
    reference = None if settings is None else settings.privacy.vault.passphrase
    passphrase: str | None = None
    if reference is not None:
        try:
            passphrase = resolve_secret(str(reference), env=env).get_secret_value()
        except ConfigError:
            raise KeySourceUnavailable("privacy.vault.passphrase could not be resolved") from None
    elif prompt is not None:
        passphrase = prompt()
    if not passphrase:
        raise KeySourceUnavailable("no passphrase was supplied for this vault")
    return derive_passphrase_key(passphrase, kdf)


def _ephemeral(account: str) -> SecretBytes:
    if "pytest" not in sys.modules:
        raise KeySourceUnavailable("the ephemeral key source is for tests only")
    return SecretBytes(_EPHEMERAL_KEYS.setdefault(account, secrets.token_bytes(KEY_BYTES)))


def resolve_master_key(
    source: KeySource | str,
    *,
    settings: Settings | None,
    prompt: Callable[[], str] | None = None,
    account: str = "default",
    kdf: ScryptParams | None = None,
    env: Mapping[str, str] | None = None,
    create: bool = True,
) -> SecretBytes:
    """The master key from ``source``.

    ``account`` names the keyring entry (the vault id); ``kdf`` is the header's scrypt record and
    is needed for a passphrase; ``create`` lets the keyring source make the entry on first use.

    Raises:
        KeySourceUnavailable: the source cannot supply a key here; the message names the cause
            and never a key or passphrase.
    """
    try:
        key_source = KeySource(source)
    except ValueError:
        raise KeySourceUnavailable("unknown vault key source") from None
    if key_source is KeySource.KEYRING:
        return _from_keyring(account, create=create)
    if key_source is KeySource.PASSPHRASE:
        return _from_passphrase(settings, prompt, kdf, env)
    if key_source is KeySource.EPHEMERAL:
        return _ephemeral(account)
    raise KeySourceUnavailable(
        "the key-management source is not available yet; it arrives with issue E10-03"
    )
