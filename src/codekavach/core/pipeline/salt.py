"""The scan salt: secret material behind deterministic pseudonyms (I5).

Owning epic: E04.

``ScanSalt`` keeps the bytes out of every accidental channel: ``repr``, ``str`` and formatting print
``ScanSalt(<redacted>)``; pickling and ``copy``/``deepcopy`` raise ``TypeError``; the
never-persist marker makes every artefact store refuse it; there is no ``__dict__``. Only
``reveal()`` returns the bytes (callers: the pseudonymiser, E09, and the vault, E10). The one-way
``fingerprint()`` may appear in the manifest and the checkpoint (I3).

Whether one salt is reused across scans of a project (stable pseudonyms) or a fresh one is used per
scan (less linkability) is decided by E10 and E25, not here.
"""

import hashlib
import hmac
import secrets
from typing import Any, NoReturn, Self

SALT_BYTES = 32
MIN_SALT_BYTES = 16
_FINGERPRINT_PREFIX = b"ck-salt-fp-v1"
_REDACTED = "ScanSalt(<redacted>)"


class ScanSalt:
    """Secret salt bytes that cannot be printed, logged, pickled or stored by accident."""

    __slots__ = ("_value",)
    __ck_never_persist__ = True
    _value: bytes

    def __init__(self, value: object) -> None:
        if not isinstance(value, bytes) or len(value) < MIN_SALT_BYTES:
            raise ValueError(f"a scan salt needs at least {MIN_SALT_BYTES} bytes")
        object.__setattr__(self, "_value", value)

    @classmethod
    def generate(cls) -> Self:
        """A fresh salt of 32 random bytes."""
        return cls(secrets.token_bytes(SALT_BYTES))

    @classmethod
    def from_hex(cls, text: object) -> Self:
        """A salt from exactly 64 hexadecimal characters; the message never echoes the text."""
        if not isinstance(text, str) or len(text) != 2 * SALT_BYTES:
            raise ValueError(f"a scan salt in hex has exactly {2 * SALT_BYTES} characters")
        try:
            return cls(bytes.fromhex(text))
        except ValueError:
            raise ValueError("a scan salt in hex contains only hexadecimal digits") from None

    def reveal(self) -> bytes:
        """The salt bytes; for the pseudonymiser and the vault only."""
        return self._value

    def fingerprint(self) -> str:
        """A one-way, 16-hex-character identifier of the salt."""
        return hashlib.sha256(_FINGERPRINT_PREFIX + self._value).hexdigest()[:16]

    def __repr__(self) -> str:
        return _REDACTED

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, spec: str) -> str:
        return _REDACTED

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScanSalt):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        return hash(self.fingerprint())

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        raise AttributeError("ScanSalt is immutable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("a scan salt cannot be pickled or copied")

    def __reduce_ex__(self, protocol: Any) -> NoReturn:
        raise TypeError("a scan salt cannot be pickled or copied")

    def __copy__(self) -> NoReturn:
        raise TypeError("a scan salt cannot be pickled or copied")

    def __deepcopy__(self, memo: Any) -> NoReturn:
        raise TypeError("a scan salt cannot be pickled or copied")
