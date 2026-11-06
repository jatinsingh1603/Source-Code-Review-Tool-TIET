"""Errors of the mapping vault.

Owning epic: E10.

No message here quotes an original, a key, a passphrase or a ciphertext: exception text is logged
and printed, and the vault holds exactly what must never appear there (invariant I3).
"""


class VaultError(Exception):
    """The vault could not do what was asked; nothing was sent or restored (I4)."""


class VaultKeyError(VaultError):
    """The master key does not open this vault, or the file has been altered.

    AES-GCM authenticates what it decrypts, so a wrong key and a tampered file fail the same way
    and neither returns garbage.
    """


class VaultConsistencyError(VaultError):
    """A pseudonym of one scan would stand for two different originals: the generator collided."""


class VaultFormatError(VaultError):
    """The file is not a vault, or is of a format this version cannot read."""


class KeySourceUnavailable(VaultError):  # noqa: N818 - named by the E10-01 interface contract
    """The configured key source cannot supply a master key in this session."""
