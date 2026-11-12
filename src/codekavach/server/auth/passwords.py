"""Password hashing with scrypt from the standard library.

Owning epic: E32.

The stored form is ``scrypt$<n>$<r>$<p>$<salt hex>$<hash hex>``, so parameters can be raised later
and ``needs_rehash`` tells when a stored hash is weaker than the current parameters. Verification
uses ``hmac.compare_digest``. ``DUMMY_HASH`` lets the login route spend the same time on an
unknown user as on a wrong password.
"""

import hashlib
import hmac
import secrets
from typing import Final

N: Final = 2**14
R: Final = 8
P: Final = 1
DKLEN: Final = 32
SALT_BYTES: Final = 16
PREFIX: Final = "scrypt"


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=DKLEN, maxmem=128 * 1024 * 1024
    )


def hash_password(password: str) -> str:
    """The storable hash of ``password`` with a fresh random salt."""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _derive(password, salt, N, R, P)
    return f"{PREFIX}${N}${R}${P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Whether ``password`` matches ``stored``; a malformed hash never matches."""
    try:
        prefix, n, r, p, salt, digest = stored.split("$")
        if prefix != PREFIX:
            return False
        candidate = _derive(password, bytes.fromhex(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, bytes.fromhex(digest))


def needs_rehash(stored: str) -> bool:
    """Whether ``stored`` was made with other parameters than the current ones."""
    parts = stored.split("$")
    return len(parts) != 6 or parts[:4] != [PREFIX, str(N), str(R), str(P)]


DUMMY_HASH: Final = hash_password(secrets.token_hex(8))
