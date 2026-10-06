"""Detached Ed25519 signatures of organisation policy files (ADR decision D7, E03-31).

Owning epic: E03.

When a policy public key is configured, every discovered policy must have a ``<policy>.sig``
file next to it: ASCII base64 of the 64-byte Ed25519 signature over the raw bytes of the policy,
with an optional trailing newline and at most 256 bytes. The policy is read once; the same bytes
are verified and then parsed. A missing, malformed or wrong signature is code 054, fail closed.
Only Ed25519 is accepted, which avoids algorithm-confusion bugs. The public key is a PEM
``SubjectPublicKeyInfo`` file, found in ``CODEKAVACH_ORG_POLICY_PUBKEY`` or as ``policy.pub``
next to a system policy path (first match wins).

``cryptography`` is imported inside the functions that need it, so a load without a configured
key does not pay its import time (E03-44).

Limits:

- **Replay.** An older, validly signed policy still verifies. Set ``expires`` (code 056), and
  pair signatures with the SHA-256 pin where a pipeline template can set it.
- **Trust anchor.** If the public key comes from the environment variable, whoever controls the
  environment controls the anchor. Prefer the system path on managed machines, and a protected
  pipeline template in CI.
"""

import base64
import binascii
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from codekavach.config.errors import ConfigErrorCode, OrgPolicyError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

PUBKEY_ENV = "CODEKAVACH_ORG_POLICY_PUBKEY"
PUBKEY_FILE_NAME = "policy.pub"
SIGNATURE_SUFFIX = ".sig"
SIGNATURE_LENGTH = 64
MAX_SIGNATURE_BYTES = 256
MAX_KEY_BYTES = 16 * 1024


def _error(message: str, path: Path | None = None, hint: str | None = None) -> OrgPolicyError:
    return OrgPolicyError.single(
        ConfigErrorCode.CK_CFG_054,
        message,
        source=str(path) if path is not None else None,
        hint=hint,
    )


def _read_small(path: Path, limit: int, what: str) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        raise _error(f"{what} cannot be read", path) from None
    if len(data) > limit:
        raise _error(f"{what} is larger than {limit} bytes", path)
    return data


def signature_path(policy_path: Path) -> Path:
    """The detached signature file of ``policy_path`` (``policy.toml.sig``)."""
    return policy_path.with_name(policy_path.name + SIGNATURE_SUFFIX)


def find_public_key(env: Mapping[str, str], system_dirs: Sequence[Path]) -> Path | None:
    """The configured public key: the environment variable, then ``policy.pub`` in a system dir."""
    named = env.get(PUBKEY_ENV, "").strip()
    if named:
        return Path(named).expanduser()
    for directory in system_dirs:
        candidate = directory / PUBKEY_FILE_NAME
        if candidate.is_file():
            return candidate
    return None


def load_public_key(path: Path) -> "Ed25519PublicKey":
    """Load an Ed25519 public key from a PEM ``SubjectPublicKeyInfo`` file.

    Raises:
        OrgPolicyError: code 054 when the file is unreadable, not PEM or not an Ed25519 key.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        load_pem_public_key,
    )

    data = _read_small(path, MAX_KEY_BYTES, "policy public key")
    try:
        key = load_pem_public_key(data)
    except (ValueError, TypeError):
        raise _error("policy public key is not a PEM public key", path) from None
    if not isinstance(key, Ed25519PublicKey):
        raise _error("policy public key is not an Ed25519 key", path, "only Ed25519 is accepted")
    return key


def _group_or_world_access(path: Path) -> bool:
    if os.name == "nt":  # POSIX mode bits only; Windows ACLs are not checked here (E03-12)
        return False
    return bool(stat.S_IMODE(path.stat().st_mode) & 0o077)


def load_private_key(path: Path, passphrase: bytes | None) -> "Ed25519PrivateKey":
    """Load an Ed25519 private key from a PEM PKCS#8 file, optionally encrypted.

    The caller passes the passphrase; this function does not prompt.

    Raises:
        OrgPolicyError: code 054 when the file is readable by group or others, unreadable, not
            PEM PKCS#8, encrypted with another passphrase, or not an Ed25519 key.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        load_pem_private_key,
    )

    try:
        if _group_or_world_access(path):
            raise _error(
                "policy signing key is readable by group or others",
                path,
                "restrict it to its owner (chmod 600)",
            )
    except OSError:
        raise _error("policy signing key cannot be read", path) from None
    data = _read_small(path, MAX_KEY_BYTES, "policy signing key")
    try:
        key = load_pem_private_key(data, password=passphrase)
    except TypeError:
        raise _error(
            "policy signing key needs a passphrase"
            if passphrase is None
            else "policy signing key is not encrypted; do not pass a passphrase",
            path,
        ) from None
    except ValueError:
        raise _error("policy signing key cannot be decrypted or is not PEM", path) from None
    if not isinstance(key, Ed25519PrivateKey):
        raise _error("policy signing key is not an Ed25519 key", path, "only Ed25519 is accepted")
    return key


def sign_policy(policy_bytes: bytes, key: "Ed25519PrivateKey") -> str:
    """The base64 Ed25519 signature of ``policy_bytes`` (the content of a ``.sig`` file)."""
    return base64.b64encode(key.sign(policy_bytes)).decode("ascii")


def decode_signature(signature_b64: str) -> bytes:
    """The 64 signature bytes of a ``.sig`` text.

    Raises:
        OrgPolicyError: code 054 when the text is not strict base64 of 64 bytes.
    """
    text = signature_b64.strip()
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise _error("policy signature is not valid base64") from None
    if len(raw) != SIGNATURE_LENGTH:
        raise _error(f"policy signature has {len(raw)} bytes; Ed25519 has {SIGNATURE_LENGTH}")
    return raw


def verify_policy(policy_bytes: bytes, signature_b64: str, key: "Ed25519PublicKey") -> None:
    """Verify ``signature_b64`` over ``policy_bytes``.

    Raises:
        OrgPolicyError: code 054 when the signature is malformed or does not verify.
    """
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415

    raw = decode_signature(signature_b64)
    try:
        key.verify(raw, policy_bytes)
    except InvalidSignature:
        raise _error(
            "organisation policy signature does not verify",
            hint="the policy or its .sig changed after signing, or another key signed it",
        ) from None


def read_signature(policy_path: Path) -> str:
    """The text of ``<policy>.sig`` (at most 256 bytes, ASCII).

    Raises:
        OrgPolicyError: code 054 when the file is missing, larger than 256 bytes or not ASCII.
    """
    path = signature_path(policy_path)
    if not path.is_file():
        raise _error(
            "organisation policy has no signature file",
            policy_path,
            f"a policy public key is configured, so {path.name} is required",
        )
    data = _read_small(path, MAX_SIGNATURE_BYTES, "policy signature")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise _error("policy signature is not ASCII", path) from None
