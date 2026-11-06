"""Envelope encryption for the mapping vault.

Owning epic: E10.

**Envelope.** A random 256-bit *data key* is made once per vault. It seals every record. The
*master key* (from the keyring, a passphrase or a key-management service) seals only the data key,
and that sealed data key lives in the vault header. Rotating the master key (E10-03) therefore
rewrites one header field and not every record.

**Records.** A record is sealed with AES-256-GCM. Its associated data is the scan id and the
pseudonym, so a ciphertext moved to another pseudonym or another scan fails authentication
instead of restoring the wrong original.

**Nonces.** GCM fails catastrophically when a nonce repeats under one key, so a nonce is never
drawn at random per record. It is a 32-bit random per-vault prefix followed by a 64-bit counter
kept in the header. The store reads the counter, uses the values after it and writes the new
counter in the same write transaction as the records, so two writers (threads or processes) take
turns and cannot hand out the same value. The data-key wrap is the one random nonce: it is made
once per master key, so with a few wraps in the life of a vault the chance of a repeat is
negligible.

**Index.** ``index_hash`` is ``HMAC-SHA256(subkey of the data key, original)`` cut to 16 bytes. It
lets the vault find an original without a plaintext index. It is deterministic, so whoever holds
the file can see that two records have equal originals; they would also hold the ciphertexts.

**Memory.** Python cannot promise to erase a value from memory. The key is held inside the
``AESGCM`` object and a derived sub-key; ``close`` drops both references. The controls that count
are the encrypted file, a short process lifetime, and the absence of any export path.
"""

import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from codekavach.privacy.vault.errors import VaultKeyError

KEY_BYTES = 32
NONCE_BYTES = 12
PREFIX_BYTES = 4
COUNTER_BYTES = 8
COUNTER_LIMIT = 2**63 - 1  # the largest integer SQLite stores in the header
INDEX_BYTES = 16
_INDEX_LABEL = b"ck-vault-index-v1"
WRAP_CONTEXT = b"ck-vault-data-key-v1"


def new_data_key() -> bytes:
    """A fresh 256-bit data key."""
    return secrets.token_bytes(KEY_BYTES)


def new_nonce_prefix() -> bytes:
    """The random per-vault part of every record nonce."""
    return secrets.token_bytes(PREFIX_BYTES)


def build_nonce(prefix: bytes, counter: int) -> bytes:
    """The 96-bit nonce of record number ``counter`` (1-based) of a vault with this prefix."""
    if len(prefix) != PREFIX_BYTES or not 0 < counter <= COUNTER_LIMIT:
        raise VaultKeyError("the nonce counter of this vault is exhausted or invalid")
    return prefix + counter.to_bytes(COUNTER_BYTES, "big")


def wrap_data_key(master_key: bytes, data_key: bytes) -> bytes:
    """The data key sealed under the master key: a random nonce followed by the ciphertext."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce + AESGCM(master_key).encrypt(nonce, data_key, WRAP_CONTEXT)


def unwrap_data_key(master_key: bytes, wrapped: bytes) -> bytes:
    """The data key, or ``VaultKeyError`` when the master key is wrong or the header was altered."""
    if len(wrapped) <= NONCE_BYTES or len(master_key) != KEY_BYTES:
        raise VaultKeyError("the vault key does not open this vault")
    try:
        return AESGCM(master_key).decrypt(
            wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], WRAP_CONTEXT
        )
    except InvalidTag:
        raise VaultKeyError("the vault key does not open this vault") from None


def record_aad(scan_id: str, pseudonym: str) -> bytes:
    """The associated data that binds a record to its scan and pseudonym."""
    return f"ck-record-v1\x00{scan_id}\x00{pseudonym}".encode()


class RecordCipher:
    """Seals and opens records under one data key; holds the key and nothing else secret."""

    __slots__ = ("_aead", "_index_key")

    def __init__(self, data_key: bytes) -> None:
        if len(data_key) != KEY_BYTES:
            raise VaultKeyError("the data key has the wrong length")
        self._aead: AESGCM | None = AESGCM(data_key)
        self._index_key: bytes | None = hmac.new(data_key, _INDEX_LABEL, hashlib.sha256).digest()

    def __repr__(self) -> str:
        return "RecordCipher(<redacted>)"

    def seal(self, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        """Authenticated encryption of ``plaintext`` bound to ``aad``."""
        if self._aead is None:
            raise VaultKeyError("the vault is closed")
        return self._aead.encrypt(nonce, plaintext, aad)

    def open(self, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        """The plaintext, or ``VaultKeyError`` when the ciphertext or its binding was altered."""
        if self._aead is None:
            raise VaultKeyError("the vault is closed")
        try:
            return self._aead.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise VaultKeyError("a vault record failed authentication") from None

    def index_hash(self, original: str) -> bytes:
        """The keyed 16-byte index of an original; equal originals have equal indexes."""
        if self._index_key is None:
            raise VaultKeyError("the vault is closed")
        digest = hmac.new(
            self._index_key, original.encode("utf-8", "surrogatepass"), hashlib.sha256
        ).digest()
        return digest[:INDEX_BYTES]

    def close(self) -> None:
        """Drop the key references; the garbage collector decides when the bytes go."""
        self._aead = None
        self._index_key = None
