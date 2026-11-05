"""``PlaceholderNumbering``: a stable index per distinct value, without keeping the value.

Owning epic: E08.

The model must be able to tell "the same key used twice" from "two different keys" without seeing
either (``docs/research/INSIGHTS.md`` section 3.3 item 8), so the index is keyed on the **value**,
not the occurrence, and lives for a whole scan: the same secret in two files gets the same index.

The dictionary key is ``hmac_sha256(scan_salt, kind NUL subtype NUL value)`` cut to 16 bytes, not
the value, so a memory dump, a ``repr`` or a pickle of this object cannot yield a secret.
``repr`` prints bucket counts only. There is no fallback to a plain dictionary: without a
``ScanSalt`` the constructor raises.
"""

import hashlib
import hmac
import threading
from collections.abc import Mapping
from typing import Final

from codekavach.core.models import PlaceholderKind
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.errors import RedactionError

MAX_INDEX: Final = 999_999  # the placeholder grammar allows six digits (E02-12)
_KEY_BYTES: Final = 16


class PlaceholderNumbering:
    """Per-scan, value-keyed, 1-based, contiguous-per-bucket placeholder indices."""

    __slots__ = ("_buckets", "_lock", "_salt")
    __ck_never_persist__ = True

    def __init__(self, salt: ScanSalt) -> None:
        if not isinstance(salt, ScanSalt):
            raise TypeError("placeholder numbering needs a ScanSalt")
        self._salt = salt
        self._buckets: dict[tuple[PlaceholderKind, str], dict[bytes, int]] = {}
        self._lock = threading.Lock()

    def _digest(self, kind: PlaceholderKind, subtype: str, value: str) -> bytes:
        message = f"{kind.value}\x00{subtype}\x00{value}".encode("utf-8", errors="surrogatepass")
        return hmac.new(self._salt.reveal(), message, hashlib.sha256).digest()[:_KEY_BYTES]

    def index_for(self, kind: PlaceholderKind, subtype: str, value: str) -> int:
        """The index of ``value`` in the ``(kind, subtype)`` bucket, assigned on first sight.

        Raises:
            RedactionError: the bucket already holds the largest index the grammar allows.
        """
        digest = self._digest(kind, subtype, value)
        with self._lock:
            bucket = self._buckets.setdefault((kind, subtype), {})
            index = bucket.get(digest)
            if index is None:
                index = len(bucket) + 1
                if index > MAX_INDEX:
                    raise RedactionError("too many distinct values of one placeholder type")
                bucket[digest] = index
            return index

    def counts(self) -> Mapping[tuple[PlaceholderKind, str], int]:
        """The number of distinct values seen per ``(kind, subtype)`` bucket."""
        with self._lock:
            return {key: len(bucket) for key, bucket in self._buckets.items()}

    def __repr__(self) -> str:
        shown = ", ".join(
            f"{kind.value}:{subtype}={count}"
            for (kind, subtype), count in sorted(self.counts().items())
        )
        return f"PlaceholderNumbering({shown})"
