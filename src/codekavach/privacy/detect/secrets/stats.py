"""``ScanSecretStats``: how often a value occurs in one scan, without holding the value.

Owning epic: E08.

The repetition filter is two-phase: detectors emit candidates, and the entropy detector asks this
object how many times a candidate's value has been seen in the scan; above
``filters.REPEAT_THRESHOLD`` it **downgrades** the span (still redacted at the default floor,
counted in ``DetectionReport.downgraded``) instead of dropping it, which keeps recall first.

The counts are keyed on an HMAC of the value under the scan salt (I3, I6): the object never
holds a value, ``repr`` shows only the number of distinct values, and it is marked never to be
persisted. One object serves one detection pass over a scan; a second pass over the same slices
(the guard's re-scan) should use a fresh one, or every value would be counted twice.
"""

import hashlib
import hmac
import threading
from typing import Final

from codekavach.core.pipeline.salt import ScanSalt

_KEY_BYTES: Final = 16


class ScanSecretStats:
    """Occurrence counts of values for one scan, keyed on a salted hash."""

    __slots__ = ("_counts", "_lock", "_salt")
    __ck_never_persist__ = True

    def __init__(self, salt: ScanSalt) -> None:
        if not isinstance(salt, ScanSalt):
            raise TypeError("scan secret statistics need a ScanSalt")
        self._salt = salt
        self._counts: dict[bytes, int] = {}
        self._lock = threading.Lock()

    def _key(self, value: str) -> bytes:
        message = value.encode("utf-8", errors="surrogatepass")
        return hmac.new(self._salt.reveal(), message, hashlib.sha256).digest()[:_KEY_BYTES]

    def observe(self, value: str) -> int:
        """Count one more occurrence of ``value`` and return its total so far."""
        key = self._key(value)
        with self._lock:
            total = self._counts.get(key, 0) + 1
            self._counts[key] = total
            return total

    def count(self, value: str) -> int:
        """How many times ``value`` has been observed."""
        key = self._key(value)
        with self._lock:
            return self._counts.get(key, 0)

    def __repr__(self) -> str:
        return f"ScanSecretStats(distinct={len(self._counts)})"
