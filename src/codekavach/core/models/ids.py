"""ULID generator and prefixed, typed identifiers for the core entities.

Owning epic: E02. Ids sort by creation time and are safe in URLs and file names. They carry no
client data but embed a creation timestamp, so they are never placed in a prompt or a
SanitisedPayload. An id is not the cross-scan identity of a weakness; that is the fingerprint.
"""

import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, NewType

from pydantic import StringConstraints

from codekavach.core.models.errors import ModelError

# pragma: allowlist nextline secret
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {char: index for index, char in enumerate(_ALPHABET)}
_ULID_LENGTH = 26
_TIME_BITS = 48
_RANDOM_BITS = 80
_RANDOM_BYTES = _RANDOM_BITS // 8
_ULID_BODY = r"[0-7][0-9A-HJKMNP-TV-Z]{25}"
_ULID_RE = re.compile(rf"^{_ULID_BODY}$")


def encode_ulid(timestamp_ms: int, randomness: bytes) -> str:
    """Encode a 48-bit millisecond timestamp and 80 bits of randomness as a ULID string."""
    if not 0 <= timestamp_ms < 1 << _TIME_BITS:
        raise ModelError("ULID timestamp must fit in 48 bits")
    if len(randomness) != _RANDOM_BYTES:
        raise ModelError("ULID randomness must be exactly 10 bytes")
    value = (timestamp_ms << _RANDOM_BITS) | int.from_bytes(randomness, "big")
    chars = []
    for _ in range(_ULID_LENGTH):
        value, index = divmod(value, 32)
        chars.append(_ALPHABET[index])
    return "".join(reversed(chars))


def decode_ulid(value: str) -> tuple[int, bytes]:
    """Return the timestamp in milliseconds and the 10 random bytes of a ULID.

    Only upper-case canonical text is accepted: no lower case and no Crockford aliases.
    """
    if not _ULID_RE.match(value):
        raise ModelError("not a canonical ULID")
    number = 0
    for char in value:
        number = number * 32 + _DECODE[char]
    randomness = (number & ((1 << _RANDOM_BITS) - 1)).to_bytes(_RANDOM_BYTES, "big")
    return number >> _RANDOM_BITS, randomness


def is_ulid(value: str) -> bool:
    """Return True when ``value`` is a canonical ULID."""
    return bool(_ULID_RE.match(value))


def ulid_datetime(value: str) -> datetime:
    """Return the creation time embedded in a ULID, in UTC."""
    timestamp_ms, _ = decode_ulid(value)
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC)


def _system_clock_ms() -> int:
    return time.time_ns() // 1_000_000


class UlidFactory:
    """Thread-safe, monotonic ULID factory with injectable clock and entropy.

    Within one millisecond, or when the clock steps backwards, the previous timestamp is kept
    and the previous randomness is incremented by one, so ids still sort in creation order.
    """

    def __init__(
        self,
        clock_ms: Callable[[], int] | None = None,
        entropy: Callable[[int], bytes] | None = None,
    ) -> None:
        self._clock_ms = clock_ms if clock_ms is not None else _system_clock_ms
        self._entropy = entropy if entropy is not None else secrets.token_bytes
        self._lock = threading.Lock()
        self._last_ms: int | None = None
        self._last_random = 0

    def reset(self) -> None:
        """Forget the last id and replace the lock (used after fork in the child)."""
        self._lock = threading.Lock()
        self._last_ms = None
        self._last_random = 0

    def new(self) -> str:
        """Return a new ULID, strictly greater than the previous one from this factory."""
        with self._lock:
            now = self._clock_ms()
            if self._last_ms is not None and now <= self._last_ms:
                randomness = self._last_random + 1
                if randomness >= 1 << _RANDOM_BITS:
                    raise ModelError("ULID randomness overflow within one millisecond")
                now = self._last_ms
            else:
                randomness = int.from_bytes(self._entropy(_RANDOM_BYTES), "big")
            self._last_ms = now
            self._last_random = randomness
            return encode_ulid(now, randomness.to_bytes(_RANDOM_BYTES, "big"))


_default_factory = UlidFactory()

if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_default_factory.reset)


def new_ulid() -> str:
    """Return a new ULID from the module-level default factory."""
    return _default_factory.new()


def id_prefix(value: str) -> str:
    """Return the prefix of a typed id including the underscore, for example ``scan_``."""
    head, sep, _ = value.partition("_")
    if not sep:
        raise ModelError("value has no id prefix")
    return head + sep


def strip_prefix(value: str) -> str:
    """Return the ULID part of a typed id."""
    return value[len(id_prefix(value)) :]


def _pattern(prefix: str) -> str:
    return rf"^{prefix}{_ULID_BODY}$"


ProjectId = NewType("ProjectId", str)
ScanId = NewType("ScanId", str)
CandidateId = NewType("CandidateId", str)
SliceId = NewType("SliceId", str)
PayloadId = NewType("PayloadId", str)
FindingId = NewType("FindingId", str)

ProjectIdField = Annotated[ProjectId, StringConstraints(pattern=_pattern("proj_"))]
ScanIdField = Annotated[ScanId, StringConstraints(pattern=_pattern("scan_"))]
CandidateIdField = Annotated[CandidateId, StringConstraints(pattern=_pattern("cand_"))]
SliceIdField = Annotated[SliceId, StringConstraints(pattern=_pattern("slice_"))]
PayloadIdField = Annotated[PayloadId, StringConstraints(pattern=_pattern("pay_"))]
FindingIdField = Annotated[FindingId, StringConstraints(pattern=_pattern("find_"))]


def new_project_id() -> ProjectId:
    """Return a new project id (``proj_`` + ULID)."""
    return ProjectId("proj_" + new_ulid())


def new_scan_id() -> ScanId:
    """Return a new scan id (``scan_`` + ULID)."""
    return ScanId("scan_" + new_ulid())


def new_candidate_id() -> CandidateId:
    """Return a new candidate id (``cand_`` + ULID)."""
    return CandidateId("cand_" + new_ulid())


def new_slice_id() -> SliceId:
    """Return a new slice id (``slice_`` + ULID)."""
    return SliceId("slice_" + new_ulid())


def new_payload_id() -> PayloadId:
    """Return a new payload id (``pay_`` + ULID)."""
    return PayloadId("pay_" + new_ulid())


def new_finding_id() -> FindingId:
    """Return a new finding id (``find_`` + ULID)."""
    return FindingId("find_" + new_ulid())
