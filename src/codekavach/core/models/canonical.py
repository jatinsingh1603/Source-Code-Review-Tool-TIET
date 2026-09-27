"""Canonical JSON encoding and SHA-256 helpers for hashed structures.

Owning epic: E02. Payload hashes, the egress ledger chain and finding fingerprints all hash
this encoding, so it must never change between versions (invariant I5). It is deliberately
simpler than RFC 8785: hashed structures contain only strings, integers, booleans and nulls,
and a float anywhere in the value is rejected.
"""

import hashlib
import json

from pydantic import BaseModel

from codekavach.core.models.errors import ModelError


def _reject_floats(value: object) -> None:
    if isinstance(value, float):
        raise ModelError("canonical JSON does not accept floating-point values")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _reject_floats(item)


def canonical_json(obj: object, *, exclude: frozenset[str] = frozenset()) -> bytes:
    """Return the canonical UTF-8 JSON encoding of a model or a JSON-compatible value.

    Keys are sorted, separators carry no whitespace, non-ASCII text is kept as is, and there is
    no trailing newline. ``exclude`` names top-level model fields to leave out.
    """
    data = obj.model_dump(mode="json", exclude=set(exclude)) if isinstance(obj, BaseModel) else obj
    _reject_floats(data)
    try:
        text = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise ModelError("text is not valid Unicode") from None
    except (TypeError, ValueError):
        raise ModelError("value is not JSON-compatible") from None


def sha256_hex(data: bytes | str) -> str:
    """Return the SHA-256 digest of ``data`` (a str is UTF-8 encoded) as lower-case hex."""
    if isinstance(data, str):
        try:
            data = data.encode("utf-8")
        except UnicodeEncodeError:
            raise ModelError("text is not valid Unicode") from None
    return hashlib.sha256(data).hexdigest()
