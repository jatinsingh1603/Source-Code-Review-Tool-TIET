"""Shared metric-token grammar for CVSS vector strings.

Owning epic: E29. A vector is a prefix (``CVSS:4.0``) followed by ``/KEY:VALUE`` tokens. Parsing
rejects an unknown prefix, unknown keys, unknown values, duplicate keys, a missing mandatory key
and, when ``ordered`` is set, tokens out of the specification's order.
"""

from collections.abc import Mapping, Sequence

from codekavach.core.log import get_logger

_log = get_logger(__name__)


class CvssVectorError(ValueError):
    """A CVSS vector string does not follow the specification grammar."""


def parse_metrics(
    text: str,
    *,
    prefix: str,
    order: Sequence[str],
    values: Mapping[str, frozenset[str]],
    mandatory: Sequence[str],
    ordered: bool = True,
) -> dict[str, str]:
    """Return ``{metric: value}`` for ``text``; raises CvssVectorError on any grammar error."""
    parts = text.strip().split("/")
    if not parts or parts[0] != prefix:
        raise CvssVectorError(f"vector must start with {prefix}")
    metrics: dict[str, str] = {}
    last_index = -1
    position = {key: index for index, key in enumerate(order)}
    for token in parts[1:]:
        key, sep, value = token.partition(":")
        if not sep or not key or not value:
            raise CvssVectorError("malformed metric token")
        if key not in position:
            raise CvssVectorError(f"unknown metric {key[:8]!r}")
        if key in metrics:
            raise CvssVectorError(f"duplicate metric {key}")
        if value not in values[key]:
            raise CvssVectorError(f"invalid value for {key}")
        if ordered and position[key] < last_index:
            raise CvssVectorError(f"metric {key} is out of order")
        last_index = max(last_index, position[key])
        metrics[key] = value
    missing = [key for key in mandatory if key not in metrics]
    if missing:
        raise CvssVectorError(f"missing mandatory metric(s): {', '.join(missing)}")
    return metrics


def format_metrics(
    metrics: Mapping[str, str], *, prefix: str, order: Sequence[str], mandatory: Sequence[str]
) -> str:
    """Return the canonical string: mandatory metrics always, optional ones unless ``X``."""
    tokens = [prefix]
    required = set(mandatory)
    for key in order:
        value = metrics.get(key)
        if value is None or (value == "X" and key not in required):
            continue
        tokens.append(f"{key}:{value}")
    return "/".join(tokens)
