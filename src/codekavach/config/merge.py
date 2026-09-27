"""Deep merge of configuration layers (ADR decision D3).

Owning epic: E03.

Rules: tables merge recursively; scalars and arrays replace; arrays of tables replace as a whole;
keys listed in ``union_keys`` (templated dotted keys, ``*`` matching any mapping key) concatenate
base-then-overlay with duplicates removed and first-seen order kept. A table overlaid on a scalar,
or the reverse, simply replaces; validation then rejects the result. A higher layer cannot delete
a key set by a lower layer: there is no deletion syntax.
"""

import copy
from collections.abc import Mapping
from typing import Any


def is_union_key(key: str, union_keys: frozenset[str]) -> bool:
    """True when the concrete dotted ``key`` matches one of the templated ``union_keys``."""
    if key in union_keys:
        return True
    parts = key.split(".")
    for template in union_keys:
        pattern = template.split(".")
        if len(pattern) == len(parts) and all(
            expected in {"*", actual} for expected, actual in zip(pattern, parts, strict=True)
        ):
            return True
    return False


def union_list(base: list[Any], overlay: list[Any]) -> list[Any]:
    """Elements of both lists once each, in first-seen order."""
    result: list[Any] = []
    for item in (*base, *overlay):
        if item not in result:
            result.append(copy.deepcopy(item))
    return result


def deep_merge(
    base: Mapping[str, Any],
    overlay: Mapping[str, Any],
    *,
    union_keys: frozenset[str] = frozenset(),
    prefix: str = "",
) -> dict[str, Any]:
    """Merge ``overlay`` onto ``base`` into a new dictionary; neither argument is mutated."""
    result: dict[str, Any] = {key: copy.deepcopy(value) for key, value in base.items()}
    for key, value in overlay.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        current = result.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            result[key] = deep_merge(current, value, union_keys=union_keys, prefix=path)
        elif (
            isinstance(current, list) and isinstance(value, list) and is_union_key(path, union_keys)
        ):
            result[key] = union_list(current, value)
        else:
            result[key] = copy.deepcopy(value)
    return result
