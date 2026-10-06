"""Compatibility classification of JSON Schema changes (E02-24).

Owning epic: E02.

``classify_change(old, new)`` compares two versions of one exported schema and returns a
``CompatReport`` with the level ``none``, ``additive`` or ``breaking`` and the reasons, each
naming a JSON pointer. It applies the rules of ``docs/reference/model-versioning.md`` ("What
the compatibility gate checks") recursively through ``properties``, ``items``, ``prefixItems``,
``$defs`` and ``anyOf``/``oneOf``/``allOf`` branches matched by position.

The comparison is a heuristic. When in doubt it errs towards ``breaking``: a false alarm costs one
version bump and an identity migration, while a miss can corrupt experiment data. Any keyword it
does not understand that changed yields ``breaking`` with the reason
``unrecognised change at <pointer>``.
"""

from dataclasses import dataclass
from typing import Any, Literal

Level = Literal["none", "additive", "breaking"]
_RANK: dict[str, int] = {"none": 0, "additive": 1, "breaking": 2}

# Annotations: a change here does not change which documents are valid.
_ANNOTATIONS = frozenset(
    {"description", "title", "examples", "default", "$comment", "$schema", "$id"}
)
# Lower bounds (raising them is stricter) and upper bounds (lowering them is stricter).
_LOWER_BOUNDS = ("minLength", "minimum", "exclusiveMinimum", "minItems", "minProperties")
_UPPER_BOUNDS = ("maxLength", "maximum", "exclusiveMaximum", "maxItems", "maxProperties")
_BRANCHES = ("anyOf", "oneOf", "allOf")
_HANDLED = frozenset(
    {
        "properties", "required", "type", "enum", "items", "prefixItems", "$defs", "pattern",
        "additionalProperties", "$ref", "const", "format", "uniqueItems",
        *_LOWER_BOUNDS, *_UPPER_BOUNDS, *_BRANCHES,
    }
)  # fmt: skip


@dataclass(frozen=True)
class CompatReport:
    """The compatibility level of a schema change and why."""

    level: Level
    reasons: tuple[str, ...] = ()


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _pointer(base: str, *tokens: str | int) -> str:
    return base + "".join(f"/{_escape(str(token))}" for token in tokens)


class _Comparison:
    def __init__(self, old_root: dict[str, Any], new_root: dict[str, Any]) -> None:
        self.old_root = old_root
        self.new_root = new_root
        self.findings: list[tuple[Level, str]] = []

    def add(self, level: Level, reason: str) -> None:
        self.findings.append((level, reason))

    # entry point --------------------------------------------------------------------------

    def compare(self, old: Any, new: Any, at: str) -> None:
        if old == new:
            return
        if not isinstance(old, dict) or not isinstance(new, dict):
            self.add("breaking", f"unrecognised change at {at or '/'}")
            return
        keys = set(old) | set(new)
        for key in sorted(keys):
            if key in _ANNOTATIONS or key.startswith("x-") or old.get(key) == new.get(key):
                continue
            if key not in _HANDLED:
                self.add("breaking", f"unrecognised change at {_pointer(at, key)}")
        self._properties(old, new, at)
        self._required(old, new, at)
        self._type(old, new, at)
        self._enum(old, new, at)
        self._bounds(old, new, at)
        self._pattern(old, new, at)
        self._simple(old, new, at)
        self._items(old, new, at)
        self._branches(old, new, at)
        self._defs(old, new, at)
        self._ref(old, new, at)

    # keywords -----------------------------------------------------------------------------

    def _properties(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        old_props: dict[str, Any] = old.get("properties", {}) or {}
        new_props: dict[str, Any] = new.get("properties", {}) or {}
        new_required = set(new.get("required", []) or [])
        for name in sorted(set(old_props) - set(new_props)):
            self.add("breaking", f"property removed at {_pointer(at, 'properties', name)}")
        for name in sorted(set(new_props) - set(old_props)):
            where = _pointer(at, "properties", name)
            schema = new_props[name]
            has_default = isinstance(schema, dict) and "default" in schema
            if name in new_required and not has_default:
                self.add("breaking", f"required property added at {where}")
            else:
                self.add("additive", f"property added at {where}")
        for name in sorted(set(old_props) & set(new_props)):
            self.compare(old_props[name], new_props[name], _pointer(at, "properties", name))

    def _required(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        old_props = set((old.get("properties") or {}).keys())
        old_required = set(old.get("required", []) or [])
        new_required = set(new.get("required", []) or [])
        for name in sorted((new_required - old_required) & old_props):
            self.add("breaking", f"property becomes required at {_pointer(at, 'properties', name)}")
        for name in sorted(old_required - new_required):
            self.add("additive", f"property becomes optional at {_pointer(at, 'properties', name)}")

    def _type(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        if old.get("type") == new.get("type"):
            return
        old_types = _as_set(old.get("type"))
        new_types = _as_set(new.get("type"))
        where = _pointer(at, "type")
        if old_types is not None and old_types == new_types:
            return  # "string" and ["string"] allow the same documents
        if "type" not in new:
            self.add("additive", f"type constraint removed at {where}")
        elif old_types is None or new_types is None or not old_types <= new_types:
            self.add("breaking", f"type changed at {where}")
        else:
            self.add("additive", f"type widened at {where}")

    def _enum(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        if old.get("enum") == new.get("enum"):
            return
        where = _pointer(at, "enum")
        if "enum" not in old:
            self.add("breaking", f"enum added at {where}")
            return
        if "enum" not in new:
            self.add("additive", f"enum removed at {where}")
            return
        removed = [value for value in old["enum"] if value not in new["enum"]]
        added = [value for value in new["enum"] if value not in old["enum"]]
        if removed:
            self.add("breaking", f"enum member removed at {where}")
        if added:
            self.add("additive", f"enum member added at {where}")

    def _bounds(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        for key in (*_LOWER_BOUNDS, *_UPPER_BOUNDS):
            before, after = old.get(key), new.get(key)
            if before == after:
                continue
            where = _pointer(at, key)
            lower = key in _LOWER_BOUNDS
            if before is None:
                stricter = True
            elif after is None:
                stricter = False
            elif not isinstance(before, (int, float)) or not isinstance(after, (int, float)):
                self.add("breaking", f"unrecognised change at {where}")
                continue
            else:
                stricter = after > before if lower else after < before
            self.add("breaking" if stricter else "additive",
                     f"bound {'tightened' if stricter else 'loosened'} at {where}")  # fmt: skip

    def _pattern(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        if old.get("pattern") == new.get("pattern"):
            return
        where = _pointer(at, "pattern")
        if "pattern" not in new:
            self.add("additive", f"pattern removed at {where}")
        else:
            self.add("breaking", f"pattern changed at {where}")

    def _simple(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        if old.get("additionalProperties") != new.get("additionalProperties"):
            before = old.get("additionalProperties", True)
            after = new.get("additionalProperties", True)
            where = _pointer(at, "additionalProperties")
            if before is False and after is not False:
                self.add("additive", f"additional properties allowed at {where}")
            elif isinstance(before, dict) and isinstance(after, dict):
                self.compare(before, after, where)
            else:
                self.add("breaking", f"additional properties restricted at {where}")
        for key in ("const", "format"):
            if old.get(key) != new.get(key):
                where = _pointer(at, key)
                level: Level = "additive" if key not in new else "breaking"
                self.add(level, f"{key} changed at {where}")
        if old.get("uniqueItems") != new.get("uniqueItems"):
            stricter = bool(new.get("uniqueItems"))
            self.add("breaking" if stricter else "additive",
                     f"uniqueItems changed at {_pointer(at, 'uniqueItems')}")  # fmt: skip

    def _items(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        if old.get("items") != new.get("items"):
            if "items" in old and "items" in new:
                self.compare(old["items"], new["items"], _pointer(at, "items"))
            elif "items" in new:
                self.add("breaking", f"items constrained at {_pointer(at, 'items')}")
            else:
                self.add("additive", f"items unconstrained at {_pointer(at, 'items')}")
        self._positional(old.get("prefixItems"), new.get("prefixItems"), at, "prefixItems")

    def _branches(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        for key in _BRANCHES:
            self._positional(old.get(key), new.get(key), at, key)

    def _positional(self, old: Any, new: Any, at: str, key: str) -> None:
        if old == new:
            return
        if not isinstance(old, list) or not isinstance(new, list):
            self.add("breaking", f"unrecognised change at {_pointer(at, key)}")
            return
        for index, (before, after) in enumerate(zip(old, new, strict=False)):
            self.compare(before, after, _pointer(at, key, index))
        if len(new) < len(old):
            self.add("breaking", f"member removed from {key} at {_pointer(at, key)}")
        elif len(new) > len(old):
            level: Level = "breaking" if key == "allOf" else "additive"
            self.add(level, f"member added to {key} at {_pointer(at, key)}")

    def _defs(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        old_defs: dict[str, Any] = old.get("$defs", {}) or {}
        new_defs: dict[str, Any] = new.get("$defs", {}) or {}
        removed = set(old_defs) - set(new_defs)
        added = set(new_defs) - set(old_defs)
        for name in sorted(removed):
            renamed = any(_strip(old_defs[name]) == _strip(new_defs[other]) for other in added)
            if not renamed:
                self.add("breaking", f"definition renamed at {_pointer(at, '$defs', name)}")
        for name in sorted(set(old_defs) & set(new_defs)):
            self.compare(old_defs[name], new_defs[name], _pointer(at, "$defs", name))

    def _ref(self, old: dict[str, Any], new: dict[str, Any], at: str) -> None:
        if old.get("$ref") == new.get("$ref"):
            return
        before = _resolve(self.old_root, old.get("$ref"))
        after = _resolve(self.new_root, new.get("$ref"))
        if before is not None and after is not None and _strip(before) == _strip(after):
            return  # a renamed definition with the same structure
        self.add("breaking", f"definition renamed at {_pointer(at, '$ref')}")


def _as_set(value: Any) -> frozenset[str] | None:
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return frozenset(value)
    return None


def _strip(schema: Any) -> Any:
    """``schema`` without annotations, for comparing definitions by structure."""
    if isinstance(schema, dict):
        return {
            key: _strip(value)
            for key, value in schema.items()
            if key not in _ANNOTATIONS and not key.startswith("x-")
        }
    if isinstance(schema, list):
        return [_strip(item) for item in schema]
    return schema


def _resolve(root: dict[str, Any], ref: Any) -> Any:
    if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
        return None
    return (root.get("$defs") or {}).get(ref.removeprefix("#/$defs/"))


def classify_change(old: dict[str, Any], new: dict[str, Any]) -> CompatReport:
    """The compatibility level of changing a schema from ``old`` to ``new``."""
    comparison = _Comparison(old, new)
    comparison.compare(old, new, "")
    if not comparison.findings:
        return CompatReport("none")
    level = max((level for level, _ in comparison.findings), key=_RANK.__getitem__)
    reasons = tuple(dict.fromkeys(reason for _, reason in comparison.findings))
    return CompatReport(level, reasons)
