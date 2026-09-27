"""Introspection of the settings model tree: dotted keys, fields and markers.

Owning epic: E03.

Pure helpers over model classes, never over settings values. Keys come in two forms:

- templated, as yielded by ``iter_fields``: ``*`` stands for any key of a mapping whose values are
  models (``llm.providers.*.base_url``) and ``[]`` for any index of a list of models
  (``privacy.paths[].level``);
- concrete, as written by users and produced by ``loc_to_key``: ``llm.providers.lab.base_url``,
  ``privacy.paths[2].level``.

Markers come from ``json_schema_extra`` (``x-ck-sensitive``, ``x-ck-volatile``,
``x-ck-merge = "union"``, ``x-ck-restricted``) and are inherited: a marker on a field applies to
every key below it, so ``FieldRef.markers`` holds the field's own markers and its ancestors'.

Limitation: a mapping key in a concrete dotted key is taken literally up to the next dot, so
mapping keys cannot contain dots or brackets. Provider and engine ids are defined so that they
cannot. A free-form dictionary field (``options``) is a leaf; one further segment names one of
its entries (``llm.providers.lab.options.seed``) and resolves to that dictionary's field.
"""

import re
import types
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from inspect import isclass
from typing import Annotated, Any, Union, get_args, get_origin

from pydantic import BaseModel
from pydantic.fields import FieldInfo

Marker = str
MARKERS: frozenset[Marker] = frozenset({"sensitive", "volatile", "union", "restricted"})
ANY_KEY = "*"
ANY_INDEX = "[]"

Token = str | int
_SEGMENT = re.compile(r"^([A-Za-z0-9_-]*|\*)((?:\[\d*\])*)$")
_INDEX = re.compile(r"\[(\d*)\]")
_MAPPINGS = (dict, Mapping)
_SEQUENCES = (list, tuple, Sequence)


@dataclass(frozen=True, slots=True)
class FieldRef:
    """One key of the settings tree."""

    key: str
    annotation: Any
    field: FieldInfo
    markers: frozenset[Marker]
    is_mapping_entry: bool


@dataclass(frozen=True, slots=True)
class _Node:
    ref: FieldRef
    tokens: tuple[Token, ...]  # "*" and "[]" are wildcards
    is_leaf: bool
    is_free_mapping: bool


def _strip(annotation: Any) -> Any:
    while get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]
    return annotation


def _members(annotation: Any) -> list[Any]:
    annotation = _strip(annotation)
    if get_origin(annotation) in (Union, types.UnionType):
        return [_strip(arg) for arg in get_args(annotation) if arg is not type(None)]
    return [annotation]


def _is_model(annotation: Any) -> bool:
    return (
        isclass(annotation) and get_origin(annotation) is None and issubclass(annotation, BaseModel)
    )


def _model_of(annotation: Any) -> type[BaseModel] | None:
    models = [member for member in _members(annotation) if _is_model(member)]
    return models[0] if len(models) == 1 else None


def _container(annotation: Any) -> tuple[str, type[BaseModel]] | None:
    """``("*", Model)`` for a mapping of models, ``("[]", Model)`` for a list of models."""
    for member in _members(annotation):
        origin, args = get_origin(member), get_args(member)
        if origin in _MAPPINGS and len(args) == 2 and (model := _model_of(args[1])):
            return ANY_KEY, model
        if origin in _SEQUENCES and args and (model := _model_of(args[0])):
            return ANY_INDEX, model
    return None


def _is_free_mapping(annotation: Any) -> bool:
    return any(get_origin(member) in _MAPPINGS for member in _members(annotation))


def markers_of(field: FieldInfo) -> frozenset[Marker]:
    """The markers set directly on ``field``."""
    extra = field.json_schema_extra
    if not isinstance(extra, dict):
        return frozenset()
    found = set()
    if extra.get("x-ck-sensitive") is True:
        found.add("sensitive")
    if extra.get("x-ck-volatile") is True:
        found.add("volatile")
    if extra.get("x-ck-merge") == "union":
        found.add("union")
    if extra.get("x-ck-restricted") is True:
        found.add("restricted")
    return frozenset(found)


def _render(tokens: Sequence[Token]) -> str:
    text = ""
    for token in tokens:
        if isinstance(token, int):
            text += f"[{token}]"
        elif token == ANY_INDEX:
            text += ANY_INDEX
        else:
            text += f".{token}" if text else token
    return text


def _walk(
    model: type[BaseModel],
    prefix: tuple[Token, ...],
    inherited: frozenset[Marker],
    through_mapping: bool,
    stack: tuple[type[BaseModel], ...],
) -> Iterator[_Node]:
    for name, field in model.model_fields.items():
        tokens = (*prefix, name)
        markers = inherited | markers_of(field)
        annotation = field.annotation
        child = _model_of(annotation)
        container = None if child else _container(annotation)
        target = child or (container[1] if container else None)
        is_leaf = target is None or target in stack
        free = is_leaf and _is_free_mapping(annotation)
        ref = FieldRef(_render(tokens), annotation, field, markers, through_mapping)
        yield _Node(ref, tokens, is_leaf, free)
        if is_leaf:
            continue
        if child is not None:
            yield from _walk(child, tokens, markers, through_mapping, (*stack, child))
        elif container is not None:
            wildcard, item = container
            yield from _walk(
                item,
                (*tokens, wildcard),
                markers,
                through_mapping or wildcard == ANY_KEY,
                (*stack, item),
            )


@cache
def _nodes(model: type[BaseModel]) -> tuple[_Node, ...]:
    return tuple(_walk(model, (), frozenset(), False, (model,)))


def iter_fields(model: type[BaseModel], *, prefix: str = "") -> Iterator[FieldRef]:
    """Leaf keys of ``model`` depth-first in declaration order, templated, under ``prefix``."""
    for node in _nodes(model):
        if not node.is_leaf:
            continue
        if not prefix:
            yield node.ref
            continue
        key = (
            f"{prefix}{node.ref.key}"
            if node.ref.key.startswith("[")
            else (f"{prefix}.{node.ref.key}")
        )
        yield FieldRef(
            key,
            node.ref.annotation,
            node.ref.field,
            node.ref.markers,
            node.ref.is_mapping_entry,
        )


def _parse(key: str, *, wildcards: bool = False) -> tuple[Token, ...] | None:
    """Tokens of a dotted key, or ``None`` when malformed; ``*`` and ``[]`` need ``wildcards``."""
    if not key:
        return None
    tokens: list[Token] = []
    for position, segment in enumerate(key.split(".")):
        match = _SEGMENT.match(segment)
        if match is None:
            return None
        name, indices = match.groups()
        if not name and (position > 0 or not indices):
            return None
        if name == ANY_KEY and not wildcards:
            return None
        if name:
            tokens.append(name)
        for index in _INDEX.findall(indices):
            if not index and not wildcards:
                return None
            tokens.append(int(index) if index else ANY_INDEX)
    return tuple(tokens)


def _matches(template: tuple[Token, ...], tokens: tuple[Token, ...]) -> bool:
    if len(template) != len(tokens):
        return False
    for expected, actual in zip(template, tokens, strict=True):
        if expected == actual:
            continue
        if expected == ANY_INDEX:
            if not isinstance(actual, int):
                return False
        elif expected == ANY_KEY:
            if not isinstance(actual, str):
                return False
        elif expected != actual:
            return False
    return True


def resolve_field(model: type[BaseModel], key: str) -> FieldRef | None:
    """The field a concrete (or templated) key names, or ``None``; never raises."""
    tokens = _parse(key, wildcards=True)
    if tokens is None:
        return None
    for node in _nodes(model):
        if _matches(node.tokens, tokens):
            return node.ref
        if (
            node.is_free_mapping
            and len(tokens) == len(node.tokens) + 1
            and isinstance(tokens[-1], str)
            and _matches(node.tokens, tokens[:-1])
        ):
            args = [get_args(m) for m in _members(node.ref.annotation) if get_args(m)]
            value = args[0][1] if args and len(args[0]) == 2 else Any
            return FieldRef(
                f"{node.ref.key}.{ANY_KEY}", value, node.ref.field, node.ref.markers, True
            )
    return None


def keys_with_marker(model: type[BaseModel], marker: Marker) -> frozenset[str]:
    """Templated leaf keys carrying ``marker``, directly or through an ancestor."""
    return frozenset(ref.key for ref in iter_fields(model) if marker in ref.markers)


def has_marker(model: type[BaseModel], key: str, marker: Marker) -> bool:
    """True when the field ``key`` names, or any ancestor of it, carries ``marker``."""
    ref = resolve_field(model, key)
    return ref is not None and marker in ref.markers


def loc_to_key(loc: tuple[str | int, ...]) -> str:
    """``("privacy", "paths", 2, "level")`` gives ``privacy.paths[2].level``."""
    return _render([item if isinstance(item, int) else str(item) for item in loc])


def key_to_path(key: str) -> tuple[str | int, ...]:
    """The inverse of ``loc_to_key``.

    Raises:
        ValueError: ``key`` is not a well-formed dotted key.
    """
    tokens = _parse(key)
    if tokens is None:
        raise ValueError("malformed dotted key")
    return tokens


def flatten_leaves(data: Mapping[str, Any], *, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dictionaries to dotted keys; lists, ``None`` and ``{}`` are leaves."""
    flat: dict[str, Any] = {}
    for name, value in data.items():
        key = f"{prefix}.{name}" if prefix else str(name)
        if isinstance(value, Mapping) and value:
            flat.update(flatten_leaves(value, prefix=key))
        else:
            flat[key] = value
    return flat
