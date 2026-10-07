"""Where each effective setting came from.

Owning epic: E03.

Every leaf key of the validated settings has an ``Origin``: the highest layer whose data contains
the key or a parent value of it, the file or source that layer came from, and the line of the key
when the layer has text. Keys set by no layer come from the built-in defaults. A table written
with nothing in it (the starter file has a ``[logging]`` header with every key commented out) sets
no key, so it is not a parent value: the merge adds nothing from it either. For union-merged
keys, ``contributors`` lists every layer that added elements, in order, with ``"<layer>:file"``
for elements read from a file such as ``privacy.domain_terms_file``.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from codekavach.config.introspect import flatten_leaves
from codekavach.config.merge import is_union_key
from codekavach.config.toml_source import locate_key

LayerName = Literal["default", "user", "project", "profile", "env", "cli", "org-policy"]


@dataclass(frozen=True, slots=True)
class Origin:
    """The source of one effective setting."""

    layer: LayerName
    source: str | None = None
    line: int | None = None
    contributors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Layer:
    """One configuration source, in precedence order."""

    name: LayerName
    source: str
    data: Mapping[str, Any]
    text: str | None = None
    sha256: str | None = None
    key_sources: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    # Keys extended from a file (``privacy.domain_terms_file``), mapped to whether the layer also
    # set them inline; the file shows up as the contributor ``"<layer>:file"``.
    expanded: Mapping[str, bool] = field(default_factory=lambda: MappingProxyType({}))


def _prefixes(key: str) -> list[str]:
    parts = key.split(".")
    return [".".join(parts[:length]) for length in range(len(parts), 0, -1)]


def _layer_key(flat: Mapping[str, Any], key: str) -> str | None:
    """The key or nearest parent of ``key`` that the layer sets, if any.

    An empty table above ``key`` sets nothing below it. An empty table that is ``key`` itself is
    a written value: ``[llm.providers]`` for a map-valued setting.
    """
    for candidate in _prefixes(key):
        if candidate in flat and (candidate == key or not _is_empty_table(flat[candidate])):
            return candidate
    return None


def _is_empty_table(value: Any) -> bool:
    return isinstance(value, Mapping) and not value


def origin_in(layer: Layer, key: str, matched: str | None = None) -> Origin:
    """The origin of ``key`` within ``layer``."""
    matched = matched or key
    source = layer.key_sources.get(matched, layer.key_sources.get(key, layer.source))
    line = locate_key(layer.text, key) if layer.text is not None else None
    return Origin(layer=layer.name, source=source, line=line)


def _contributors(layer: Layer, key: str) -> tuple[str, ...]:
    if key not in layer.expanded:
        return (layer.name,)
    inline = (layer.name,) if layer.expanded[key] else ()
    return (*inline, f"{layer.name}:file")


def compute_origins(
    layers: Sequence[Layer],
    final: Mapping[str, Any],
    *,
    union_keys: frozenset[str] = frozenset(),
    defaults: Mapping[str, Any] | None = None,
) -> dict[str, Origin]:
    """An origin for every leaf key of ``final`` (the dumped, validated settings)."""
    flats = [flatten_leaves(layer.data) for layer in layers]
    default_flat = flatten_leaves(defaults) if defaults is not None else {}
    origins: dict[str, Origin] = {}
    for key in flatten_leaves(final):
        origin = Origin(layer="default")
        for layer, flat in zip(reversed(layers), reversed(flats), strict=True):
            matched = _layer_key(flat, key)
            if matched is not None:
                origin = origin_in(layer, key, matched)
                break
        if is_union_key(key, union_keys):
            contributors = tuple(
                name
                for layer, flat in zip(layers, flats, strict=True)
                if flat.get(key)
                for name in _contributors(layer, key)
            )
            if default_flat.get(key):
                contributors = ("default", *contributors)
            origin = Origin(origin.layer, origin.source, origin.line, contributors)
        origins[key] = origin
    return origins
