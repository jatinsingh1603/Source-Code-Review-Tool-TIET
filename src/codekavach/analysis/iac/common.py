"""Shared pieces of the native IaC checks: the issue record and a line-tracking YAML loader."""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Final

import yaml

from codekavach.core.models import Confidence, Severity

MAX_DOCS: Final = 64


@dataclass(frozen=True)
class Issue:
    """One misconfiguration: a rule id, a line, and fixed text. Never quotes a file's values."""

    rule: str
    line: int
    severity: Severity
    cwe: int
    message: str
    confidence: Confidence = Confidence.HIGH
    end_line: int | None = None


class YMap(dict[str, Any]):
    """A mapping that remembers the line of itself and of each key."""

    line: int = 1
    klines: dict[str, int]

    def line_of(self, key: str) -> int:
        """The line of ``key``, or of the mapping when the key is absent."""
        return self.klines.get(key, self.line)


class YSeq(list[Any]):
    """A sequence that remembers the line of itself and of each item."""

    line: int = 1
    ilines: list[int]


def _build(node: yaml.Node, loader: yaml.SafeLoader) -> Any:
    if isinstance(node, yaml.MappingNode):
        mapping = YMap()
        mapping.line = node.start_mark.line + 1
        mapping.klines = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                continue
            key = str(key_node.value)
            mapping[key] = _build(value_node, loader)
            mapping.klines[key] = key_node.start_mark.line + 1
        return mapping
    if isinstance(node, yaml.SequenceNode):
        seq = YSeq()
        seq.line = node.start_mark.line + 1
        seq.ilines = []
        for item in node.value:
            seq.append(_build(item, loader))
            seq.ilines.append(item.start_mark.line + 1)
        return seq
    if isinstance(node, yaml.ScalarNode):
        try:
            return loader.construct_object(node, deep=True)
        except yaml.YAMLError:
            return str(node.value)
    return None


def load_yaml(text: str) -> list[Any]:
    """The documents of ``text`` with line numbers; an empty list when it is not valid YAML."""
    docs: list[Any] = []
    try:
        loader = yaml.SafeLoader(text)
        try:
            while loader.check_node() and len(docs) < MAX_DOCS:
                node = loader.get_node()
                if node is not None:
                    docs.append(_build(node, loader))
        finally:
            loader.dispose()
    except yaml.YAMLError:
        return docs
    return docs


def walk(value: Any) -> Iterator[Any]:
    """Every nested mapping and sequence of ``value``, ``value`` itself first."""
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def truthy(value: Any) -> bool:
    """True for YAML true and the strings a config file uses for it."""
    return value is True or (isinstance(value, str) and value.strip().lower() in {"true", "yes"})


def falsy(value: Any) -> bool:
    """True for YAML false and the strings a config file uses for it."""
    return value is False or (isinstance(value, str) and value.strip().lower() in {"false", "no"})
