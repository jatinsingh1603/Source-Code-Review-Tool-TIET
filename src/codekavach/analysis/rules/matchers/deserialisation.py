"""Insecure deserialisation (CWE-502): untrusted data is turned back into objects.

Owning epic: E13. MVP; extended by E16.

Sinks: ``pickle``, ``cPickle``, ``marshal``, ``dill`` and ``shelve`` loaders, ``jsonpickle.decode``
and ``yaml.load`` without a safe loader in Python; ``unserialize`` of ``node-serialize`` in
JavaScript. A literal argument never fires. The safe forms are ``json.loads`` and
``yaml.safe_load`` (or ``yaml.load`` with ``SafeLoader``), which are simply not on the sink list.
"""

from collections.abc import Iterator
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.engine import FileContext, Hit, NodeMatcher, Rule
from codekavach.analysis.rules.syntax import (
    CALL_TYPES,
    call_arguments,
    callee_name,
    is_literal,
    last_segment,
    text_of,
)
from codekavach.core.models import Severity

RULE: Final = Rule(
    slug="insecure-deserialisation",
    cwe=502,
    severity=Severity.HIGH,
    message="Data is deserialised with a loader that can construct arbitrary objects.",
)
PYTHON_SINKS: Final = frozenset(
    {"pickle.load", "pickle.loads", "pickle.unpickler", "cpickle.load", "cpickle.loads",
     "marshal.load", "marshal.loads", "dill.load", "dill.loads", "shelve.open",
     "jsonpickle.decode", "jsonpickle.loads", "yaml.unsafe_load", "yaml.full_load"}
)  # fmt: skip
JAVASCRIPT_SINKS: Final = frozenset({"unserialize", "serialize.unserialize", "funserialize"})
SAFE_YAML_LOADERS: Final = ("SafeLoader", "CSafeLoader", "BaseLoader")


def _unsafe_yaml_load(node: Node) -> bool:
    arguments, keywords = call_arguments(node)
    loader = keywords.get("Loader") or (arguments[1] if len(arguments) > 1 else None)
    return loader is None or not text_of(loader).endswith(SAFE_YAML_LOADERS)


class DeserialisationMatcher(NodeMatcher):
    """Finds calls that rebuild objects from data the program does not control."""

    node_types: ClassVar[frozenset[str]] = CALL_TYPES

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for an unsafe loader applied to a non-literal argument."""
        name = (callee_name(node) or "").lower()
        if node.type == "call":
            unsafe = name in PYTHON_SINKS or (name == "yaml.load" and _unsafe_yaml_load(node))
        else:
            unsafe = name in JAVASCRIPT_SINKS or last_segment(name) == "unserialize"
        if not unsafe:
            return
        arguments, _ = call_arguments(node)
        if arguments and not is_literal(arguments[0]):
            yield Hit(RULE, node)
