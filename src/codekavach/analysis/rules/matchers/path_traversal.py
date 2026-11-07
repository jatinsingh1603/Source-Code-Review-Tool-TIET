"""Path traversal (CWE-22): a file path that comes from the caller reaches a file operation.

Owning epic: E13. MVP; extended by E16.

Sinks: ``open``, ``send_file`` and the ``os`` and ``shutil`` file operations in Python; the ``fs``
file functions, ``sendFile`` and ``download`` in JavaScript. The matcher fires when the path
argument uses a parameter of the enclosing function, ``request`` data or a local taken from them.
The safe form is a containment check in the same function: ``startswith``, ``is_relative_to``,
``commonpath``, ``secure_filename``, ``basename``, or an Express ``root`` option.
"""

from collections.abc import Iterator
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.engine import FileContext, Hit, NodeMatcher, Rule
from codekavach.analysis.rules.syntax import (
    CALL_TYPES,
    call_arguments,
    callee_name,
    enclosing_function,
    identifiers_in,
    is_request_derived,
    last_segment,
)
from codekavach.core.models import Severity

RULE: Final = Rule(
    slug="path-traversal",
    cwe=22,
    severity=Severity.HIGH,
    message="A file operation uses a path that comes from the caller without a containment check.",
)
PYTHON_SINKS: Final = frozenset(
    {"open", "io.open", "send_file", "send_from_directory", "fileresponse", "os.remove",
     "os.unlink", "os.rename", "os.listdir", "os.makedirs", "shutil.copy", "shutil.copyfile",
     "shutil.move", "shutil.rmtree"}
)  # fmt: skip
JAVASCRIPT_SINKS: Final = frozenset(
    {"readfile", "readfilesync", "createreadstream", "writefile", "writefilesync",
     "createwritestream", "appendfile", "appendfilesync", "unlink", "unlinksync", "readdir",
     "readdirsync", "rm", "rmsync", "sendfile", "download", "open", "opensync"}
)  # fmt: skip
SAFE_MARKERS: Final = frozenset(
    {"secure_filename", "basename", "startswith", "is_relative_to", "relative_to", "commonpath"}
)


def _is_sink(name: str, is_python: bool) -> bool:
    if is_python:
        return name.lower() in PYTHON_SINKS
    return last_segment(name).lower() in JAVASCRIPT_SINKS and ("." in name or name == "open")


class PathTraversalMatcher(NodeMatcher):
    """Finds file operations on caller-controlled paths."""

    node_types: ClassVar[frozenset[str]] = CALL_TYPES

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for a file operation on an unchecked caller-controlled path."""
        name = callee_name(node)
        if name is None or not _is_sink(name, node.type == "call"):
            return
        arguments, keywords = call_arguments(node)
        if not arguments or "root" in keywords:
            return
        function = enclosing_function(node)
        if not is_request_derived(arguments[0], function, ctx.root):
            return
        scope = function if function is not None else ctx.root
        if any(word.lower() in SAFE_MARKERS for word in identifiers_in(scope)):
            return
        yield Hit(RULE, node)
