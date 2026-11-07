"""The Python renamer (E09-04).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

Python needs no node-by-node rules for names: one token per name makes a definition, a use, a
keyword argument, a decorator, a ``global`` or ``nonlocal`` name, an ``except ... as`` target, a
``with ... as`` target, a comprehension variable, a walrus target and a ``del`` operand agree.
Keyword arguments follow the parameter they bind (``BaseRenamer`` keeps a keyword in clear when the
parameter is). What this module adds is the two places where a string names a binding:

* an entry of ``__all__``;
* a string annotation (``x: "Account"``).

An f-string needs no rule either: its literal segments are separate spans for the literal shaper,
its interpolations are ordinary code, and the format specifier and conversion are not spans, so
they stay as written. The self-documenting ``{total=}`` echoes the token because ``total`` is
renamed.
"""

from typing import Final

from tree_sitter import Node

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer

_MAX_DEPTH: Final = 8
_SEQUENCES: Final = frozenset({"list", "tuple", "set"})


class PythonRenamer(BaseRenamer):
    """Renames the internal identifiers of a Python file."""

    language = Language.PYTHON

    def is_name_string(self, node: Node | None) -> bool:
        """True for an entry of ``__all__`` or a string annotation."""
        current = node
        for _ in range(_MAX_DEPTH):
            if current is None:
                return False
            if current.type == "type":
                return True
            if current.type in _SEQUENCES:
                parent = current.parent
                if parent is not None and parent.type in {"assignment", "augmented_assignment"}:
                    left = parent.child_by_field_name("left")
                    return left is not None and (left.text or b"") == b"__all__"
                return False
            current = current.parent
        return False
