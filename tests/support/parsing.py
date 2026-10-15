"""Shared test helpers for ``codekavach.parsing`` (E07-01)."""

from codekavach.core.models import Language
from codekavach.parsing.spec import NodeKind, NodeKindMap


def reference_position(text: str, byte_offset: int) -> tuple[int, int]:
    """A direct-decode reference implementation of ``LineIndex.position``.

    Counts ``\\n`` bytes before ``byte_offset`` for the line, then decodes the bytes since the
    last one with ``errors="ignore"`` for the column: a byte offset that lands strictly inside a
    multi-byte character drops that character's incomplete tail, which is exactly
    ``LineIndex``'s own documented rule (the column before a character that is not yet complete).
    """
    data = text.encode("utf-8")
    offset = min(max(byte_offset, 0), len(data))
    prefix = data[:offset]
    line = prefix.count(b"\n")
    last_newline = prefix.rfind(b"\n")
    line_prefix = prefix[last_newline + 1 :]
    column = len(line_prefix.decode("utf-8", errors="ignore")) + 1
    return line + 1, column


class TrivialSpec:
    """A minimal, real ``LanguageSpec`` used only in tests (E07-01's own trivial example).

    Maps Python's actual ``identifier``, ``string``/``string_content`` and ``comment`` node
    types, so ``parse()``'s generic extraction walk has something real to exercise without any
    other issue's per-language knowledge.
    """

    language = Language.PYTHON
    grammar_version = "test-fixture"
    keywords: frozenset[str] = frozenset()
    builtins: frozenset[str] = frozenset()

    def node_kinds(self) -> NodeKindMap:
        return {
            NodeKind.IDENTIFIER: frozenset({"identifier"}),
            NodeKind.STRING: frozenset({"string"}),
            NodeKind.COMMENT: frozenset({"comment"}),
        }

    def enclosing_symbol(self, node: object, source: str) -> str | None:
        return None
