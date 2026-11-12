"""The C renamer (E09-07).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

One token per name covers functions, structs, unions, enums, typedefs, fields, macros, locals
and parameters. The C library and POSIX surface stays in clear.

**Macro bodies.** The grammar leaves the body of ``#define`` as one ``preproc_arg`` token, so the
identifiers in it are not in the symbol table. Each word of the body that the file renames
elsewhere takes the same token (so ``#define LIMIT MAX_SESSIONS * 2`` stays consistent), a word of
the language or its library stays, and any other word is blanked with ``x`` because it may be a
name the file does not define (a header's). Quoted text is blanked the same way and numbers stay.
"""

import re
from functools import lru_cache

from tree_sitter import Query, QueryCursor

from codekavach.core.models import Language
from codekavach.parsing.loader import load_language
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.specs.c_family import C_BUILTINS, C_KEYWORDS
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.plan import EditReason, RenameEdit
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer, SourceFacts

_MACRO_QUERY = "(preproc_arg) @macro"
_PIECE = re.compile(
    r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|[A-Za-z_]\w*|\s+|.",
    re.DOTALL,
)
_WORD = re.compile(r"[A-Za-z_]\w*")


@lru_cache(maxsize=4)
def _macro_query(language: Language) -> Query:
    return Query(load_language(language), _MACRO_QUERY)


def _blank(text: str) -> str:
    return "".join(ch if ch.isspace() else "x" for ch in text)


def rewrite_macro(
    original: str, tokens: dict[str, str], keep: frozenset[str], start: int
) -> list[RenameEdit]:
    """The edits that rename the words of one macro body and blank what may be a client name."""
    edits: list[RenameEdit] = []
    for match in _PIECE.finditer(original):
        piece = match.group(0)
        if piece[0] in "\"'" and len(piece) >= 2 and piece[-1] == piece[0]:
            new = piece[0] + _blank(piece[1:-1]) + piece[-1]
        elif _WORD.fullmatch(piece):
            if piece in tokens:
                new = tokens[piece]
            elif piece in keep:
                continue
            else:
                new = _blank(piece)
        else:
            continue
        if new != piece:
            offset = start + len(original[: match.start()].encode("utf-8"))
            width = len(piece.encode("utf-8"))
            edits.append(RenameEdit(offset, offset + width, new, EditReason.LITERAL))
    return edits


class CRenamer(BaseRenamer):
    """Renames the internal identifiers of a C file."""

    language = Language.C
    keep: frozenset[str] = frozenset(C_KEYWORDS | C_BUILTINS)

    def facts(self, parsed: ParsedFile) -> SourceFacts:
        """The start offsets of the macro bodies."""
        if parsed.tree is None:
            raise PseudonymError("a file without a syntax tree is not renamed")
        captures = QueryCursor(_macro_query(self.language)).captures(parsed.tree.root_node)
        return SourceFacts(
            macro_starts=frozenset(node.start_byte for node in captures.get("macro", []))
        )

    def literal_edits(
        self, original: str, start: int, end: int, tokens: dict[str, str], facts: SourceFacts
    ) -> list[RenameEdit] | None:
        """A macro body is rewritten word by word; any other string takes the common path."""
        if start not in facts.macro_starts:
            return None
        return rewrite_macro(original, tokens, self.keep, start)
