"""Shared checks for the parsing conformance corpus (E07-02).

Owning epic: not a ``codekavach`` module; a test-only helper, so it carries no "Owning epic"
docstring requirement.
"""

from pathlib import Path

import tree_sitter as ts

from codekavach.core.models import Language
from codekavach.parsing.loader import load_language
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.parser import parse
from codekavach.parsing.positions import LineIndex

# Grammar node types whose occurrences identifiers() must report exactly once each, per
# language: the same vocabulary the issue's technical notes name.
IDENTIFIER_NODE_TYPES: dict[Language, frozenset[str]] = {
    Language.PYTHON: frozenset({"identifier"}),
    Language.JAVASCRIPT: frozenset(
        {
            "identifier",
            "property_identifier",
            "shorthand_property_identifier",
            "shorthand_property_identifier_pattern",
            "private_property_identifier",
            "statement_identifier",
        }
    ),
    Language.TYPESCRIPT: frozenset(
        {
            "identifier",
            "property_identifier",
            "shorthand_property_identifier",
            "shorthand_property_identifier_pattern",
            "private_property_identifier",
            "statement_identifier",
            "type_identifier",
        }
    ),
}


def _every_identifier_typed_node(language: Language, text: str) -> list[tuple[int, int]]:
    tree = ts.Parser(load_language(language)).parse(text.encode("utf-8"))
    wanted = IDENTIFIER_NODE_TYPES[language]
    spans: list[tuple[int, int]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in wanted:
            spans.append((node.start_byte, node.end_byte))
        stack.extend(node.children)
    return spans


def assert_identifiers_exhaustive(language: Language, text: str, parsed: ParsedFile) -> None:
    """Every identifier-typed node in the tree appears in ``identifiers()`` exactly once.

    Compares spans, not just a count: a byte span of every identifier-typed node found by a
    fresh tree walk is converted to the same ``(line, col)`` terms ``identifiers()`` uses (via a
    ``LineIndex`` of the same text, since the two may disagree about a hidden-character
    substitution's exact byte width), and the two sets must be equal.
    """
    line_index = LineIndex.build(text)
    expected = {
        line_index.region(start, end).sort_key()
        for start, end in _every_identifier_typed_node(language, text)
    }
    reported = [location.region.sort_key() for location, _ in parsed.identifiers()]
    assert len(reported) == len(set(reported)), (
        f"identifiers() reported the same span more than once: {reported}"
    )
    missing = expected - set(reported)
    extra = set(reported) - expected
    assert not missing and not extra, f"missing {sorted(missing)}, unexpected {sorted(extra)}"


def assert_strings_and_comments_disjoint(parsed: ParsedFile) -> None:
    """``string_literals()`` and ``comments()`` never share a line/column span."""
    string_spans = {
        (
            span.location.start_line,
            span.location.start_col,
            span.location.end_line,
            span.location.end_col,
        )
        for span in parsed.string_literals()
    }
    comment_spans = {
        (location.start_line, location.start_col, location.end_line, location.end_col)
        for location in parsed.comments()
    }
    overlap = string_spans & comment_spans
    assert not overlap, f"string_literals() and comments() share spans: {overlap}"


def parse_fixture(language: Language, path: Path) -> ParsedFile:
    """Parse one conformance fixture file (read as UTF-8 text).

    ``path.name`` is passed as the repository path, not the absolute filesystem path: ``parse``
    passes it straight to ``Location``, which requires a relative, repository-style path.
    """
    text = path.read_text(encoding="utf-8")
    return parse(path.name, language, text)
