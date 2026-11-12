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

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "parsing" / "conformance"
GOLDEN_ROOT = CORPUS_ROOT / "golden"

# Every conformance fixture: the single list the identifier, symbol-table and function-range
# tests all iterate, so a new fixture is covered by all of them at once.
FIXTURES: list[tuple[Language, str]] = [
    (Language.PYTHON, "basics.py.txt"),
    (Language.PYTHON, "control_flow.py.txt"),
    (Language.PYTHON, "strings.py.txt"),
    (Language.PYTHON, "shadowing.py.txt"),
    (Language.PYTHON, "syntax_error.py.txt"),
    (Language.JAVASCRIPT, "basics.js.txt"),
    (Language.JAVASCRIPT, "modules.js.txt"),
    (Language.JAVASCRIPT, "shadowing.js.txt"),
    (Language.JAVASCRIPT, "syntax_error.js.txt"),
    (Language.TYPESCRIPT, "basics.ts.txt"),
    (Language.TYPESCRIPT, "generics.ts.txt"),
    (Language.TYPESCRIPT, "syntax_error.ts.txt"),
    (Language.JAVA, "basics.java.txt"),
    (Language.JAVA, "classes.java.txt"),
    (Language.JAVA, "scoping.java.txt"),
    (Language.JAVA, "lambdas.java.txt"),
    (Language.JAVA, "patterns.java.txt"),
    (Language.JAVA, "annotations.java.txt"),
    (Language.JAVA, "initialisers.java.txt"),
    (Language.JAVA, "strings.java.txt"),
    (Language.JAVA, "generics.java.txt"),
    (Language.JAVA, "syntax_error.java.txt"),
    (Language.GO, "basics.go.txt"),
    (Language.GO, "scoping.go.txt"),
    (Language.GO, "methods.go.txt"),
    (Language.GO, "types.go.txt"),
    (Language.GO, "closures.go.txt"),
    (Language.GO, "control.go.txt"),
    (Language.GO, "strings.go.txt"),
    (Language.GO, "imports.go.txt"),
    (Language.GO, "consts.go.txt"),
    (Language.GO, "syntax_error.go.txt"),
    (Language.KOTLIN, "basics.kt.txt"),
    (Language.KOTLIN, "scoping.kt.txt"),
    (Language.KOTLIN, "syntax_error.kt.txt"),
    (Language.PHP, "basics.php.txt"),
    (Language.PHP, "scoping.php.txt"),
    (Language.PHP, "syntax_error.php.txt"),
    (Language.CSHARP, "basics.cs.txt"),
    (Language.CSHARP, "scoping.cs.txt"),
    (Language.CSHARP, "syntax_error.cs.txt"),
    (Language.RUBY, "basics.rb.txt"),
    (Language.RUBY, "scoping.rb.txt"),
    (Language.RUBY, "syntax_error.rb.txt"),
    (Language.C, "basics.c.txt"),
    (Language.C, "scoping.c.txt"),
    (Language.C, "syntax_error.c.txt"),
    (Language.CPP, "basics.cpp.txt"),
    (Language.CPP, "scoping.cpp.txt"),
    (Language.CPP, "syntax_error.cpp.txt"),
]


def fixture_path(language: Language, name: str) -> Path:
    """The path of one conformance fixture."""
    return CORPUS_ROOT / language.value / name


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
    Language.JAVA: frozenset({"identifier", "type_identifier"}),
    Language.KOTLIN: frozenset({"simple_identifier", "type_identifier", "interpolated_identifier"}),
    Language.PHP: frozenset({"name"}),
    Language.CSHARP: frozenset({"identifier", "implicit_parameter"}),
    Language.RUBY: frozenset(
        {
            "identifier",
            "constant",
            "instance_variable",
            "class_variable",
            "global_variable",
            "simple_symbol",
            "hash_key_symbol",
        }
    ),
    Language.C: frozenset(
        {"identifier", "type_identifier", "field_identifier", "statement_identifier"}
    ),
    Language.CPP: frozenset(
        {
            "identifier",
            "type_identifier",
            "field_identifier",
            "statement_identifier",
            "namespace_identifier",
        }
    ),
    Language.GO: frozenset(
        {"identifier", "type_identifier", "field_identifier", "package_identifier", "label_name"}
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
