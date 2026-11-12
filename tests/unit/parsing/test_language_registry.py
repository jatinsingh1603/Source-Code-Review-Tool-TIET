"""The parametrised conformance suite over every registered language (E07-05).

One test module iterates the registry, so a language added later is held to the same bar: its
grammar loads, its query files compile, it has a conformance corpus with a syntax-error file, and
the documentation-comment and string forms of the language come out where the issue says.
"""

import pytest

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.loader import GRAMMAR_PINS, grammar_available, grammar_version
from codekavach.parsing.queries.loader import load_query
from tests.support.conformance import FIXTURES, fixture_path, parse_fixture

LANGUAGES = list(REGISTRY.languages())
QUERY_NAMES = ("identifiers", "strings", "comments")


def test_the_registry_holds_the_eleven_shipped_languages() -> None:
    assert set(LANGUAGES) == {
        Language.PYTHON,
        Language.JAVASCRIPT,
        Language.TYPESCRIPT,
        Language.JAVA,
        Language.GO,
        Language.KOTLIN,
        Language.PHP,
        Language.CSHARP,
        Language.RUBY,
        Language.C,
        Language.CPP,
    }


@pytest.mark.parametrize("language", LANGUAGES, ids=lambda lang: lang.value)
def test_every_registered_language_has_an_available_pinned_grammar(language: Language) -> None:
    assert language in GRAMMAR_PINS
    assert grammar_available(language)
    assert grammar_version(language)


@pytest.mark.parametrize("language", LANGUAGES, ids=lambda lang: lang.value)
@pytest.mark.parametrize("name", QUERY_NAMES)
def test_every_query_file_compiles_against_the_pinned_grammar(
    language: Language, name: str
) -> None:
    assert load_query(language, name) is not None


@pytest.mark.parametrize("language", LANGUAGES, ids=lambda lang: lang.value)
def test_every_language_has_a_corpus_with_a_syntax_error_file(language: Language) -> None:
    names = [name for lang, name in FIXTURES if lang is language]
    assert len([n for n in names if "syntax_error" not in n]) >= 2
    assert any("syntax_error" in n for n in names)


@pytest.mark.parametrize("language", [Language.JAVA, Language.GO], ids=lambda lang: lang.value)
def test_the_new_languages_have_at_least_eight_corpus_files_and_a_syntax_error(
    language: Language,
) -> None:
    names = [name for lang, name in FIXTURES if lang is language]
    assert len([n for n in names if "syntax_error" not in n]) >= 8
    assert any("syntax_error" in n for n in names)


@pytest.mark.parametrize(
    ("language", "name"),
    [(lang, n) for lang, n in FIXTURES if "syntax_error" in n],
    ids=lambda value: value if isinstance(value, str) else value.value,
)
def test_a_syntax_error_is_counted_and_the_rest_of_the_file_still_yields_identifiers(
    language: Language, name: str
) -> None:
    parsed = parse_fixture(language, fixture_path(language, name))
    assert parsed.error_count > 0
    texts = [text for _, text in parsed.identifiers()]
    assert texts, "no identifiers survived the syntax error"
    assert "later" in texts or language in (Language.PYTHON, Language.JAVASCRIPT)


# --- documentation comments: in comments(), not in string_literals() -----------------------------


def _doc_comment_cases() -> list[tuple[Language, str, str]]:
    return [
        (Language.JAVA, "case.java", "/** Docs about the thing. */\nclass A {}\n"),
        (Language.GO, "case.go", "package p\n\n// Docs about the thing.\nfunc F() {}\n"),
    ]


@pytest.mark.parametrize(
    ("language", "path", "text"),
    _doc_comment_cases(),
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_a_documentation_comment_is_a_comment_and_not_a_string(
    language: Language, path: str, text: str
) -> None:
    parsed = parse(path, language, text)
    assert len(parsed.comments()) == 1
    assert parsed.string_literals() == ()
    assert [name for _, name in parsed.identifiers()] != []


# --- the language's own string forms ------------------------------------------------------------


def test_a_java_text_block_is_one_string_spanning_its_lines() -> None:
    text = 'class A {\n  String s = """\n    hello\n    world\n    """;\n}\n'
    parsed = parse("A.java", Language.JAVA, text)
    spans = parsed.string_literals()
    assert len(spans) == 1
    assert spans[0].location.end_line > spans[0].location.start_line
    assert "hello" in spans[0].raw_text and "world" in spans[0].raw_text


def test_a_java_character_literal_is_not_a_string_delimiter() -> None:
    text = 'class A { char q = \'"\'; String s = "x"; }\n'
    parsed = parse("A.java", Language.JAVA, text)
    assert [span.raw_text for span in parsed.string_literals()] == ["x"]


def test_a_java_concatenated_query_is_classified_as_sql() -> None:
    text = (
        'class A { String q(String id) { return "SELECT name FROM users WHERE id = \'" + id; } }\n'
    )
    parsed = parse("A.java", Language.JAVA, text)
    assert [span.kind for span in parsed.string_literals()] == ["sql"]


def test_a_go_raw_string_is_one_string_spanning_its_lines() -> None:
    text = "package p\n\nconst raw = `one\ntwo`\n"
    parsed = parse("a.go", Language.GO, text)
    spans = parsed.string_literals()
    assert len(spans) == 1
    assert spans[0].raw_text == "one\ntwo"
    assert spans[0].location.end_line == spans[0].location.start_line + 1


def test_a_go_rune_is_not_a_string() -> None:
    parsed = parse("a.go", Language.GO, "package p\n\nvar r = 'q'\nvar s = \"x\"\n")
    assert [span.raw_text for span in parsed.string_literals()] == ["x"]


def test_a_go_interpreted_string_with_a_backquote_inside_stays_whole() -> None:
    parsed = parse("a.go", Language.GO, 'package p\n\nvar s = "a`b"\n')
    assert [span.raw_text for span in parsed.string_literals()] == ["a`b"]


def test_a_go_url_and_path_are_classified() -> None:
    text = 'package p\n\nvar u = "https://example.invalid/x"\nvar p = "/etc/passwd"\n'
    parsed = parse("a.go", Language.GO, text)
    assert [span.kind for span in parsed.string_literals()] == ["url", "path"]
