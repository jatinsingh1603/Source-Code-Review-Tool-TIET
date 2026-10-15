"""The parsing conformance corpus: exhaustiveness, disjointness and golden output (E07-02).

A smaller, representative corpus than the issue's full feature list (nested functions, classes,
decorators, comprehensions, async, f-strings/template literals, destructuring, a syntax error,
and TypeScript generics/interfaces are covered; JSX and the remaining per-language exotica are
not): the ``Language`` enum (E02-04) has no TSX/JSX member, so there is nothing to register a
grammar or a spec under, and the two property tests below are the corpus's real value, not the
file count.
"""

from pathlib import Path

import pytest

from codekavach.core.models import Language
from codekavach.parsing.models import ParsedFile
from tests.support.conformance import (
    assert_identifiers_exhaustive,
    assert_strings_and_comments_disjoint,
    parse_fixture,
)
from tests.support.golden import assert_matches_golden

CORPUS_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "parsing" / "conformance"
GOLDEN_ROOT = CORPUS_ROOT / "golden"

FIXTURES: list[tuple[Language, str]] = [
    (Language.PYTHON, "basics.py.txt"),
    (Language.PYTHON, "control_flow.py.txt"),
    (Language.PYTHON, "strings.py.txt"),
    (Language.PYTHON, "syntax_error.py.txt"),
    (Language.JAVASCRIPT, "basics.js.txt"),
    (Language.JAVASCRIPT, "modules.js.txt"),
    (Language.JAVASCRIPT, "syntax_error.js.txt"),
    (Language.TYPESCRIPT, "basics.ts.txt"),
]


def _fixture_path(language: Language, name: str) -> Path:
    return CORPUS_ROOT / language.value / name


@pytest.mark.parametrize(
    ("language", "name"), FIXTURES, ids=[f"{lang.value}-{n}" for lang, n in FIXTURES]
)
def test_identifiers_are_exhaustive(language: Language, name: str) -> None:
    path = _fixture_path(language, name)
    text = path.read_text(encoding="utf-8")
    parsed = parse_fixture(language, path)
    assert_identifiers_exhaustive(language, text, parsed)


@pytest.mark.parametrize(
    ("language", "name"), FIXTURES, ids=[f"{lang.value}-{n}" for lang, n in FIXTURES]
)
def test_strings_and_comments_never_overlap(language: Language, name: str) -> None:
    parsed = parse_fixture(language, _fixture_path(language, name))
    assert_strings_and_comments_disjoint(parsed)


def _rendered(parsed: ParsedFile) -> str:
    lines: list[str] = ["identifiers:"]
    lines.extend(f"  {location.display()} {text!r}" for location, text in parsed.identifiers())
    lines.append("strings:")
    lines.extend(
        f"  {span.location.display()} {span.kind} {span.raw_text!r}"
        for span in parsed.string_literals()
    )
    lines.append("comments:")
    lines.extend(f"  {location.display()}" for location in parsed.comments())
    lines.append(f"error_count: {parsed.error_count}")
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    ("language", "name"), FIXTURES, ids=[f"{lang.value}-{n}" for lang, n in FIXTURES]
)
def test_golden_output(language: Language, name: str) -> None:
    parsed = parse_fixture(language, _fixture_path(language, name))
    golden = GOLDEN_ROOT / f"{language.value}-{name.replace('.txt', '')}.txt"
    assert_matches_golden(_rendered(parsed), golden)


def test_a_syntax_error_still_yields_identifiers_for_the_parseable_region() -> None:
    path = _fixture_path(Language.PYTHON, "syntax_error.py.txt")
    parsed = parse_fixture(Language.PYTHON, path)
    assert parsed.error_count > 0
    names = [text for _, text in parsed.identifiers()]
    assert "still_parseable" in names
    assert "x" in names


def test_a_js_syntax_error_still_yields_identifiers_for_the_parseable_region() -> None:
    path = _fixture_path(Language.JAVASCRIPT, "syntax_error.js.txt")
    parsed = parse_fixture(Language.JAVASCRIPT, path)
    assert parsed.error_count > 0
    names = [text for _, text in parsed.identifiers()]
    assert "stillParseable" in names


@pytest.mark.parametrize(
    ("language", "name"), FIXTURES, ids=[f"{lang.value}-{n}" for lang, n in FIXTURES]
)
def test_extraction_is_invariant_under_reparsing(language: Language, name: str) -> None:
    """Parsing the same text twice gives byte-for-byte identical identifiers/strings/comments."""
    path = _fixture_path(language, name)
    first = parse_fixture(language, path)
    second = parse_fixture(language, path)
    assert first.identifiers() == second.identifiers()
    assert first.string_literals() == second.string_literals()
    assert first.comments() == second.comments()
    assert first.error_count == second.error_count
