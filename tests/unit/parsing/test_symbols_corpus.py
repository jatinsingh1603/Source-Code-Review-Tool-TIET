"""Symbol tables and function ranges over the conformance corpus (E07-03).

The corpus is the one in ``tests/fixtures/parsing/conformance`` (E07-02), extended here with
shadowing and generics fixtures. Three things are asserted for every file: each identifier the
parser reports is attributed exactly once and no identifier is left for the fallback, the
result is identical when the file is parsed again, and the rendered table and function ranges
match a golden file.
"""

from pathlib import Path

import pytest

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.functions import function_ranges
from codekavach.parsing.symbols import build_symbol_table, count_unclassified
from tests.support.conformance import (
    FIXTURES,
    GOLDEN_ROOT,
    fixture_path,
    parse_fixture,
)
from tests.support.golden import assert_matches_golden
from tests.support.symbols import render, render_functions, render_references

IDS = [f"{lang.value}-{n}" for lang, n in FIXTURES]
PARSEABLE = [(lang, name) for lang, name in FIXTURES if "syntax_error" not in name]


def _golden(prefix: str, language: Language, name: str) -> Path:
    return GOLDEN_ROOT / f"{prefix}-{language.value}-{name.replace('.txt', '')}.txt"


@pytest.mark.parametrize(("language", "name"), FIXTURES, ids=IDS)
def test_every_identifier_is_attributed_exactly_once(language: Language, name: str) -> None:
    parsed = parse_fixture(language, fixture_path(language, name))
    table = build_symbol_table(parsed, REGISTRY.get(language))
    expected = [(location, text) for location, text in parsed.identifiers()]
    assert [(s.location, s.name) for s in table.symbols] == expected
    seen = [s.location.region.sort_key() for s in table.symbols]
    assert len(seen) == len(set(seen))


@pytest.mark.parametrize(
    ("language", "name"), PARSEABLE, ids=[f"{lang.value}-{n}" for lang, n in PARSEABLE]
)
def test_the_binder_classifies_every_identifier_of_a_well_formed_file(
    language: Language, name: str
) -> None:
    parsed = parse_fixture(language, fixture_path(language, name))
    assert parsed.error_count == 0
    assert count_unclassified(parsed, REGISTRY.get(language)) == 0


@pytest.mark.parametrize(("language", "name"), FIXTURES, ids=IDS)
def test_symbol_tables_are_identical_across_reparses(language: Language, name: str) -> None:
    spec = REGISTRY.get(language)
    first = build_symbol_table(parse_fixture(language, fixture_path(language, name)), spec)
    second = build_symbol_table(parse_fixture(language, fixture_path(language, name)), spec)
    assert render(first) == render(second)


@pytest.mark.parametrize(("language", "name"), FIXTURES, ids=IDS)
def test_golden_symbol_table(language: Language, name: str) -> None:
    parsed = parse_fixture(language, fixture_path(language, name))
    table = build_symbol_table(parsed, REGISTRY.get(language))
    assert_matches_golden(
        render(table) + render_references(table), _golden("symbols", language, name)
    )


@pytest.mark.parametrize(("language", "name"), FIXTURES, ids=IDS)
def test_golden_function_ranges(language: Language, name: str) -> None:
    parsed = parse_fixture(language, fixture_path(language, name))
    ranges = function_ranges(parsed, REGISTRY.get(language))
    assert_matches_golden(render_functions(ranges), _golden("functions", language, name))


def test_references_are_checked_against_golden_output_for_at_least_ten_cases() -> None:
    bindings = 0
    for language, name in PARSEABLE:
        parsed = parse_fixture(language, fixture_path(language, name))
        table = build_symbol_table(parsed, REGISTRY.get(language))
        bindings += sum(1 for line in render_references(table).splitlines() if "scope=" in line)
    assert bindings >= 10


def test_a_timed_out_or_unsupported_file_is_all_unresolved_not_an_error() -> None:
    parsed = parse("notes.txt", Language.PYTHON, "x = 1\n")
    table = build_symbol_table(parsed, None)
    assert [s.scope_id for s in table.symbols] == [-1]
    assert table.unresolved() == table.symbols
    assert function_ranges(parsed, None) == ()
