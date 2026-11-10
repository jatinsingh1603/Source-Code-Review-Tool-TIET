"""Performance budget: the whole parsing conformance corpus, every language (E07-05).

Parsing, building the symbol table and finding the function ranges of every fixture of every
registered language is the work the parametrised conformance suite repeats several times over, so
a slowdown in any language shows up here first. The budget is an absolute ceiling over the whole
corpus, scaled by the performance factor.
"""

import pytest

from codekavach.parsing import REGISTRY
from codekavach.parsing.functions import function_ranges
from codekavach.parsing.symbols import build_symbol_table
from tests.support.conformance import FIXTURES, fixture_path, parse_fixture
from tests.support.perf import assert_within_budget, measure

CORPUS_BUDGET_SECONDS = 1.0


def _run_corpus() -> int:
    identifiers = 0
    for language, name in FIXTURES:
        parsed = parse_fixture(language, fixture_path(language, name))
        spec = REGISTRY.get(language)
        identifiers += len(build_symbol_table(parsed, spec).symbols)
        function_ranges(parsed, spec)
    return identifiers


@pytest.mark.perf
def test_the_whole_conformance_corpus_stays_within_budget() -> None:
    assert _run_corpus() > 0  # warm: loads every grammar and query once
    seconds = measure(_run_corpus, repeat=3)
    assert_within_budget(seconds, CORPUS_BUDGET_SECONDS, label="conformance corpus")
