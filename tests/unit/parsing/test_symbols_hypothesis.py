"""Symbol-table properties over generated programs (E07-03).

Hypothesis does not generate arbitrary Python or JavaScript here; it varies a pool of small, valid
statements (the same approach as ``test_extraction_hypothesis.py``) and, for the reference-count
property, a name and a number of uses, so every program is valid by construction.
"""

from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY
from codekavach.parsing.symbols import build_symbol_table, count_unclassified
from tests.support.parsing_generators import javascript_program, python_program
from tests.support.symbols import render, table_of

NAMES = st.from_regex(r"v_[a-z]{1,8}", fullmatch=True)
USES = st.integers(min_value=0, max_value=8)


def _assert_total_and_deterministic(language: Language, text: str) -> None:
    parsed, table = table_of(language, text)
    assert [(s.location, s.name) for s in table.symbols] == list(parsed.identifiers())
    assert count_unclassified(parsed, REGISTRY.get(language)) == 0
    again = build_symbol_table(parsed, REGISTRY.get(language))
    assert render(again) == render(table)
    reparsed, other = table_of(language, text)
    assert reparsed.identifiers() == parsed.identifiers()
    assert render(other) == render(table)


@given(st.permutations(range(8)).map(lambda order: python_program(list(order))))
def test_python_attribution_is_total_and_deterministic(text: str) -> None:
    _assert_total_and_deterministic(Language.PYTHON, text)


@given(st.permutations(range(8)).map(lambda order: javascript_program(list(order))))
def test_javascript_attribution_is_total_and_deterministic(text: str) -> None:
    _assert_total_and_deterministic(Language.JAVASCRIPT, text)


@given(NAMES, USES)
def test_a_python_name_defined_once_and_used_n_times_has_n_plus_one_references(
    name: str, uses: int
) -> None:
    body = "".join(f"    consume({name})\n" for _ in range(uses))
    _, table = table_of(Language.PYTHON, f"def f():\n    {name} = 0\n{body}")
    assert len(table.references(name, 1)) == uses + 1
    assert [s.is_definition for s in table.symbols if s.name == name] == [True] + [False] * uses


@given(NAMES, USES)
def test_a_javascript_name_defined_once_and_used_n_times_has_n_plus_one_references(
    name: str, uses: int
) -> None:
    body = "".join(f"  consume({name});\n" for _ in range(uses))
    _, table = table_of(Language.JAVASCRIPT, f"function f() {{\n  let {name} = 0;\n{body}}}\n")
    assert len(table.references(name, 1)) == uses + 1


@given(NAMES, NAMES, USES)
def test_two_bindings_of_one_spelling_never_share_references(
    name: str, other: str, uses: int
) -> None:
    body = "".join(f"    consume({name})\n" for _ in range(uses))
    source = f"{name} = 1\ndef f({name}):\n{body}    return {other}\n"
    _, table = table_of(Language.PYTHON, source)
    outer = {location.start_line for location in table.references(name, 0)}
    inner = {location.start_line for location in table.references(name, 1)}
    assert outer == {1}
    assert 2 in inner
    assert not outer & inner
