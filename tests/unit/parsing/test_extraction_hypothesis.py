"""Identifier exhaustiveness and string/comment disjointness, over small generated programs.

The conformance corpus (``test_conformance.py``) is the acceptance criterion; this is the
"small generated programs" half of the same "Tests required" bullet. Hypothesis does not
generate arbitrary Python or JavaScript (nothing here parses it reliably); it instead picks and
orders a combination of small, independently valid statements from a fixed pool, so every
generated program is syntactically valid by construction while still varying shape, nesting and
which constructs appear together.
"""

from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import Language
from codekavach.parsing import parse
from tests.support.conformance import (
    assert_identifiers_exhaustive,
    assert_strings_and_comments_disjoint,
)
from tests.support.parsing_generators import javascript_program, python_program


@given(st.permutations(range(8)).map(lambda order: python_program(list(order))))
def test_python_identifiers_exhaustive_over_generated_programs(text: str) -> None:
    parsed = parse("generated.py", Language.PYTHON, text)
    assert_identifiers_exhaustive(Language.PYTHON, text, parsed)
    assert_strings_and_comments_disjoint(parsed)


@given(st.permutations(range(8)).map(lambda order: javascript_program(list(order))))
def test_javascript_identifiers_exhaustive_over_generated_programs(text: str) -> None:
    parsed = parse("generated.js", Language.JAVASCRIPT, text)
    assert_identifiers_exhaustive(Language.JAVASCRIPT, text, parsed)
    assert_strings_and_comments_disjoint(parsed)
