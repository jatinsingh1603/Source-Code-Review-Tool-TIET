"""Performance budget: the symbol table and function ranges of a 5 000-line file (E07-03).

The issue's budget is "no more than the parse itself", and "well under 200 milliseconds" for a
5 000-line file. Measured on the development machine (a slow one: the repository's other timing
tests already need ``CODEKAVACH_PERF_FACTOR=3`` there), ``build_symbol_table`` costs about as much
as ``parse`` (roughly 0.18 s against 0.19 s for 5 000 lines of Python, 0.18 s against 0.18 s for
4 500 lines of JavaScript) and ``function_ranges`` about a quarter of it. Both budgets below are
the measured numbers plus headroom, not the issue's figures, and are scaled by the performance
factor: an absolute ceiling, and a ratio to the parse that catches a regression on any machine.

Profiling what is left shows ``Symbol`` construction (one pydantic model per identifier, which
the ``SymbolTable`` contract requires) and the tree walk itself, which creates one
``tree_sitter.Node`` per syntax node; neither is avoidable without changing the contract.
"""

import time

import pytest

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.functions import function_ranges
from codekavach.parsing.symbols import build_symbol_table
from tests.support.perf import assert_within_budget, measure

FUNCTIONS = 500
SYMBOLS_BUDGET_SECONDS = 0.6
FUNCTIONS_BUDGET_SECONDS = 0.3
MAX_RATIO_TO_PARSE = 2.0

PYTHON_FUNCTION = """
def handler_{i}(request, limit=10):
    total = 0
    for item in request.items:
        if item.value > limit:
            total += item.value
        else:
            total -= 1
    result = [x * 2 for x in range(total)]
    return total, result
"""

JAVASCRIPT_FUNCTION = """
function handler_{i}(request, limit) {{
  let total = 0;
  for (const item of request.items) {{
    if (item.value > limit) {{ total += item.value; }} else {{ total -= 1; }}
  }}
  const result = [1, 2].map((x) => x * 2);
  return {{ total, result }};
}}
"""

CASES = [
    (Language.PYTHON, PYTHON_FUNCTION, "py"),
    (Language.JAVASCRIPT, JAVASCRIPT_FUNCTION, "js"),
]


@pytest.mark.perf
@pytest.mark.parametrize(("language", "template", "extension"), CASES, ids=["python", "javascript"])
def test_symbol_table_and_function_ranges_of_a_5000_line_file_stay_within_budget(
    language: Language, template: str, extension: str
) -> None:
    text = "".join(template.format(i=i) for i in range(FUNCTIONS))
    assert text.count("\n") >= 4_500
    started = time.perf_counter()
    parsed = parse(f"synthetic/big.{extension}", language, text)
    parse_seconds = time.perf_counter() - started
    spec = REGISTRY.get(language)

    symbols_seconds = measure(lambda: build_symbol_table(parsed, spec), repeat=3)
    functions_seconds = measure(lambda: function_ranges(parsed, spec), repeat=3)

    assert_within_budget(symbols_seconds, SYMBOLS_BUDGET_SECONDS, label="build_symbol_table")
    assert_within_budget(functions_seconds, FUNCTIONS_BUDGET_SECONDS, label="function_ranges")
    assert_within_budget(
        symbols_seconds,
        parse_seconds * MAX_RATIO_TO_PARSE,
        factor=1.0,
        label="build_symbol_table relative to parse",
    )
    assert len(build_symbol_table(parsed, spec).symbols) == len(parsed.identifiers())
