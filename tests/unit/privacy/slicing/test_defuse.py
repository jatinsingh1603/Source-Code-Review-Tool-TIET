"""Def-use chains and control dependence (E11-03).

Each case is a small source read by the real parser and symbol table. The answers are the lines of
the defining statements and of the statements that decide whether a line runs; they are what the
taint-path, backward and forward strategies cut.
"""

import time

import pytest

from codekavach.core.models import Location
from tests.support.slicing import make_index

WORKED = """def transfer(req, items):
    amount = req.json["amount"]
    total = 0
    for item in items:
        total += item.price
        if total > 10:
            break
    if not is_admin(req.user):
        raise Forbidden()
    cur.execute("UPDATE accounts SET bal = bal - " + amount)
    with open(amount) as fh:
        data = fh.read()
    return data
"""

JS_WORKED = """function transfer(req, items) {
  const amount = req.body.amount;
  let total = 0;
  for (const item of items) {
    total += item.price;
    if (total > 10) {
      break;
    }
  }
  if (!isAdmin(req.user)) {
    throw new Forbidden();
  }
  db.query(`UPDATE a SET b = ${amount}`);
}
"""


def at(path: str, line: int) -> Location:
    return Location(path=path, start_line=line, end_line=line)


def defs(source: str, path: str, line: int, name: str) -> list[int]:
    index = make_index({path: source}).defuse_of(path)
    return [d.start_line for d in index.definitions_reaching(at(path, line), name)]


def controls(source: str, path: str, line: int) -> list[tuple[int, int]]:
    index = make_index({path: source}).defuse_of(path)
    return [(c.start_line, c.end_line) for c in index.control_ancestors(at(path, line))]


# --- definitions that reach a use -------------------------------------------------------------


def test_the_sink_argument_is_defined_by_the_source_statement() -> None:
    assert defs(WORKED, "a.py", 10, "amount") == [2]


def test_a_parameter_is_a_definition_on_the_signature() -> None:
    assert defs(WORKED, "a.py", 2, "req") == [1]


def test_a_loop_carried_dependence_reaches_its_own_statement() -> None:
    assert defs(WORKED, "a.py", 5, "total") == [3, 5]


def test_the_latest_certain_definition_kills_the_earlier_ones() -> None:
    source = "def f():\n    x = 1\n    x = 2\n    return x\n"
    assert defs(source, "a.py", 4, "x") == [3]


def test_definitions_in_both_branches_reach_a_use_after_the_branch() -> None:
    source = (
        "def f(c):\n    x = 0\n    if c:\n        x = 1\n    else:\n        x = 2\n    return x\n"
    )
    assert defs(source, "a.py", 7, "x") == [2, 4, 6]


def test_a_definition_in_a_branch_does_not_kill_the_one_before_it() -> None:
    source = "def f(c):\n    x = 0\n    if c:\n        x = 1\n    return x\n"
    assert defs(source, "a.py", 5, "x") == [2, 4]


def test_a_loop_target_is_certain_only_inside_its_loop() -> None:
    source = "def f(xs):\n    x = 0\n    for x in xs:\n        use(x)\n    return x\n"
    assert defs(source, "a.py", 4, "x") == [3]
    assert defs(source, "a.py", 5, "x") == [2, 3]


def test_a_member_name_is_not_a_variable() -> None:
    source = "def f(req):\n    json = 1\n    return req.json\n"
    assert defs(source, "a.py", 3, "json") == []


def test_a_nested_definition_with_the_same_name_does_not_kill_the_outer_one() -> None:
    source = "def f():\n    x = 1\n    def g():\n        x = 2\n        return x\n    return x\n"
    assert defs(source, "a.py", 6, "x") == [2]
    assert defs(source, "a.py", 5, "x") == [4]


def test_a_name_without_a_visible_binding_has_no_definition() -> None:
    assert defs(WORKED, "a.py", 8, "is_admin") == []
    assert defs(WORKED, "a.py", 10, "cur") == []


def test_a_location_outside_any_function_has_no_chain() -> None:
    source = "x = 1\ny = x\n"
    assert defs(source, "a.py", 2, "x") == []
    assert controls(source, "a.py", 2) == []


def test_the_with_target_is_a_definition_that_reaches_its_body() -> None:
    assert defs(WORKED, "a.py", 12, "fh") == [11]


# --- control dependence -----------------------------------------------------------------------


def test_the_sink_depends_on_the_early_exit_guard_before_it() -> None:
    assert controls(WORKED, "a.py", 10) == [(8, 9)]


def test_a_statement_depends_on_the_loop_and_the_condition_around_it() -> None:
    assert controls(WORKED, "a.py", 7) == [(4, 4), (6, 6)]


def test_an_if_that_does_not_exit_is_not_a_guard() -> None:
    source = "def f(c):\n    if c:\n        log(c)\n    sink(c)\n"
    assert controls(source, "a.py", 4) == []


def test_an_assert_before_the_statement_is_a_guard() -> None:
    source = "def f(c):\n    assert c\n    sink(c)\n"
    assert controls(source, "a.py", 3) == [(2, 2)]


def test_a_guard_in_an_enclosing_list_counts_for_a_nested_statement() -> None:
    source = "def f(a, b):\n    if not a:\n        return\n    if b:\n        sink(a)\n"
    assert controls(source, "a.py", 5) == [(2, 4)]  # the guard and the if are adjacent lines


def test_a_guard_after_the_statement_is_not_a_dependence() -> None:
    source = "def f(c):\n    sink(c)\n    if not c:\n        return\n"
    assert controls(source, "a.py", 2) == []


def test_an_else_branch_that_exits_makes_the_if_a_guard() -> None:
    source = "def f(c):\n    if c:\n        ok()\n    else:\n        return\n    sink(c)\n"
    assert controls(source, "a.py", 6) == [(2, 5)]


# --- JavaScript -------------------------------------------------------------------------------


def test_javascript_template_literal_use_is_defined_by_the_const() -> None:
    assert defs(JS_WORKED, "a.js", 13, "amount") == [2]


def test_javascript_augmented_assignment_is_carried_around_the_loop() -> None:
    assert defs(JS_WORKED, "a.js", 5, "total") == [3, 5]


def test_javascript_guard_and_closers_are_control_lines() -> None:
    assert controls(JS_WORKED, "a.js", 13) == [(10, 12)]
    assert controls(JS_WORKED, "a.js", 7) == [(4, 4), (6, 6), (8, 9)]


def test_javascript_loop_target_reaches_the_body() -> None:
    assert defs(JS_WORKED, "a.js", 5, "item") == [4]


def test_javascript_update_expression_reads_and_writes() -> None:
    source = "function f() {\n  let i = 0;\n  while (i < 3) {\n    i++;\n  }\n  return i;\n}\n"
    assert defs(source, "a.js", 3, "i") == [2, 4]
    assert defs(source, "a.js", 6, "i") == [2, 4]


# --- the flow object --------------------------------------------------------------------------


def test_readers_are_the_statements_a_definition_reaches() -> None:
    index = make_index({"a.py": WORKED})
    flow = index.defuse_of("a.py").flow_for(at("a.py", 10))
    assert flow is not None
    amount = next(k for k in flow.writes_of(flow.statement_at(2) or 0) if k[0] == "amount")
    readers = flow.readers(flow.statement_at(2) or 0, amount)
    assert [flow.statements[i].lines.start for i in readers] == [10, 11]


def test_a_one_line_if_body_is_the_same_line_unit_pair() -> None:
    source = "def f(c):\n    if c: x = 1\n    return x\n"
    assert defs(source, "a.py", 3, "x") == [2]


@pytest.mark.parametrize("name", ["total", "x", "amount"])
def test_asking_twice_gives_the_same_answer(name: str) -> None:
    first = defs(WORKED, "a.py", 5, name)
    assert first == defs(WORKED, "a.py", 5, name)


# --- performance ------------------------------------------------------------------------------


def _long_function(lines: int) -> str:
    body = ["def big(a):", "    v0 = a"]
    body.extend(f"    v{number} = v{number - 1} + {number}" for number in range(1, lines))
    body.append(f"    return v{lines - 1}")
    return "\n".join(body) + "\n"


@pytest.mark.perf
def test_a_backward_walk_of_depth_20_over_500_lines_is_fast_once_the_index_exists() -> None:
    source = _long_function(500)
    index = make_index({"big.py": source}).defuse_of("big.py")
    last = at("big.py", 502)
    index.definitions_reaching(last, "v499")  # builds the flow of the function: once per file
    started = time.perf_counter()
    line = 502
    name = "v499"
    for _ in range(20):
        found = index.definitions_reaching(at("big.py", line), name)
        assert found
        line = found[0].start_line
        name = f"v{line - 3}"
    assert time.perf_counter() - started < 0.030 * 3
