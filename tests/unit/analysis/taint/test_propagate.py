"""Intraprocedural propagation, sanitiser adequacy and path construction (E17-02)."""

# ruff: noqa: S608 - the fixtures are source text for the analyser, never executed

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.analysis.taint.catalogue import SINK_CLASSES, Binding, sink_kind
from codekavach.analysis.taint.path import build_path, build_path_result, cap_per_sink
from codekavach.analysis.taint.propagate import Budget, BudgetExceededError, propagate_bound
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language, TaintRole
from tests.support.golden import assert_matches_golden
from tests.support.taint import (
    candidates_of,
    flows_of,
    lower_source,
    shipped_catalogues,
)

GOLDEN = Path(__file__).parent / "golden"
JS = Language.JAVASCRIPT
FLASK = "import sqlite3\nfrom flask import request\n"
WORKED = (
    FLASK
    + "\ndef transfer(cur):\n"
    + "    to = request.args.get('to')\n"
    + '    q = "UPDATE accounts SET payee = \'" + to + "\'"\n'
    + "    cur.execute(q)\n"
)


def roles(code: str, language: Language = Language.PYTHON) -> list[list[TaintRole]]:
    found = []
    for function, flow in flows_of(code, language):
        path = build_path(flow, function)
        assert path is not None
        found.append([step.role for step in path.steps])
    return found


# --- worked example --------------------------------------------------------------------------


def test_the_worked_example_yields_one_three_step_path() -> None:
    ((function, flow),) = flows_of(WORKED)
    path = build_path(flow, function)
    assert path is not None
    assert [(s.role, s.location.start_line) for s in path.steps] == [
        (TaintRole.SOURCE, 5),
        (TaintRole.PROPAGATOR, 6),
        (TaintRole.SINK, 7),
    ]
    assert [s.note for s in path.steps][1] == "concat"
    assert path.sink.note == "cur.execute arg 0"
    assert all(s.location.symbol == "transfer" for s in path.steps)


def test_the_parameterised_variant_yields_no_path() -> None:
    code = FLASK + (
        "\ndef transfer(cur):\n    to = request.args.get('to')\n"
        "    q = 'UPDATE accounts SET payee = ?'\n    cur.execute(q, (to,))\n"
    )
    assert flows_of(code) == []


def test_the_candidate_matches_the_golden_file() -> None:
    (candidate,) = candidates_of(WORKED, path="services/api/transfer.py")
    assert candidate.engine == "codekavach-taint"
    assert candidate.rule_id == "taint.http_param.sql"
    assert candidate.cwe == (89,)
    assert candidate.taint_path is not None and len(candidate.taint_path) == 3
    assert candidate.taint_path.sink.location.path == candidate.primary_location.path
    text = candidate.model_dump_json(indent=2, exclude={"id"}) + "\n"
    assert_matches_golden(text, GOLDEN / "worked_example_candidate.json")


# --- sanitiser adequacy ----------------------------------------------------------------------


def test_a_sanitiser_covering_the_right_context_yields_no_path() -> None:
    code = (
        "from flask import request, make_response\nfrom markupsafe import escape\n\n"
        "def view():\n    v = request.args.get('v')\n    return make_response(escape(v))\n"
    )
    assert flows_of(code) == []


def test_a_sanitiser_covering_the_wrong_context_yields_an_inadequate_step() -> None:
    code = (
        "import shlex\nfrom flask import request, make_response\n\n"
        "def view():\n    v = request.args.get('v')\n    return make_response(shlex.quote(v))\n"
    )
    ((function, flow),) = flows_of(code)
    path = build_path(flow, function)
    assert path is not None and path.is_sanitised
    (sanitiser,) = [s for s in path.steps if s.role is TaintRole.SANITISER]
    assert sanitiser.note is not None
    assert "sanitiser.inadequate" in sanitiser.note
    assert "required_context=html" in sanitiser.note and "covered=shell" in sanitiser.note
    assert flow.covered == frozenset({"shell"})


@pytest.mark.parametrize(
    ("sanitiser", "sink_context", "flows"),
    [
        ("html.escape", "html", 0),
        ("html.escape", "path", 1),
        ("shlex.quote", "html", 1),
        ("os.path.basename", "path", 0),
        ("urllib.parse.quote", "path", 1),
    ],
)
def test_adequacy_matrix(sanitiser: str, sink_context: str, flows: int) -> None:
    module, _, name = sanitiser.rpartition(".")
    sink = {
        "html": ("from flask import make_response", "make_response"),
        "path": ("from flask import send_file", "send_file"),
    }[sink_context]
    code = (
        f"import {module.split('.')[0]}\n{sink[0]}\nfrom flask import request\n\n"
        f"def view():\n    v = request.args.get('v')\n    return {sink[1]}({module}.{name}(v))\n"
    )
    assert len(flows_of(code)) == flows


# --- transfer functions ----------------------------------------------------------------------


def test_a_source_call_taints_its_result_and_a_source_place_taints_its_reader() -> None:
    code = "import os\n\ndef f(c):\n    a = input()\n    b = os.environ\n    c.execute(a + b)\n"
    assert {flow.label for _, flow in flows_of(code)} == {"cli", "environment"}


def test_an_unknown_callee_with_a_tainted_argument_gives_an_uncertain_result() -> None:
    code = (
        FLASK
        + "\ndef f(cur):\n    t = request.args.get('x')\n    u = mystery(t)\n    cur.execute(u)\n"
    )
    ((function, flow),) = flows_of(code)
    assert flow.uncertain
    path = build_path(flow, function)
    assert path is not None and path.steps[1].note == "call mystery"
    (candidate,) = candidates_of(code)
    assert dict(candidate.properties)["taint.uncertain"] == "true"


def test_an_unknown_callee_without_tainted_arguments_stays_untainted() -> None:
    code = FLASK + "\ndef f(cur):\n    u = mystery('x')\n    cur.execute(u)\n"
    assert flows_of(code) == []


def test_a_comparison_does_not_carry_taint() -> None:
    code = FLASK + "\ndef f(cur):\n    ok = request.args.get('x') == 'a'\n    cur.execute(ok)\n"
    assert flows_of(code) == []


def test_a_sink_argument_other_than_the_sink_index_is_not_reported() -> None:
    code = FLASK + "\ndef f(cur):\n    t = request.args.get('x')\n    cur.execute('select 1', t)\n"
    assert flows_of(code) == []


def test_reassignment_clears_taint() -> None:
    code = (
        FLASK + "\ndef f(cur):\n    t = request.args.get('x')\n    t = 'safe'\n    cur.execute(t)\n"
    )
    assert flows_of(code) == []


def test_taint_survives_a_conditional_reassignment_and_a_loop() -> None:
    code = FLASK + (
        "\ndef f(cur, flag, rows):\n    q = 'select 1'\n    if flag:\n"
        "        q = q + request.args.get('x')\n    for r in rows:\n        q = q + r\n"
        "    cur.execute(q)\n"
    )
    assert len(flows_of(code)) == 1


def test_a_loop_carried_flow_is_found_within_the_iteration_bound() -> None:
    code = FLASK + (
        "\ndef f(cur, rows):\n    q = ''\n    for r in rows:\n        cur.execute(q)\n"
        "        q = request.args.get('x')\n"
    )
    assert len(flows_of(code)) == 1


def test_branch_guards_are_recorded_on_the_flow() -> None:
    code = FLASK + (
        "\ndef f(cur):\n    t = request.args.get('x')\n    if t.startswith('a'):\n"
        "        cur.execute(t)\n"
    )
    ((_, flow),) = flows_of(code)
    assert flow.guards == (6,)
    (candidate,) = candidates_of(code)
    assert dict(candidate.properties)["taint.guards"] == "6"


# --- string operations and narrowing ---------------------------------------------------------

PY_OPERATIONS = {
    "concat": "q = 'select ' + t",
    "fstring": "q = f'select {t}'",
    "format": "q = 'select {}'.format(t)",
    "percent": "q = 'select %s' % t",
    "join": "q = ''.join(['select ', t])",
    "replace": "q = 'select X'.replace('X', t)",
    "str": "q = str(t)",
    "augmented": "q = 'select '\n    q += t",
}


@pytest.mark.parametrize("operation", sorted(PY_OPERATIONS))
def test_python_string_operations_propagate_taint(operation: str) -> None:
    body = PY_OPERATIONS[operation]
    code = FLASK + f"\ndef f(cur):\n    t = request.args.get('x')\n    {body}\n    cur.execute(q)\n"
    ((_, flow),) = flows_of(code)
    assert not flow.uncertain, operation


JS_OPERATIONS = {
    "template": "const q = `select ${t}`;",
    "concat": "const q = 'select ' + t;",
    "concat-call": "const q = 'select '.concat(t);",
    "join": "const q = ['select ', t].join('');",
    "replace": "const q = 'select X'.replace('X', t);",
    "augmented": "let q = 'select '; q += t;",
}


@pytest.mark.parametrize("operation", sorted(JS_OPERATIONS))
def test_javascript_string_operations_propagate_taint(operation: str) -> None:
    body = JS_OPERATIONS[operation]
    head = (
        "const { exec } = require('child_process');\nfunction h(req) {\n  const t = req.query.x;\n"
    )
    code = head + f"  {body}\n  exec(q);\n}}\n"
    ((_, flow),) = flows_of(code, JS)
    assert flow.sink.kind == "shell"
    assert not flow.uncertain, operation


def test_a_numeric_conversion_clears_taint_for_a_query_sink_but_not_a_path_sink() -> None:
    query = (
        FLASK
        + "\ndef f(cur):\n    n = int(request.args.get('n'))\n    cur.execute('select ' + str(n))\n"
    )
    path = FLASK + "\ndef f():\n    n = int(request.args.get('n'))\n    open(str(n))\n"
    assert flows_of(query) == []
    ((_, flow),) = flows_of(path)
    assert flow.sink.kind == "path"


def test_javascript_numeric_conversions_follow_the_same_table() -> None:
    shell = (
        "const { exec } = require('child_process');\nconst fs = require('fs');\n"
        "function h(req) {\n  const n = parseInt(req.query.n);\n  exec('ls ' + n);\n}\n"
        "function g(req) {\n  const n = Number(req.query.n);\n  fs.readFile('/tmp/' + n);\n}\n"
    )
    found = flows_of(shell, JS)
    assert [(f.qualname, flow.sink.kind) for f, flow in found] == [("g", "path")]


# --- caps, trimming and validity -------------------------------------------------------------


def test_a_long_chain_is_trimmed_and_keeps_source_sink_and_sanitisers() -> None:
    body = "".join(f"    a{n + 1} = a{n}\n" for n in range(100))
    code = (
        "import shlex\nfrom flask import request, make_response\n\n"
        "def f():\n    a0 = request.args.get('x')\n    a0 = shlex.quote(a0)\n"
        + body
        + "    make_response(a100)\n"
    )
    ((function, flow),) = flows_of(code)
    result = build_path_result(flow, function, 10)
    assert result is not None and result.trimmed
    assert len(result.path) == 10
    roles_ = [s.role for s in result.path.steps]
    assert roles_[0] is TaintRole.SOURCE and roles_[-1] is TaintRole.SINK
    assert TaintRole.SANITISER in roles_
    lines = [s.location.start_line for s in result.path.steps]
    assert lines == sorted(lines)
    (candidate,) = candidates_of(code, settings=TaintSettings(max_path_steps=10))
    assert dict(candidate.properties)["taint.path_trimmed"] == "true"


def test_paths_per_sink_are_capped_shortest_first() -> None:
    reads = "".join(f"    s{n} = request.args.get('k{n}')\n" for n in range(6))
    code = (
        FLASK
        + "\ndef f(cur):\n"
        + reads
        + "    q = s0 + s1 + s2 + s3 + s4 + s5\n    cur.execute(q)\n"
    )
    assert len(candidates_of(code, settings=TaintSettings(max_paths_per_sink=3))) == 3
    assert len(candidates_of(code, settings=TaintSettings(max_paths_per_sink=10))) == 6
    flows = [flow for _, flow in flows_of(code)]
    kept = cap_per_sink(flows, 2)
    assert kept == sorted(flows, key=lambda flow: flow.sort_key)[:2]


def test_a_witness_that_cannot_form_a_valid_path_is_dropped() -> None:
    ((function, flow),) = flows_of(WORKED)
    broken = flow.__class__(
        origin=flow.origin,
        label=flow.label,
        source_id=flow.source_id,
        steps=flow.steps[1:],
        sink=flow.sink,
        sink_location=flow.sink_location,
        sink_callee=flow.sink_callee,
        arg_index=flow.arg_index,
        uncertain=False,
    )
    assert build_path(broken, function) is None


def test_the_time_budget_stops_propagation() -> None:
    module = lower_source(FLASK + "\ndef f(c):\n    t = request.args.get('x')\n    c.execute(t)\n")
    function = next(f for f in module.functions if f.name == "f")
    binding = Binding(shipped_catalogues(), module.aliases, "python")
    with pytest.raises(BudgetExceededError):
        propagate_bound(function, binding, budget=Budget(deadline=0.0, _ticks=63))


def test_every_shipped_sink_has_a_weakness_class_or_is_deliberately_excluded() -> None:
    kinds = {sink_kind(entry) for catalogue in shipped_catalogues() for entry in catalogue.sinks}
    assert kinds - {None} <= set(SINK_CLASSES)
    excluded = {
        entry.id
        for catalogue in shipped_catalogues()
        for entry in catalogue.sinks
        if sink_kind(entry) is None
    }
    assert all(".weakhash." in item for item in excluded)


@settings(max_examples=40, deadline=None)
@given(st.integers(min_value=1, max_value=120))
def test_any_assignment_chain_from_source_to_sink_yields_one_bounded_path(length: int) -> None:
    body = "".join(f"    a{n + 1} = a{n}\n" for n in range(length))
    code = (
        FLASK
        + "\ndef f(cur):\n    a0 = request.args.get('x')\n"
        + body
        + f"    cur.execute(a{length})\n"
    )
    ((function, flow),) = flows_of(code)
    path = build_path(flow, function, 64)
    assert path is not None
    assert path.steps[0].role is TaintRole.SOURCE
    assert path.steps[-1].role is TaintRole.SINK
    assert len(path) <= 64
