"""The Python lowering (E17-01)."""

from pathlib import Path

from codekavach.analysis.taint.ir import (
    Assign,
    Branch,
    Const,
    Goto,
    Loop,
    Op,
    Place,
    Raise,
    Return,
    Unknown,
)
from codekavach.analysis.taint.lowering import coverage_note, get_lowering, lowering_languages
from codekavach.core.models import Language
from tests.support.golden import assert_matches_golden
from tests.support.taint import calls, function_of, lower_source, statements

GOLDEN = Path(__file__).parent / "golden"


def test_an_assignment_from_a_call_defines_the_target_with_the_call_result() -> None:
    module = lower_source("def f(r):\n    q = r.args.get('q')\n")
    (call,) = calls(function_of(module, "f"))
    assert call.result == Place(base="q")
    assert call.receiver == Place(base="r", steps=(".args",))
    assert call.callee.text == "r.args.get"
    assert call.args == (Const(kind="str", shape="q"),)


def test_imported_names_resolve_to_dotted_symbols() -> None:
    code = "import os\nfrom flask import request\n\ndef f():\n    os.popen(request.args['x'])\n"
    module = lower_source(code)
    symbols = [c.callee.symbol for c in calls(function_of(module, "f"))]
    assert symbols == ["flask.request.args.__getitem__", "os.popen"]


def test_concatenation_formatting_and_fstrings_are_string_operations() -> None:
    code = (
        "def f(a, b):\n    x = 'S ' + a\n    y = 'S %s' % a\n"
        "    z = f'S {a} {b.c}'\n    w = a + 1\n"
    )
    module = lower_source(code)
    values = [s.value for s in statements(function_of(module, "f")) if isinstance(s, Assign)]
    styles = [v.style for v in values if isinstance(v, Op)]
    assert styles == ["concat", "format", "fstring", "binary"]


def test_a_subscript_read_is_a_call_and_a_subscript_write_is_a_weak_place() -> None:
    module = lower_source("def f(d, r):\n    d['k'] = 1\n    x = r['y']\n")
    function = function_of(module, "f")
    (assign,) = [s for s in statements(function) if isinstance(s, Assign)]
    assert assign.target.text == "d[*]"
    assert not assign.target.strong()
    assert calls(function)[0].callee.text == "r.__getitem__"


def test_access_paths_are_cut_at_the_configured_depth() -> None:
    module = lower_source("def f(a):\n    x = a.b.c.d.e.f\n")
    (assign,) = [s for s in statements(function_of(module, "f")) if isinstance(s, Assign)]
    assert isinstance(assign.value, Place)
    assert assign.value.truncated
    assert assign.value.text == "a.b.c.d..."


def test_if_creates_a_branch_with_both_arms_joining() -> None:
    code = "def f(c):\n    if c:\n        x = 1\n    else:\n        x = 2\n    return x\n"
    blocks = function_of(lower_source(code), "f").blocks
    branch = blocks[0].stmts[-1]
    assert isinstance(branch, Branch)
    assert (branch.then_block, branch.else_block) == (1, 2)
    jumps = [b.stmts[-1] for b in blocks[1:3]]
    assert all(isinstance(j, Goto) for j in jumps)
    assert len({j.target for j in jumps if isinstance(j, Goto)}) == 1


def test_a_loop_has_a_header_a_back_edge_and_an_exit() -> None:
    module = lower_source("def f(rows):\n    for r in rows:\n        use(r)\n")
    blocks = function_of(module, "f").blocks
    loop = next(s for b in blocks for s in b.stmts if isinstance(s, Loop))
    back = blocks[loop.body_block].stmts[-1]
    assert isinstance(back, Goto) and back.target == loop.header_block
    first = blocks[loop.body_block].stmts[0]
    assert isinstance(first, Assign) and first.value == Place(base="rows", steps=("[*]",))


def test_try_body_calls_carry_the_handler_block() -> None:
    code = (
        "def f(x):\n    try:\n        a(x)\n    except OSError as e:\n        b(e)\n"
        "    finally:\n        c()\n"
    )
    by_name = {c.callee.text: c for c in calls(function_of(lower_source(code), "f"))}
    assert by_name["a"].handler is not None
    assert by_name["b"].handler is None and by_name["c"].handler is None


def test_raise_return_and_the_implicit_return() -> None:
    module = lower_source("def f(x):\n    if x:\n        raise ValueError(x)\n")
    function = function_of(module, "f")
    assert Raise in {type(s) for s in statements(function)}
    returns = [s for s in statements(function) if isinstance(s, Return)]
    assert returns and all(r.implicit for r in returns)


def test_nested_calls_are_hoisted_into_temporaries() -> None:
    module = lower_source("def f(x):\n    a(b(x))\n")
    first, second = calls(function_of(module, "f"))
    assert first.callee.text == "b" and first.result is not None
    assert second.callee.text == "a" and second.args == (first.result,)


def test_methods_lambdas_and_decorators_become_functions() -> None:
    code = "class C:\n    @route('/x')\n    def m(self, a):\n        return lambda y: y + a\n"
    module = lower_source(code)
    names = [f.qualname for f in module.functions]
    assert names[0] == "<module>"
    assert "C.m" in names and any("<lambda>" in n for n in names)
    assert function_of(module, "C.m").decorators == ("route('/x')",)
    assert function_of(module, "C.m").params == ("self", "a")


def test_unpacking_and_comprehensions_keep_taint_flowing() -> None:
    module = lower_source("def f(q):\n    a, b = g(q)\n    z = [i for i in q if i]\n")
    targets = {s.target.text for s in statements(function_of(module, "f")) if isinstance(s, Assign)}
    assert {"a", "b", "i", "z"} <= targets


def test_unsupported_constructs_become_unknown_with_their_names() -> None:
    module = lower_source("def f(x):\n    match x:\n        case 1:\n            pass\n")
    unknown = [s for s in statements(function_of(module, "f")) if isinstance(s, Unknown)]
    assert unknown and Place(base="x") in unknown[0].mentions


def test_malformed_code_is_lowered_and_marked_degraded() -> None:
    module = lower_source("def f(x:\n    y = (\n")
    assert module.degraded_reason is not None
    assert module.functions


def test_lowering_is_deterministic() -> None:
    code = "def f(a):\n    for i in a:\n        if i:\n            g(i)\n    return a\n"
    assert lower_source(code) == lower_source(code)


def test_every_block_ends_in_a_terminator_and_every_target_exists() -> None:
    code = (
        "def f(a):\n    while a:\n        try:\n            g(a)\n        except E:\n"
        "            break\n        else:\n            continue\n    return a\n"
    )
    function = function_of(lower_source(code), "f")
    ids = {b.id for b in function.blocks}
    for block in function.blocks:
        last = block.stmts[-1]
        assert isinstance(last, Return | Branch | Loop | Goto | Raise)
        if isinstance(last, Branch):
            assert {last.then_block, last.else_block} <= ids
        elif isinstance(last, Loop):
            assert {last.body_block, last.exit_block} <= ids
        elif isinstance(last, Goto):
            assert last.target in ids


def test_the_registry_has_python_javascript_and_pending_stubs() -> None:
    languages = set(lowering_languages())
    assert {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.GO} <= languages
    assert get_lowering(Language.PYTHON).version
    assert "go" in coverage_note(Language.GO)


def test_the_transfer_handler_lowering_matches_the_golden_file() -> None:
    code = (
        "import os\nfrom flask import request\n\n"
        "@app.route('/transfer', methods=['POST'])\n"
        "def transfer(account):\n"
        "    to = request.args.get('to')\n"
        "    note = request.form['note']\n"
        '    query = "UPDATE t SET n=\'" + note + "\' WHERE a=" + account\n'
        "    for row in db.execute(query):\n"
        "        if row.flag:\n            continue\n"
        "        audit(row, to)\n"
        "    try:\n        os.system('notify ' + to)\n"
        "    except OSError:\n        return None\n"
        "    return query\n"
    )
    module = lower_source(code, path="services/api/transfer.py")
    assert_matches_golden(module.model_dump_json(indent=2) + "\n", GOLDEN / "ir_transfer.json")
