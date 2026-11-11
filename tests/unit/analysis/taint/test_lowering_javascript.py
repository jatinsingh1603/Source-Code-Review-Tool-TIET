"""The JavaScript and TypeScript lowering (E17-01)."""

from codekavach.analysis.taint.ir import Assign, Branch, Loop, Op, Place, Raise
from codekavach.core.models import Language
from tests.support.taint import calls, function_of, lower_source, statements

JS = Language.JAVASCRIPT


def test_declarations_destructuring_and_member_reads() -> None:
    code = "function h(req) {\n  const { name } = req.query;\n  const p = req.body.id;\n}\n"
    function = function_of(lower_source(code, JS), "h")
    assigns = {s.target.text: s.value for s in statements(function) if isinstance(s, Assign)}
    assert assigns["name"] == Place(base="req", steps=(".query",))
    assert assigns["p"] == Place(base="req", steps=(".body", ".id"))


def test_template_strings_and_concatenation_are_string_operations() -> None:
    code = "function h(a) {\n  const x = `/tmp/${a}`;\n  const y = 'k' + a;\n}\n"
    function = function_of(lower_source(code, JS), "h")
    values = [s.value for s in statements(function) if isinstance(s, Assign)]
    assert [v.style for v in values if isinstance(v, Op)] == ["template", "concat"]


def test_require_binds_a_resolvable_module_symbol() -> None:
    code = "const fs = require('fs');\nfunction h(p) {\n  fs.readFile(p, cb);\n}\n"
    (call,) = calls(function_of(lower_source(code, JS), "h"))
    assert call.callee.symbol == "fs.readFile"
    assert call.receiver == Place(base="fs")


def test_callbacks_are_functions_of_their_own() -> None:
    module = lower_source("function h(res) {\n  load((e, d) => res.send(d));\n}\n", JS)
    callback = function_of(module, "h.<callback1>")
    assert callback.params == ("e", "d")
    assert [c.callee.text for c in calls(callback)] == ["res.send"]


def test_loops_branches_try_and_switch_produce_a_well_formed_graph() -> None:
    code = (
        "function h(items, n) {\n  for (const k of items) { use(k); }\n  while (n) { break; }\n"
        "  if (n) a(); else b();\n  try { c(n[0]); } catch (e) { throw e; } finally { d(); }\n"
        "  switch (n) { case 1: f(); break; default: g(); }\n  return n;\n}\n"
    )
    function = function_of(lower_source(code, JS), "h")
    assert {Loop, Branch, Raise} <= {type(s) for s in statements(function)}
    ids = {b.id for b in function.blocks}
    assert all(b.stmts for b in function.blocks)
    for stmt in statements(function):
        if isinstance(stmt, Branch):
            assert {stmt.then_block, stmt.else_block} <= ids


def test_classes_methods_and_typescript_types() -> None:
    code = "class S {\n  run(q: string): void {\n    exec(q as string);\n  }\n}\n"
    module = lower_source(code + "interface I { a: number }\n", Language.TYPESCRIPT)
    method = function_of(module, "S.run")
    assert method.params == ("q",)
    assert [c.callee.text for c in calls(method)] == ["exec"]


def test_new_expressions_are_calls() -> None:
    module = lower_source("function h(u) {\n  const r = new Request(u);\n}\n", JS)
    (call,) = calls(function_of(module, "h"))
    assert call.callee.text == "new Request"
    assert call.result == Place(base="r")


def test_lowering_is_deterministic() -> None:
    code = "function h(a) { for (const i of a) { if (i) g(i); } return a; }\n"
    assert lower_source(code, JS) == lower_source(code, JS)
