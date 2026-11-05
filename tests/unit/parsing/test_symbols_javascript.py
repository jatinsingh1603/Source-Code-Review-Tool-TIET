"""JavaScript and TypeScript scoping rules of the symbol table, one test per rule (E07-03)."""

from textwrap import dedent

from codekavach.core.models import Language
from codekavach.parsing.symbols import SymbolTable
from tests.support.symbols import lines_of, named, scope_ids, table_of


def _js(source: str) -> SymbolTable:
    return table_of(Language.JAVASCRIPT, dedent(source).lstrip("\n"))[1]


def _ts(source: str) -> SymbolTable:
    return table_of(Language.TYPESCRIPT, dedent(source).lstrip("\n"))[1]


def test_hoisting_example_from_the_issue() -> None:
    table = _js(
        """
        function pay(amount) {
          if (amount > limit) { var fee = 1; }
          return fee;
        }
        let limit = 10;
        """
    )
    fee = named(table, "fee")
    assert [s.scope_id for s in fee] == [1, 1]
    assert table.scopes[1].kind == "function"
    assert lines_of(table, "fee", 1) == [2, 3]
    assert lines_of(table, "limit", 0) == [2, 5]


def test_a_block_let_and_an_enclosing_function_var_are_different_bindings() -> None:
    table = _js(
        """
        function f() {
          var x = 1;
          { let x = 2; use(x); }
          return x;
        }
        """
    )
    ids = scope_ids(table, "x")
    assert ids[0] == ids[3]
    assert ids[1] == ids[2]
    assert ids[0] != ids[1]
    assert table.scopes[ids[0]].kind == "function"
    assert table.scopes[ids[1]].kind == "block"


def test_let_and_const_are_block_scoped() -> None:
    table = _js(
        """
        { const k = 1; let m = 2; }
        use(k, m);
        """
    )
    assert [s.scope_id for s in named(table, "k")][1] == -1
    assert [s.scope_id for s in named(table, "m")][1] == -1


def test_a_var_inside_a_block_is_visible_in_the_function() -> None:
    table = _js(
        """
        function f() {
          { var v = 1; }
          return v;
        }
        """
    )
    assert lines_of(table, "v", 1) == [2, 3]


def test_function_declarations_hoist_to_the_top_of_their_scope() -> None:
    table = _js(
        """
        run();
        function run() { helper(); function helper() {} }
        """
    )
    assert lines_of(table, "run", 0) == [1, 2]
    assert lines_of(table, "helper", 1) == [2, 2]


def test_a_catch_parameter_has_its_own_scope() -> None:
    table = _js(
        """
        let e = 1;
        try { risky(); } catch (e) { log(e); }
        use(e);
        """
    )
    ids = scope_ids(table, "e")
    assert ids[0] == ids[3] == 0
    assert ids[1] == ids[2] != 0
    assert table.scopes[ids[1]].kind == "block"


def test_a_class_declaration_binds_in_its_block_and_members_are_not_lexical() -> None:
    table = _js(
        """
        let x = 0;
        class A {
          x = 1;
          m() { return x; }
        }
        new A();
        """
    )
    assert lines_of(table, "A", 0) == [2, 6]
    assert lines_of(table, "x", 0) == [1, 4]
    members = [s for s in named(table, "x") if s.kind == "field"]
    assert [s.location.start_line for s in members] == [3]
    assert table.scopes[members[0].scope_id].kind == "class"


def test_a_class_expression_name_is_visible_only_inside_the_class() -> None:
    table = _js(
        """
        const C = class Inner { make() { return new Inner(); } };
        use(Inner);
        """
    )
    ids = scope_ids(table, "Inner")
    assert ids[0] == ids[1] != -1
    assert ids[2] == -1


def test_an_arrow_function_binds_only_its_parameters() -> None:
    table = _js(
        """
        function outer() {
          const f = (a) => this.v + arguments.length + a;
          return f;
        }
        """
    )
    assert not named(table, "this")
    assert scope_ids(table, "arguments") == [-1]
    a = named(table, "a")
    assert a[0].kind == "parameter"
    assert {s.scope_id for s in a} == {a[0].scope_id}
    assert table.scopes[a[0].scope_id].kind == "function"


def test_declaration_patterns_bind_and_assignment_patterns_only_use() -> None:
    table = _js(
        """
        let a, b;
        const { p, q: r = 1 } = src;
        [a, b] = [b, a];
        ({ p } = other);
        """
    )
    assert [s.is_definition for s in named(table, "a")] == [True, False, False]
    assert lines_of(table, "r", 0) == [2]
    assert [s.scope_id for s in named(table, "p")] == [0, 0]
    assert [s.is_definition for s in named(table, "p")] == [True, False]
    assert [s.kind for s in named(table, "q")] == ["field"]


def test_member_and_object_keys_are_external_but_shorthand_values_are_uses() -> None:
    table = _js(
        """
        const value = 1;
        const o = { value: 2, value, other: value };
        o.value;
        """
    )
    kinds = [(s.kind, s.scope_id) for s in named(table, "value")]
    assert kinds == [
        ("variable", 0),
        ("field", -1),
        ("variable", 0),
        ("variable", 0),
        ("field", -1),
    ]


def test_a_loop_header_let_is_scoped_to_the_loop() -> None:
    table = _js(
        """
        let i = 9;
        for (let i = 0; i < 3; i++) { use(i); }
        for (const k of items) { use(k); }
        use(i);
        """
    )
    ids = scope_ids(table, "i")
    assert ids[0] == ids[-1] == 0
    assert len(set(ids[1:-1])) == 1
    assert ids[1] != 0


def test_imports_bind_local_names_and_re_exports_do_not() -> None:
    table = _js(
        """
        import def, { a, b as c } from "m";
        import * as ns from "n";
        export { a as z };
        export { q } from "o";
        """
    )
    assert {s.name for s in table.definitions_by_kind("import")} == {"def", "a", "c", "ns"}
    assert lines_of(table, "a", 0) == [1, 3]
    assert all(s.scope_id == -1 for s in named(table, "b"))
    assert all(s.scope_id == -1 for s in named(table, "q"))


def test_a_function_expression_name_is_local_to_the_function() -> None:
    table = _js(
        """
        const h = function named(n) { return n ? named(n - 1) : 0; };
        named;
        """
    )
    ids = scope_ids(table, "named")
    assert ids[0] == ids[1] != -1
    assert ids[2] == -1


def test_dynamic_access_is_unresolved() -> None:
    table = _js(
        """
        function read(obj, key) {
          return obj[key] + eval("1") + globalThis.x;
        }
        """
    )
    unresolved = {s.name for s in table.unresolved()}
    assert {"eval", "globalThis", "x"} <= unresolved
    assert not {"obj", "key"} & unresolved
    assert all(s.scope_id == -1 and s.kind in {"variable", "field"} for s in table.unresolved())


def test_labels_are_not_variables() -> None:
    table = _js(
        """
        let outer = 0;
        outer: for (;;) { break outer; }
        """
    )
    assert lines_of(table, "outer", 0) == [1]


def test_typescript_type_parameters_are_visible_in_the_declaration() -> None:
    table = _ts(
        """
        class Repo<T> {
          items: T[] = [];
          get<K extends keyof T>(key: K): T[K] { return this.items[0]; }
        }
        function id<V>(value: V): V { return value; }
        """
    )
    t = named(table, "T")
    assert len({s.scope_id for s in t}) == 1
    assert t[0].is_definition
    assert -1 not in {s.scope_id for s in t}
    v = named(table, "V")
    assert len({s.scope_id for s in v}) == 1
    assert len(v) == 3  # the declaration, the parameter type and the return type


def test_typescript_interfaces_aliases_and_enums_bind_their_names() -> None:
    table = _ts(
        """
        interface Shape { area(): number; name: string }
        type Alias = Shape;
        enum Color { Red, Green = 2 }
        let x: Alias = Color.Red;
        """
    )
    assert lines_of(table, "Shape", 0) == [1, 2]
    assert lines_of(table, "Alias", 0) == [2, 4]
    assert lines_of(table, "Color", 0) == [3, 4]
    assert [s.kind for s in named(table, "Red")] == ["field", "field"]
    assert [s.scope_id for s in named(table, "Red")][1] == -1


def test_typescript_function_ranges_are_recorded_for_methods_and_classes() -> None:
    table = _ts(
        """
        class Account {
          deposit(amount: number): void {}
        }
        """
    )
    assert [named(table, "deposit")[0].kind] == ["method"]
    assert [table.symbols[e.symbol_index].name for e in table.extents] == ["Account", "deposit"]
