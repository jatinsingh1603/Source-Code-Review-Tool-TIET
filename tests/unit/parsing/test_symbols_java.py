"""Java scoping rules of the symbol table, one test per rule (E07-05).

The named pitfalls of the issue are the regression cases: annotations are identifiers, a field and
a local of the same name shadow with ``this.x`` disambiguating, and an anonymous class opens a
scope whose parent is the enclosing method.
"""

from textwrap import dedent

from codekavach.core.models import Language
from codekavach.parsing.symbols import SymbolTable
from tests.support.symbols import lines_of, named, scope_ids, table_of


def _java(source: str) -> SymbolTable:
    return table_of(Language.JAVA, dedent(source).lstrip("\n"))[1]


def test_a_field_is_visible_in_a_method_by_its_bare_name() -> None:
    table = _java(
        """
        class A {
            int rate;
            int f() { return rate; }
        }
        """
    )
    assert scope_ids(table, "rate") == [1, 1]
    assert table.scopes[1].kind == "class"


def test_a_local_shadows_the_field_and_this_dot_names_the_field() -> None:
    table = _java(
        """
        class A {
            int rate;
            void f() {
                int rate = 1;
                this.rate = rate;
            }
        }
        """
    )
    by_line = {(s.location.start_line, s.scope_id) for s in named(table, "rate")}
    assert by_line == {(2, 1), (4, 2), (5, -1), (5, 2)}
    assert lines_of(table, "rate", 2) == [4, 5]


def test_a_parameter_and_the_top_level_locals_of_a_method_share_one_scope() -> None:
    table = _java(
        """
        class A {
            int f(int amount) {
                int local = amount;
                return local;
            }
        }
        """
    )
    assert scope_ids(table, "amount") == [2, 2]
    assert scope_ids(table, "local") == [2, 2]
    assert table.scopes[2].kind == "function"


def test_a_block_a_for_header_and_a_catch_clause_each_open_a_scope() -> None:
    table = _java(
        """
        class A {
            void f() {
                { int a = 1; }
                for (int i = 0; i < 2; i++) { int b = i; }
                try { g(); } catch (Exception e) { h(e); }
            }
        }
        """
    )
    assert table.scopes[scope_ids(table, "a")[0]].kind == "block"
    assert scope_ids(table, "i") == [scope_ids(table, "i")[0]] * 4
    assert scope_ids(table, "i")[0] != scope_ids(table, "b")[0]
    assert scope_ids(table, "e")[0] == scope_ids(table, "e")[1]
    assert table.scopes[scope_ids(table, "e")[0]].kind == "block"


def test_try_with_resources_binds_the_resource_for_the_body() -> None:
    table = _java(
        """
        class A {
            int f(java.io.Reader s) throws Exception {
                try (java.io.Reader r = s) { return r.read(); }
            }
        }
        """
    )
    assert len(set(scope_ids(table, "r"))) == 1
    assert scope_ids(table, "r")[0] > 2


def test_a_lambda_parameter_is_bound_in_the_lambda() -> None:
    table = _java(
        """
        class A {
            void f(java.util.List<String> xs) {
                xs.forEach(x -> use(x));
                java.util.function.BiFunction<Integer, Integer, Integer> g = (a, b) -> a + b;
            }
        }
        """
    )
    assert scope_ids(table, "x")[0] == scope_ids(table, "x")[1] > 2
    assert named(table, "a")[0].kind == "parameter"
    assert named(table, "b")[0].kind == "parameter"


def test_an_anonymous_class_scope_has_the_enclosing_method_as_its_parent() -> None:
    table = _java(
        """
        class A {
            void f() {
                int captured = 1;
                Runnable r = new Runnable() {
                    int own;
                    public void run() { use(captured, own); }
                };
            }
        }
        """
    )
    own, captured = scope_ids(table, "own")[0], scope_ids(table, "captured")[0]
    assert table.scopes[own].kind == "class"
    assert table.scopes[own].parent_id == captured
    assert scope_ids(table, "captured")[1] == captured
    assert scope_ids(table, "own")[1] == own


def test_a_constructor_name_is_a_use_of_the_class_not_a_new_declaration() -> None:
    table = _java(
        """
        class Engine {
            Engine(int rate) { }
        }
        """
    )
    engine = named(table, "Engine")
    assert [s.is_definition for s in engine] == [True, False]
    assert scope_ids(table, "Engine") == [0, 0]


def test_an_import_declares_its_simple_name_and_the_package_is_external() -> None:
    table = _java(
        """
        import java.util.List;
        import static java.lang.Math.max;
        import com.acme.*;
        """
    )
    assert [(s.name, s.is_definition) for s in named(table, "List")] == [("List", True)]
    assert named(table, "List")[0].kind == "import"
    assert named(table, "max")[0].is_definition
    for name in ("java", "util", "lang", "com", "acme"):
        assert all(s.scope_id == -1 for s in named(table, name))


def test_annotations_are_identifiers_and_their_element_names_are_external() -> None:
    table = _java(
        """
        @interface Tag { String value() default "x"; }
        @Tag(value = "a")
        class A { @Deprecated int old; }
        """
    )
    tags = named(table, "Tag")
    assert len(tags) == 2  # the declaration and the use
    assert [s.scope_id for s in named(table, "Deprecated")] == [-1]
    value = [s for s in named(table, "value") if not s.is_definition]
    assert [s.scope_id for s in value] == [-1]


def test_method_calls_and_member_names_after_a_dot_are_external() -> None:
    table = _java(
        """
        class A {
            void f(B b) { b.run(); run(); }
            void run() {}
        }
        """
    )
    runs = named(table, "run")
    assert [(s.scope_id, s.is_definition) for s in runs] == [(-1, False), (1, False), (1, True)]
    assert runs[1].kind == "method"


def test_a_pattern_variable_binds_in_the_enclosing_scope() -> None:
    table = _java(
        """
        class A {
            void f(Object o) {
                if (o instanceof Account a && a.ok()) { use(a); }
            }
        }
        """
    )
    assert len(set(scope_ids(table, "a"))) == 1
    assert named(table, "a")[0].is_definition


def test_type_parameters_are_declared_where_the_type_or_method_is() -> None:
    table = _java(
        """
        class Box<T> {
            T item;
            <R> R map(T value) { return null; }
        }
        """
    )
    assert scope_ids(table, "T")[0] == 1
    assert scope_ids(table, "T")[1] == 1
    r = named(table, "R")
    assert r[0].is_definition and r[0].scope_id == r[1].scope_id


def test_an_enum_constant_and_a_record_component_are_declared_in_the_type() -> None:
    table = _java(
        """
        enum Color { RED, GREEN }
        record Point(int x, int y) { int sum() { return x + y; } }
        """
    )
    assert named(table, "RED")[0].kind == "constant"
    assert named(table, "x")[0].kind == "field"
    assert scope_ids(table, "x") == [scope_ids(table, "x")[0]] * 2


def test_static_and_instance_initialisers_are_function_scopes() -> None:
    table = _java(
        """
        class A {
            static int counter;
            static { int seed = 1; counter = seed; }
            { int boot = 2; counter += boot; }
        }
        """
    )
    assert table.scopes[scope_ids(table, "seed")[0]].kind == "function"
    assert table.scopes[scope_ids(table, "boot")[0]].kind == "function"


def test_the_extent_of_a_class_and_a_method_are_recorded() -> None:
    table = _java(
        """
        class A {
            void f() {}
        }
        """
    )
    assert {table.symbols[e.symbol_index].name for e in table.extents} == {"A", "f"}
