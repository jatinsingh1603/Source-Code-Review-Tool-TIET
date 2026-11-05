"""Python scoping rules of the symbol table, one test per rule (E07-03)."""

from textwrap import dedent

from codekavach.core.models import Language
from codekavach.parsing.symbols import SymbolTable
from tests.support.symbols import lines_of, named, scope_ids, table_of


def _table(source: str) -> SymbolTable:
    return table_of(Language.PYTHON, dedent(source).lstrip("\n"))[1]


def test_shadowing_example_from_the_issue() -> None:
    table = _table(
        """
        total = 0
        def apply_fee(total, rate):
            def inner():
                nonlocal total
                total += 1
            inner()
            return total
        """
    )
    assert lines_of(table, "total", 0) == [1]
    assert lines_of(table, "total", 1) == [2, 4, 5, 7]
    assert len(table.references("total", 1)) == 4


def test_a_class_body_name_and_a_method_body_name_resolve_to_different_scopes() -> None:
    table = _table(
        """
        class A:
            value = 1
            def m(self):
                value = 2
                return value
        """
    )
    ids = scope_ids(table, "value")
    class_scope, method_scope = ids[0], ids[1]
    assert class_scope != method_scope
    assert table.scopes[class_scope].kind == "class"
    assert table.scopes[method_scope].kind == "function"
    assert lines_of(table, "value", method_scope) == [4, 5]


def test_a_class_body_does_not_enclose_its_methods() -> None:
    table = _table(
        """
        x = 1
        class A:
            x = 2
            def m(self):
                return x
        """
    )
    assert scope_ids(table, "x")[-1] == 0


def test_a_class_body_sees_its_own_earlier_names() -> None:
    table = _table(
        """
        class A:
            x = 1
            y = x + 1
        """
    )
    assert scope_ids(table, "x")[0] == scope_ids(table, "x")[1]


def test_a_comprehension_variable_is_scoped_to_the_comprehension() -> None:
    table = _table(
        """
        i = 0
        squares = [i * i for i in range(3)]
        print(i)
        """
    )
    assert lines_of(table, "i", 0) == [1, 3]
    inner = {s for s in scope_ids(table, "i") if s != 0}
    assert len(inner) == 1
    assert table.scopes[inner.pop()].kind == "function"


def test_the_first_iterable_of_a_comprehension_is_read_in_the_enclosing_scope() -> None:
    table = _table(
        """
        data = [1, 2]
        out = [d for d in data]
        """
    )
    assert lines_of(table, "data", 0) == [1, 2]


def test_a_generator_expression_has_its_own_scope() -> None:
    table = _table(
        """
        n = 5
        total = sum(n for n in range(3))
        """
    )
    assert lines_of(table, "n", 0) == [1]


def test_global_rebinds_a_name_to_the_module() -> None:
    table = _table(
        """
        counter = 0
        def bump():
            global counter
            counter += 1
        """
    )
    assert lines_of(table, "counter", 0) == [1, 3, 4]
    assert all(not s.is_definition for s in named(table, "counter")[1:])


def test_nonlocal_rebinds_a_name_to_the_enclosing_function() -> None:
    table = _table(
        """
        def outer():
            count = 0
            def inner():
                nonlocal count
                count += 1
            return count
        """
    )
    assert lines_of(table, "count", 1) == [2, 4, 5, 6]


def test_except_as_binds_the_name() -> None:
    table = _table(
        """
        def f():
            try:
                g()
            except ValueError as err:
                log(err)
        """
    )
    err = named(table, "err")
    assert [s.is_definition for s in err] == [True, False]
    assert err[0].scope_id == err[1].scope_id == 1


def test_with_as_binds_in_the_enclosing_function() -> None:
    table = _table(
        """
        def f(path):
            with open(path) as fh:
                return fh.read()
        """
    )
    fh = named(table, "fh")
    assert [s.scope_id for s in fh] == [1, 1]
    assert fh[0].is_definition


def test_a_walrus_target_binds_in_the_enclosing_function() -> None:
    table = _table(
        """
        def f():
            if (n := compute()):
                return n
        """
    )
    assert lines_of(table, "n", 1) == [2, 3]


def test_a_walrus_in_a_comprehension_binds_outside_the_comprehension() -> None:
    table = _table(
        """
        def f(items):
            hits = [y := item for item in items]
            return y
        """
    )
    assert lines_of(table, "y", 1) == [2, 3]


def test_parameters_bind_in_the_function_and_defaults_read_the_enclosing_scope() -> None:
    table = _table(
        """
        limit = 10
        def f(a, b=limit, *args, **kwargs):
            return a, b, args, kwargs
        """
    )
    assert lines_of(table, "limit", 0) == [1, 2]
    for name in ("a", "b", "args", "kwargs"):
        symbols = named(table, name)
        assert symbols[0].kind == "parameter"
        assert symbols[0].is_definition
        assert {s.scope_id for s in symbols} == {1}


def test_a_lambda_parameter_is_scoped_to_the_lambda() -> None:
    table = _table(
        """
        x = 1
        f = lambda x: x + 1
        """
    )
    assert lines_of(table, "x", 0) == [1]


def test_a_decorator_and_an_annotation_are_read_in_the_enclosing_scope() -> None:
    table = _table(
        """
        kind = int
        def deco(fn): return fn
        @deco
        def f(a: kind) -> kind:
            return a
        """
    )
    assert lines_of(table, "kind", 0) == [1, 4, 4]
    assert lines_of(table, "deco", 0) == [2, 3]


def test_imports_bind_the_local_name_only() -> None:
    table = _table(
        """
        import os.path
        import numpy as np
        from pkg.mod import thing as other, plain
        """
    )
    bound = {s.name for s in table.definitions_by_kind("import")}
    assert bound == {"os", "np", "other", "plain"}
    # ``path`` is a member of the module ``os``, ``pkg`` and ``mod`` name the source module,
    # and ``thing`` is the name inside that module: none is a binding of this file.
    for name in ("path", "pkg", "mod", "thing"):
        assert all(s.scope_id == -1 and not s.is_definition for s in named(table, name))


def test_attribute_and_keyword_names_are_not_variables() -> None:
    table = _table(
        """
        value = 1
        obj.value = 2
        call(value=value)
        """
    )
    assert lines_of(table, "value", 0) == [1, 3]
    assert [s.kind for s in table.symbols if s.name == "value" and s.scope_id == -1] == [
        "field",
        "parameter",
    ]


def test_unresolved_names_are_scope_minus_one() -> None:
    table = _table(
        """
        def read(obj, name):
            return getattr(obj, name), globals()[name], undefined_thing
        """
    )
    unresolved = {s.name for s in table.unresolved()}
    assert {"getattr", "globals", "undefined_thing"} <= unresolved
    assert all(s.scope_id == -1 and s.kind == "variable" for s in table.unresolved())
    assert not {"obj", "name"} & unresolved


def test_a_use_before_a_later_definition_resolves_to_it() -> None:
    table = _table(
        """
        def f():
            return helper()
        def helper():
            return 1
        """
    )
    assert lines_of(table, "helper", 0) == [2, 3]


def test_definitions_by_kind() -> None:
    table = _table(
        """
        LIMIT = 3
        class K:
            field = 1
            def m(self): pass
        def f(): pass
        """
    )
    assert [s.name for s in table.definitions_by_kind("class")] == ["K"]
    assert [s.name for s in table.definitions_by_kind("method")] == ["m"]
    assert [s.name for s in table.definitions_by_kind("function")] == ["f"]
    assert [s.name for s in table.definitions_by_kind("constant")] == ["LIMIT"]
    assert [s.name for s in table.definitions_by_kind("field")] == ["field"]


def test_enclosing_finds_the_innermost_definition() -> None:
    parsed, table = table_of(
        Language.PYTHON,
        dedent(
            """
            class K:
                def m(self):
                    return 1
            def f():
                return 2
            """
        ).lstrip("\n"),
    )
    inside_method = next(loc for loc, text in parsed.identifiers() if text == "self")
    symbol = table.enclosing(inside_method)
    assert symbol is not None
    assert symbol.name == "m"
    first_identifier = parsed.identifiers()[0][0]  # the class name, inside the class's own range
    enclosing = table.enclosing(first_identifier)
    assert enclosing is not None
    assert enclosing.name == "K"
