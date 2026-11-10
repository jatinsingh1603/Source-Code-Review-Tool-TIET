"""Go scoping rules of the symbol table, one test per rule (E07-05).

The named pitfalls of the issue are the regression cases: ``:=`` in an ``if`` initialiser binds for
the whole ``if``/``else`` chain, a method receiver is a parameter, and exported names are a
visibility fact, not a public-API fact.
"""

from textwrap import dedent

from codekavach.core.models import Language
from codekavach.parsing.symbols import SymbolTable
from tests.support.symbols import lines_of, named, scope_ids, table_of


def _go(source: str) -> SymbolTable:
    return table_of(Language.GO, dedent(source).lstrip("\n"))[1]


def test_the_worked_example_of_the_issue() -> None:
    table = _go(
        """
        package billing
        func (e *Engine) Accrue(amount int64) int64 {
            if rate := e.rate(); rate > 0 {
                return amount * rate
            }
            return 0
        }
        """
    )
    rate = [s for s in named(table, "rate") if s.scope_id >= 0]
    assert len(rate) == 3
    assert len({s.scope_id for s in rate}) == 1
    assert table.scopes[rate[0].scope_id].kind == "block"
    assert named(table, "e")[0].kind == "parameter"
    assert named(table, "amount")[0].kind == "parameter"
    assert scope_ids(table, "e")[0] == scope_ids(table, "amount")[0]


def test_a_short_declaration_in_an_if_initialiser_binds_for_the_whole_chain() -> None:
    table = _go(
        """
        package p
        func f(x int) int {
            if a := x + 1; a > 2 {
                return a
            } else if b := a * 2; b > 1 {
                return b + a
            }
            return 0
        }
        """
    )
    a_scope = scope_ids(table, "a")
    assert len(set(a_scope)) == 1 and a_scope[0] > 1
    assert lines_of(table, "a", a_scope[0]) == [3, 3, 4, 5, 6]
    assert len(set(scope_ids(table, "b"))) == 1


def test_a_short_declaration_shadows_in_an_inner_block_only() -> None:
    table = _go(
        """
        package p
        func f() int {
            total := 1
            {
                total := 2
                _ = total
            }
            return total
        }
        """
    )
    scopes = scope_ids(table, "total")
    assert scopes[0] == scopes[3]
    assert scopes[1] == scopes[2]
    assert scopes[0] != scopes[1]


def test_a_receiver_and_a_named_result_are_parameters_of_the_function() -> None:
    table = _go(
        """
        package p
        func (s Stack) Pop() (value int, err error) { return }
        """
    )
    for name in ("s", "value", "err"):
        assert named(table, name)[0].kind == "parameter"
        assert scope_ids(table, name)[0] == scope_ids(table, "s")[0]


def test_methods_and_fields_are_declared_in_a_class_scope_that_a_bare_name_does_not_reach() -> None:
    table = _go(
        """
        package p
        type Engine struct { rate int }
        func (e *Engine) Rate() int { return e.rate }
        func other() int { return rate }
        """
    )
    rates = named(table, "rate")
    assert rates[0].is_definition and table.scopes[rates[0].scope_id].kind == "class"
    assert rates[1].scope_id == -1  # e.rate: a selector is external
    assert rates[2].scope_id == -1  # a bare rate does not see the field
    assert named(table, "Rate")[0].kind == "method"


def test_a_range_clause_declares_only_with_a_short_declaration() -> None:
    table = _go(
        """
        package p
        func f(xs []int) {
            var k, v int
            for k, v = range xs { _, _ = k, v }
            for i, w := range xs { _, _ = i, w }
        }
        """
    )
    assert named(table, "i")[0].is_definition
    k = named(table, "k")
    assert [s.is_definition for s in k] == [True, False, False]
    assert len({s.scope_id for s in k}) == 1


def test_a_type_switch_alias_is_declared_in_the_switch() -> None:
    table = _go(
        """
        package p
        func f(x interface{}) int {
            switch t := x.(type) {
            case int:
                return t
            }
            return 0
        }
        """
    )
    t = named(table, "t")
    assert t[0].is_definition and t[0].scope_id == t[1].scope_id > 1


def test_a_select_receive_declares_with_a_short_declaration() -> None:
    table = _go(
        """
        package p
        func f(ch chan int) int {
            select {
            case v := <-ch:
                return v
            }
            return 0
        }
        """
    )
    assert named(table, "v")[0].is_definition
    assert len(set(scope_ids(table, "v"))) == 1


def test_a_function_literal_is_its_own_function_scope() -> None:
    table = _go(
        """
        package p
        func f() func(int) int {
            base := 1
            return func(a int) int { return a + base }
        }
        """
    )
    assert scope_ids(table, "base")[0] == scope_ids(table, "base")[1]
    a = named(table, "a")
    assert a[0].scope_id == a[1].scope_id
    assert a[0].scope_id != scope_ids(table, "base")[0]
    assert table.scopes[a[0].scope_id].kind == "function"


def test_a_function_type_does_not_leak_its_parameter_names() -> None:
    table = _go(
        """
        package p
        type Handler func(name string) error
        var name = 1
        """
    )
    names = named(table, "name")
    assert names[0].scope_id != names[1].scope_id
    assert names[1].scope_id == 0


def test_imports_declare_their_alias_and_the_default_name_is_a_plain_reference() -> None:
    table = _go(
        """
        package p
        import (
            "os"
            led "github.com/acme/ledger"
            _ "embed"
        )
        var a = os.Args
        var b = led.Open
        """
    )
    assert named(table, "led")[0].kind == "import" and named(table, "led")[0].is_definition
    assert named(table, "os")[0].scope_id == -1  # no node declares the default name


def test_a_selector_field_a_label_and_a_qualified_type_member_are_external() -> None:
    table = _go(
        """
        package p
        import "net/http"
        func f(r *http.Request) {
        loop:
            for {
                _ = r.URL
                break loop
            }
        }
        """
    )
    assert all(s.scope_id == -1 for s in named(table, "URL"))
    assert all(s.scope_id == -1 for s in named(table, "loop"))
    assert named(table, "Request")[0].scope_id == -1


def test_exported_and_unexported_names_are_declared_alike() -> None:
    table = _go(
        """
        package p
        func Public() {}
        func private() {}
        """
    )
    assert named(table, "Public")[0].is_definition
    assert named(table, "private")[0].is_definition
    assert named(table, "Public")[0].scope_id == named(table, "private")[0].scope_id == 0


def test_package_level_declarations_are_in_the_module_scope() -> None:
    table = _go(
        """
        package p
        const Max, Min = 1, 0
        var counter int
        func use() int { return Max + counter }
        """
    )
    assert scope_ids(table, "Max") == [0, 0]
    assert named(table, "Max")[0].kind == "constant"
    assert scope_ids(table, "counter") == [0, 0]


def test_the_blank_identifier_binds_nothing() -> None:
    table = _go(
        """
        package p
        func f() { _, err := g(); _ = err }
        """
    )
    assert all(s.scope_id == -1 for s in named(table, "_"))
