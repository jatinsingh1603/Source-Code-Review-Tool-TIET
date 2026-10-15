"""``LanguageSpec.enclosing_symbol`` for Python and JavaScript (E07-02)."""

import tree_sitter as ts

from codekavach.core.models import Language
from codekavach.parsing.loader import load_language
from codekavach.parsing.spec import REGISTRY


def _first(root: ts.Node, node_type: str) -> ts.Node:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == node_type:
            return node
        stack.extend(reversed(node.children))
    raise AssertionError(f"no {node_type!r} node found")


def _enclosing(language: Language, source: str, marker_type: str) -> str | None:
    tree = ts.Parser(load_language(language)).parse(source.encode("utf-8"))
    node = _first(tree.root_node, marker_type)
    return REGISTRY.get(language).enclosing_symbol(node, source)


def test_python_module_level_function() -> None:
    source = "def top():\n    return 1\n"
    assert _enclosing(Language.PYTHON, source, "return_statement") == "top"


def test_python_method() -> None:
    source = "class Foo:\n    def method(self):\n        return 1\n"
    assert _enclosing(Language.PYTHON, source, "return_statement") == "Foo.method"


def test_python_nested_function() -> None:
    source = "def outer():\n    def inner():\n        return 1\n    return inner\n"
    assert _enclosing(Language.PYTHON, source, "return_statement") == "outer.inner"


def test_python_node_inside_a_comment_returns_none() -> None:
    source = "def f():\n    # a comment\n    return 1\n"
    assert _enclosing(Language.PYTHON, source, "comment") is None


def test_javascript_module_level_function() -> None:
    source = "function top(x) { return x; }"
    assert _enclosing(Language.JAVASCRIPT, source, "return_statement") == "top"


def test_javascript_method() -> None:
    source = "class Foo { method(a) { return a; } }"
    assert _enclosing(Language.JAVASCRIPT, source, "return_statement") == "Foo.method"


def test_javascript_nested_function() -> None:
    source = "function outer() { function inner() { return 1; } }"
    assert _enclosing(Language.JAVASCRIPT, source, "return_statement") == "outer.inner"


def test_javascript_arrow_function_assigned_to_a_constant() -> None:
    source = "const foo = (y) => { return y; };"
    assert _enclosing(Language.JAVASCRIPT, source, "return_statement") == "foo"


def test_javascript_class_expression() -> None:
    source = "const Klass = class { run() { return 1; } };"
    assert _enclosing(Language.JAVASCRIPT, source, "return_statement") == "Klass.run"


def test_javascript_node_inside_a_comment_returns_none() -> None:
    source = "function f() {\n  // a comment\n}\n"
    assert _enclosing(Language.JAVASCRIPT, source, "comment") is None


def test_typescript_interface_method_uses_the_javascript_logic() -> None:
    source = "class Foo implements Bar { method(): number { return 1; } }"
    assert _enclosing(Language.TYPESCRIPT, source, "return_statement") == "Foo.method"
