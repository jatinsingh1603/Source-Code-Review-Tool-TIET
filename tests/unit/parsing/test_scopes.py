"""The language-neutral scope machinery: ``ScopeBuilder`` and ``ScopeTree.lookup`` (E07-03)."""

from codekavach.parsing.scopes import MODULE_SCOPE, UNRESOLVED, ScopeBuilder


def _span(index: int) -> tuple[int, int]:
    return index * 10, index * 10 + 1


def _define(builder: ScopeBuilder, index: int, name: str, scope: int) -> None:
    builder.occur(*_span(index), name, scope, "define")


def _use(builder: ScopeBuilder, index: int, name: str, scope: int) -> None:
    builder.occur(*_span(index), name, scope, "reference")


def test_the_module_scope_is_scope_zero_and_ids_follow_opening_order() -> None:
    builder = ScopeBuilder()
    assert builder.open("module", None) == MODULE_SCOPE
    assert builder.open("function", 0) == 1
    assert builder.open("block", 1) == 2
    tree, _ = builder.build()
    assert [(s.id, s.parent_id, s.kind) for s in tree.scopes] == [
        (0, None, "module"),
        (1, 0, "function"),
        (2, 1, "block"),
    ]


def test_lookup_walks_outwards_and_returns_the_innermost_binding() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    inner = builder.open("function", 0)
    _define(builder, 0, "x", 0)
    _define(builder, 1, "x", inner)
    _define(builder, 2, "y", 0)
    tree, _ = builder.build()
    assert tree.lookup("x", inner) == inner
    assert tree.lookup("y", inner) == 0
    assert tree.lookup("missing", inner) is None


def test_a_reference_before_its_definition_still_resolves() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    _use(builder, 0, "later", 0)
    _define(builder, 1, "later", 0)
    _, bindings = builder.build()
    assert [(b.scope_id, b.is_definition) for b in bindings] == [(0, False), (0, True)]


def test_unresolved_references_are_scope_minus_one_variables() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    _use(builder, 0, "nowhere", 0)
    _, (binding,) = builder.build()
    assert (binding.scope_id, binding.kind, binding.is_definition) == (
        UNRESOLVED,
        "variable",
        False,
    )


def test_external_occurrences_never_resolve_even_if_the_name_is_declared() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    _define(builder, 0, "name", 0)
    builder.occur(*_span(1), "name", 0, "external", "field")
    _, bindings = builder.build()
    assert [(b.scope_id, b.kind) for b in bindings] == [(0, "variable"), (UNRESOLVED, "field")]


def test_class_scopes_are_skipped_by_lookups_from_nested_functions() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    cls = builder.open("class", 0)
    method = builder.open("function", cls)
    _define(builder, 0, "x", 0)
    _define(builder, 1, "x", cls)
    tree, _ = builder.build()
    assert tree.lookup("x", method) == 0


def test_a_class_body_sees_its_own_names_when_the_language_says_so() -> None:
    for sees, expected in ((True, 1), (False, 0)):
        builder = ScopeBuilder(class_body_sees_members=sees)
        builder.open("module", None)
        cls = builder.open("class", 0)
        _define(builder, 0, "x", 0)
        _define(builder, 1, "x", cls)
        tree, _ = builder.build()
        assert tree.lookup("x", cls) == expected


def test_a_definition_binds_in_its_own_scope_even_when_lookups_skip_it() -> None:
    builder = ScopeBuilder(class_body_sees_members=False)
    builder.open("module", None)
    cls = builder.open("class", 0)
    _define(builder, 0, "member", cls)
    _, (binding,) = builder.build()
    assert (binding.scope_id, binding.is_definition) == (cls, True)


def test_global_redirects_uses_and_definitions_to_the_module() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    func = builder.open("function", 0)
    _define(builder, 0, "n", 0)
    builder.declare_global(func, "n")
    _use(builder, 1, "n", func)
    _define(builder, 2, "n", func)
    _, bindings = builder.build()
    assert [(b.scope_id, b.is_definition) for b in bindings] == [(0, True), (0, False), (0, False)]


def test_global_of_an_undeclared_name_creates_the_module_binding() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    func = builder.open("function", 0)
    builder.declare_global(func, "created")
    _define(builder, 0, "created", func)
    _, (binding,) = builder.build()
    assert binding.scope_id == 0


def test_nonlocal_redirects_to_the_nearest_enclosing_function() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    outer = builder.open("function", 0)
    inner = builder.open("function", outer)
    _define(builder, 0, "n", 0)
    _define(builder, 1, "n", outer)
    builder.declare_nonlocal(inner, "n")
    _use(builder, 2, "n", inner)
    _define(builder, 3, "n", inner)
    _, bindings = builder.build()
    assert [b.scope_id for b in bindings] == [0, outer, outer, outer]
    assert [b.is_definition for b in bindings] == [True, True, False, False]


def test_enclosing_function_skips_blocks_and_comprehensions() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    func = builder.open("function", 0)
    block = builder.open("block", func)
    comprehension = builder.open("function", block, comprehension=True)
    assert builder.enclosing_function(comprehension) == func
    assert builder.enclosing_function(comprehension, skip_comprehensions=False) == comprehension
    assert builder.enclosing_function(block) == func
    assert builder.enclosing_function(func) == func
    assert builder.enclosing_function(MODULE_SCOPE) == MODULE_SCOPE


def test_bindings_come_back_in_source_order_whatever_the_recording_order() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    _define(builder, 2, "c", 0)
    _define(builder, 0, "a", 0)
    _define(builder, 1, "b", 0)
    _, bindings = builder.build()
    assert [b.name for b in bindings] == ["a", "b", "c"]


def test_the_first_definition_decides_the_kind_of_a_name() -> None:
    builder = ScopeBuilder()
    builder.open("module", None)
    builder.occur(*_span(0), "f", 0, "define", "function")
    builder.occur(*_span(1), "f", 0, "define", "variable")
    _use_span = _span(2)
    builder.occur(*_use_span, "f", 0, "reference")
    _, bindings = builder.build()
    assert [b.kind for b in bindings] == ["function", "function", "function"]
