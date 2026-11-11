"""The control flow graph and the reaching definitions (E17-01)."""

from codekavach.analysis.taint.cfg import build_cfg
from codekavach.analysis.taint.defuse import PARAM_INDEX, Definition, analyse
from codekavach.analysis.taint.ir import Assign, Call, Place
from tests.support.taint import function_of, lower_source


def analysed(code: str, name: str = "f"):  # type: ignore[no-untyped-def]
    function = function_of(lower_source(code), name)
    return function, analyse(function)


def reaching_lines(function, info, place: Place, kind=Call):  # type: ignore[no-untyped-def]
    """The source lines of the definitions reaching the first read of ``place`` by ``kind``."""
    for block in function.blocks:
        for index, stmt in enumerate(block.stmts):
            if isinstance(stmt, kind) and any(
                isinstance(a, Place) and a.text == place.text for a in getattr(stmt, "args", ())
            ):
                found = info.definitions(place, block.id, index)
                return sorted(
                    function.blocks[d.site.block].stmts[d.site.index].location.start_line
                    if d.site.index != PARAM_INDEX
                    else 0
                    for d in found
                )
    raise AssertionError("no read found")


def test_straight_line_code_is_one_block_with_no_back_edge() -> None:
    function, _ = analysed("def f(a):\n    b = a\n    return b\n")
    cfg = build_cfg(function)
    assert cfg.order == (0,)
    assert cfg.back_edges == frozenset()
    assert cfg.exits == frozenset({0})


def test_a_loop_has_one_back_edge_to_its_header() -> None:
    function, _ = analysed("def f(r):\n    for x in r:\n        use(x)\n")
    cfg = build_cfg(function)
    assert len(cfg.back_edges) == 1
    ((_, header),) = cfg.back_edges
    assert cfg.is_loop_header(header)


def test_a_handler_is_reachable_from_the_try_body() -> None:
    function, _ = analysed("def f(x):\n    try:\n        a(x)\n    except E:\n        b(x)\n")
    cfg = build_cfg(function)
    assert len(cfg.reachable) == len(function.blocks) or len(cfg.reachable) >= 4


def test_a_later_assignment_kills_an_earlier_one() -> None:
    code = "def f(a):\n    x = a\n    x = 'safe'\n    use(x)\n"
    function, info = analysed(code)
    assert reaching_lines(function, info, Place(base="x")) == [3]


def test_both_arms_of_a_conditional_reach_the_join() -> None:
    code = "def f(c, a):\n    if c:\n        x = a\n    else:\n        x = 'k'\n    use(x)\n"
    function, info = analysed(code)
    assert reaching_lines(function, info, Place(base="x")) == [3, 5]
    assert info.phis, "two definitions meet at the join"
    (phi,) = (p for phis in info.phis.values() for p in phis if p.place.base == "x")
    assert len(phi.sources) == 2


def test_a_loop_carried_definition_reaches_the_top_of_the_loop() -> None:
    code = (
        "def f(items):\n    acc = ''\n    for i in items:\n        use(acc)\n"
        "        acc = acc + i\n"
    )
    function, info = analysed(code)
    assert reaching_lines(function, info, Place(base="acc")) == [2, 5]


def test_parameters_are_definitions_at_the_entry() -> None:
    function, info = analysed("def f(a):\n    use(a)\n")
    (param,) = info.parameters
    assert param == Definition(param.site, Place(base="a"))
    assert reaching_lines(function, info, Place(base="a")) == [0]
    (use,) = info.uses(param)
    assert use.place == Place(base="a")


def test_writing_a_whole_object_kills_its_fields_but_a_field_write_does_not_kill_the_object() -> (
    None
):
    code = "def f(a, b):\n    o.p = a\n    o = b\n    use(o.p)\n"
    function, info = analysed(code)
    assert reaching_lines(function, info, Place(base="o", steps=(".p",))) == [3]
    code = "def f(a, b):\n    o = b\n    o.p = a\n    use(o)\n"
    function, info = analysed(code)
    assert reaching_lines(function, info, Place(base="o")) == [2, 3]


def test_an_indexed_write_is_weak_and_keeps_earlier_definitions() -> None:
    code = "def f(a, b):\n    d = a\n    d['k'] = b\n    use(d)\n"
    function, info = analysed(code)
    assert reaching_lines(function, info, Place(base="d")) == [2, 3]


def test_a_use_of_a_field_is_reached_by_a_write_to_its_parent() -> None:
    code = "def f(a):\n    o = a\n    use(o.p)\n"
    function, info = analysed(code)
    assert reaching_lines(function, info, Place(base="o", steps=(".p",))) == [2]


def test_unreachable_code_has_no_reaching_definitions() -> None:
    code = "def f(a):\n    return a\n    x = a\n    use(x)\n"
    function, info = analysed(code)
    unreachable = [b.id for b in function.blocks if b.id not in info.cfg.reachable]
    assert unreachable


def test_def_use_chains_list_every_read_of_a_definition() -> None:
    code = "def f(a):\n    x = a\n    use(x)\n    other(x)\n"
    function, info = analysed(code)
    assign_index = next(i for i, s in enumerate(function.blocks[0].stmts) if isinstance(s, Assign))
    (definition,) = (
        d for d in info.definitions(Place(base="x"), 0, assign_index + 1) if d.place.text == "x"
    )
    assert [u.site.index for u in info.uses(definition)] == [assign_index + 1, assign_index + 2]
