"""``function_ranges``: exact, decorator-aware ranges that round-trip through ``LineIndex``."""

from textwrap import dedent

import pytest

from codekavach.core.models import Language, Location
from codekavach.parsing import REGISTRY
from codekavach.parsing.functions import FunctionRange, function_ranges
from codekavach.parsing.positions import LineIndex
from tests.support.conformance import FIXTURES, fixture_path, parse_fixture
from tests.support.symbols import table_of


def _ranges(language: Language, source: str) -> tuple[str, tuple[FunctionRange, ...]]:
    text = dedent(source).lstrip("\n")
    parsed, _ = table_of(language, text)
    return text, function_ranges(parsed, REGISTRY.get(language))


def _byte_span(text: str, location: Location) -> tuple[int, int]:
    """The UTF-8 byte offsets a ``Location`` denotes, computed independently of ``LineIndex``."""
    lines = text.split("\n")

    def offset(line: int, column: int | None) -> int:
        assert column is not None
        before = "".join(f"{item}\n" for item in lines[: line - 1])
        return len((before + lines[line - 1][: column - 1]).encode("utf-8"))

    return offset(location.start_line, location.start_col), offset(
        location.end_line, location.end_col
    )


def _text_of(text: str, location: Location) -> str:
    start, end = _byte_span(text, location)
    return text.encode("utf-8")[start:end].decode("utf-8")


def test_python_decorators_belong_to_full_and_not_to_header() -> None:
    text, ranges = _ranges(
        Language.PYTHON,
        """
        import functools

        @functools.cache
        @other(1, key="v")
        def compute(x: int) -> int:
            return x * 2
        """,
    )
    (item,) = ranges
    assert item.symbol_name == "compute"
    assert _text_of(text, item.full).startswith("@functools.cache\n@other(1")
    assert _text_of(text, item.header) == "def compute(x: int) -> int:"
    assert _text_of(text, item.body) == "return x * 2"
    assert [_text_of(text, d) for d in item.decorators] == [
        "@functools.cache",
        '@other(1, key="v")',
    ]
    assert item.full.start_line == 3
    assert item.header.start_line == 5


def test_a_typescript_method_decorator_is_in_full_and_not_in_header() -> None:
    text, ranges = _ranges(
        Language.TYPESCRIPT,
        """
        class Service {
          @log("call")
          public run(arg: string): void {
            use(arg);
          }
        }
        """,
    )
    (item,) = ranges
    assert item.qualified_name == "Service.run"
    assert item.kind == "method"
    assert _text_of(text, item.full).startswith('@log("call")')
    assert _text_of(text, item.header).startswith("public run(arg: string)")
    assert [_text_of(text, d) for d in item.decorators] == ['@log("call")']


def test_a_function_without_decorators_has_header_equal_to_the_start_of_full() -> None:
    text, ranges = _ranges(Language.PYTHON, "async def go():\n    await x()\n")
    (item,) = ranges
    assert item.decorators == ()
    assert _text_of(text, item.header) == "async def go():"
    assert (item.header.start_line, item.header.start_col) == (
        item.full.start_line,
        item.full.start_col,
    )


def test_nested_functions_and_methods_get_qualified_names() -> None:
    _, ranges = _ranges(
        Language.PYTHON,
        """
        def outer():
            def inner(): pass
        class K:
            def m(self):
                def deep(): pass
            class Nested:
                def n(self): pass
        """,
    )
    assert [(r.qualified_name, r.kind) for r in ranges] == [
        ("outer", "function"),
        ("outer.inner", "function"),
        ("K.m", "method"),
        ("K.m.deep", "function"),
        ("K.Nested.n", "method"),
    ]


def test_javascript_names_functions_by_what_they_are_bound_to() -> None:
    _, ranges = _ranges(
        Language.JAVASCRIPT,
        """
        function declared() {}
        const arrow = (a) => a;
        const expr = function () {};
        obj.assigned = () => 1;
        const o = { key: function () {}, method() {} };
        class C { field = () => 1; m() {} static s() {} }
        run(() => 1);
        """,
    )
    assert [r.qualified_name for r in ranges] == [
        "declared",
        "arrow",
        "expr",
        "assigned",
        "key",
        "method",
        "C.field",
        "C.m",
        "C.s",
    ]


def test_an_anonymous_callback_is_skipped_but_functions_inside_it_are_found() -> None:
    _, ranges = _ranges(Language.JAVASCRIPT, "run(() => { function inside() {} });\n")
    assert [r.qualified_name for r in ranges] == ["inside"]


def test_a_python_lambda_is_not_a_named_function() -> None:
    _, ranges = _ranges(Language.PYTHON, "f = lambda x: x\n")
    assert ranges == ()


def test_ranges_are_in_source_order_and_nest() -> None:
    _, ranges = _ranges(
        Language.PYTHON,
        """
        def a():
            def b(): pass
        def c(): pass
        """,
    )
    starts = [(r.full.start_line, r.full.start_col) for r in ranges]
    assert starts == sorted(starts)
    for item in ranges:
        assert (item.full.start_line, item.full.start_col) <= (
            item.header.start_line,
            item.header.start_col,
        )
        assert (item.header.end_line, item.header.end_col) <= (
            item.body.start_line,
            item.body.start_col,
        )
        assert (item.body.end_line, item.body.end_col) <= (item.full.end_line, item.full.end_col)


def test_non_ascii_source_keeps_code_point_columns() -> None:
    text, ranges = _ranges(Language.PYTHON, 'def f(): return "héllo"; x = "日本語"\n')
    (item,) = ranges
    assert _text_of(text, item.header) == "def f():"
    assert _text_of(text, item.full).endswith('"héllo"; x = "日本語"')


@pytest.mark.parametrize(
    ("language", "name"), FIXTURES, ids=[f"{lang.value}-{n}" for lang, n in FIXTURES]
)
def test_every_range_round_trips_through_line_index(language: Language, name: str) -> None:
    path = fixture_path(language, name)
    text = path.read_text(encoding="utf-8")
    parsed = parse_fixture(language, path)
    index = LineIndex.build(text)
    for item in function_ranges(parsed, REGISTRY.get(language)):
        for location in (item.header, item.body, item.full, *item.decorators):
            start, end = _byte_span(text, location)
            assert index.location(location.path, start, end) == location
            assert 0 <= start <= end <= len(text.encode("utf-8"))
        assert _text_of(text, item.header).strip()
        assert _text_of(text, item.full).endswith(_text_of(text, item.body))
