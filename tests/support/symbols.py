"""Helpers for the symbol-table tests (E07-03).

Owning epic: not a ``codekavach`` module; a test-only helper, so it carries no "Owning epic"
docstring requirement.
"""

from codekavach.core.models import Language, Location
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.functions import FunctionRange
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import Symbol, SymbolTable, build_symbol_table

EXTENSIONS = {
    Language.PYTHON: "py",
    Language.JAVASCRIPT: "js",
    Language.TYPESCRIPT: "ts",
    Language.JAVA: "java",
    Language.GO: "go",
}


def table_of(language: Language, text: str) -> tuple[ParsedFile, SymbolTable]:
    """Parse ``text`` and build its symbol table with the registered spec."""
    parsed = parse(f"case.{EXTENSIONS[language]}", language, text)
    return parsed, build_symbol_table(parsed, REGISTRY.get(language))


def named(table: SymbolTable, name: str) -> list[Symbol]:
    """Every occurrence of ``name``, in source order."""
    return [symbol for symbol in table.symbols if symbol.name == name]


def scope_ids(table: SymbolTable, name: str) -> list[int]:
    """The binding scope of every occurrence of ``name``, in source order."""
    return [symbol.scope_id for symbol in named(table, name)]


def lines_of(table: SymbolTable, name: str, scope_id: int) -> list[int]:
    """The 1-based lines of every occurrence bound to ``(name, scope_id)``."""
    return [location.start_line for location in table.references(name, scope_id)]


def render(table: SymbolTable) -> str:
    """A stable text form of a table, for golden files."""
    lines = ["scopes:"]
    lines.extend(f"  {s.id} parent={s.parent_id} {s.kind}" for s in table.scopes)
    lines.append("symbols:")
    for symbol in table.symbols:
        role = "def" if symbol.is_definition else "ref"
        lines.append(
            f"  {symbol.location.display()} {symbol.name!r} {symbol.kind} "
            f"scope={symbol.scope_id} {role}"
        )
    lines.append("extents:")
    lines.extend(
        f"  {table.symbols[e.symbol_index].name!r} {e.location.display()}" for e in table.extents
    )
    return "\n".join(lines) + "\n"


def render_references(table: SymbolTable) -> str:
    """Every ``(name, scope_id)`` binding with the lines of all its occurrences, in source order."""
    groups: dict[tuple[str, int], list[int]] = {}
    for symbol in table.symbols:
        groups.setdefault((symbol.name, symbol.scope_id), []).append(symbol.location.start_line)
    lines = ["references:"]
    lines.extend(
        f"  {name!r} scope={scope_id}: {', '.join(str(n) for n in occurrences)}"
        for (name, scope_id), occurrences in sorted(groups.items(), key=lambda item: item[1][0])
    )
    return "\n".join(lines) + "\n"


def _span(location: Location) -> str:
    return f"{location.start_line}:{location.start_col}-{location.end_line}:{location.end_col}"


def render_functions(ranges: tuple[FunctionRange, ...]) -> str:
    """A stable text form of function ranges with exact line:column bounds, for golden files."""
    lines: list[str] = []
    for item in ranges:
        lines.append(f"{item.kind} {item.qualified_name!r} ({item.symbol_name!r})")
        lines.append(f"  header {_span(item.header)}")
        lines.append(f"  body   {_span(item.body)}")
        lines.append(f"  full   {_span(item.full)}")
        lines.extend(f"  decorator {_span(decorator)}" for decorator in item.decorators)
    return "\n".join(lines) + "\n"
