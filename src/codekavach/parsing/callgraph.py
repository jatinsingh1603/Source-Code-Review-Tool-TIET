"""A best-effort, name-based call graph (E07-04).

Owning epic: E07.

**This graph is not sound.** It resolves a call through names only, so it misses calls through
variables, dictionaries of handlers, decorators that wrap, dynamic dispatch and reflection. The
slicer uses it to decide which callees deserve a signature stub (E11-02): an over-approximate
graph costs tokens, an under-approximate one costs context, and every extra function in a slice
is a disclosure decision, so the resolver prefers to miss an edge. The metered ``needs_context``
loop (E11-04) recovers what it misses. Say so in any user-facing text that cites it.

Two passes. :func:`extract_call_facts` works on one file and needs nothing else, so its result can
be memoised per file: it resolves each call through the file's symbol table to a definition in the
same file (``local``), to an imported name (``import``) or to nothing (``unresolved``).
:func:`build_call_graph_from_facts` then joins the files: an imported name is matched against the
qualified names defined in internal modules, giving the cross-file edge.

Node names are ``<module>.<qualified name>`` (Python modules are dotted paths such as
``billing.engine``; a JavaScript or TypeScript module is its extension-less path such as
``src/billing/engine``). A callee that cannot be resolved is written with a ``?`` prefix, which
lets a consumer tell a missing edge (``?obj.method``, or an internal module whose definition was
not found) from an external one (``requests.get``).
"""

import posixpath
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import ClassVar, Final, Literal

from pydantic import PrivateAttr
from tree_sitter import Node

from codekavach.core.models import DataClassification, KavachModel, Language, RepoPath
from codekavach.parsing.functions import Definition, definitions_of
from codekavach.parsing.imports import ImportRef, Origin
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.positions import LineIndex
from codekavach.parsing.symbols import Symbol, SymbolTable

UNRESOLVED_PREFIX: Final = "?"
MAX_TEXT: Final = 200
_CALL_NODES: Final = frozenset({"call", "call_expression", "new_expression"})
_MEMBER_NODES: Final = frozenset({"attribute", "member_expression"})
_NOT_CALLS: Final = frozenset({"require", "__import__", "importlib.import_module"})
_SELF_NAMES: Final = frozenset({"self", "cls", "this"})
_JS_EXTENSIONS: Final = (".d.ts", ".tsx", ".ts", ".jsx", ".js", ".mjs", ".cjs", ".mts", ".cts")
_ROOT_DIRS: Final = frozenset({"src", "lib"})


class CallSite(KavachModel):
    """One distinct call in a file, resolved as far as the file alone allows.

    ``caller`` is the qualified name of the enclosing function or method, ``""`` for module-level
    code. For ``kind == "local"``, ``target`` is the qualified name defined in this file. For
    ``"import"``, ``module``/``imported`` name the import that binds the callee, ``origin`` its
    classification and ``target`` the attribute path after it. For ``"unresolved"``, ``target`` is
    the callee as written.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    caller: str
    kind: Literal["local", "import", "unresolved"]
    target: str
    module: str | None = None
    imported: str | None = None
    origin: Origin | None = None


class CallFacts(KavachModel):
    """What one file contributes to the call graph. Client data: it holds names."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    calls: tuple[CallSite, ...] = ()
    definitions: tuple[str, ...] = ()


class CallGraph(KavachModel):
    """Caller-to-callee edges between qualified names, best effort (see the module docstring)."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    edges: tuple[tuple[str, str], ...] = ()

    _forward: dict[str, tuple[str, ...]] | None = PrivateAttr(default=None)
    _backward: dict[str, tuple[str, ...]] | None = PrivateAttr(default=None)

    def _indexes(self) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
        if self._forward is None or self._backward is None:
            forward: dict[str, list[str]] = {}
            backward: dict[str, list[str]] = {}
            for caller, callee in self.edges:
                forward.setdefault(caller, []).append(callee)
                backward.setdefault(callee, []).append(caller)
            self._forward = {k: tuple(sorted(set(v))) for k, v in forward.items()}
            self._backward = {k: tuple(sorted(set(v))) for k, v in backward.items()}
        return self._forward, self._backward

    def callees(self, symbol: str) -> tuple[str, ...]:
        """The callees of ``symbol``, sorted and without duplicates."""
        return self._indexes()[0].get(symbol, ())

    def callers(self, symbol: str) -> tuple[str, ...]:
        """The callers of ``symbol``, sorted and without duplicates."""
        return self._indexes()[1].get(symbol, ())


# --- module names --------------------------------------------------------------------------


def module_ids(path: str, language: Language) -> tuple[str, ...]:
    """The names a file's module goes by: the importable (``src/``-stripped) form first."""
    if language is Language.PYTHON:
        stem = path.removesuffix(".py").removesuffix(".pyi")
        parts = [p for p in stem.split("/") if p]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        names = [".".join(parts)]
        if len(parts) > 1 and parts[0] in _ROOT_DIRS:
            names.insert(0, ".".join(parts[1:]))
        return tuple(n for n in names if n)
    stem = path
    for suffix in _JS_EXTENSIONS:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    stem = stem.removesuffix("/index")
    return (stem,) if stem else ()


def _absolute_python(module: str, file_ids: tuple[str, ...], *, is_package: bool) -> str | None:
    """Resolve ``module`` as written (possibly relative) against the importing file."""
    if not module.startswith("."):
        return module
    if not file_ids:
        return None
    level = len(module) - len(module.lstrip("."))
    parts = file_ids[0].split(".")
    package = parts if is_package else parts[:-1]
    if level - 1 > len(package):
        return None
    base = package[: len(package) - (level - 1)]
    rest = module[level:]
    return ".".join([*base, *([rest] if rest else [])]) or None


def _absolute_javascript(module: str, file_path: str) -> str | None:
    if not module.startswith("."):
        return module
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(file_path), module))
    if joined.startswith(".."):
        return None
    stem = joined
    for suffix in _JS_EXTENSIONS:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem.removesuffix("/index")


# --- pass one: one file --------------------------------------------------------------------


def _text(node: Node | None) -> str:
    return "" if node is None else "".join((node.text or b"").decode("utf-8", "replace").split())


def _callee_head(function: Node) -> tuple[Node | None, str]:
    """The base identifier of a call target and the attribute path after it."""
    attributes: list[str] = []
    current: Node | None = function
    while current is not None and current.type in _MEMBER_NODES:
        name = current.child_by_field_name("attribute") or current.child_by_field_name("property")
        attributes.append(_text(name))
        current = current.child_by_field_name("object")
    if current is not None and current.type in ("identifier", "this"):
        return current, ".".join(reversed(attributes))
    return None, ""


def _call_nodes(root: Node) -> list[tuple[int, Node]]:
    found: list[tuple[int, Node]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in _CALL_NODES:
            function = node.child_by_field_name("function") or node.child_by_field_name(
                "constructor"
            )
            if function is not None and function.type != "import":
                found.append((node.start_byte, function))
        stack.extend(node.named_children)
    found.sort(key=lambda item: item[0])
    return found


class _Frame:
    """The enclosing function and class while sweeping calls in source order."""

    __slots__ = ("stack",)

    def __init__(self) -> None:
        self.stack: list[Definition] = []

    def advance(self, position: int, pending: list[Definition]) -> None:
        while self.stack and self.stack[-1].full_end <= position:
            self.stack.pop()
        while pending and pending[0].full_start <= position:
            definition = pending.pop(0)
            if definition.full_end > position:
                self.stack.append(definition)

    def caller(self) -> str:
        return next((d.qualified for d in reversed(self.stack) if d.kind != "class"), "")

    def enclosing_class(self) -> str:
        return next((d.qualified for d in reversed(self.stack) if d.kind == "class"), "")


@dataclass(frozen=True, slots=True)
class _FileContext:
    """What resolving one file's calls needs, built once per file."""

    defined: frozenset[str]
    by_position: Mapping[tuple[int, int], Symbol]
    local_by_binding: Mapping[tuple[str, int], str]
    imports: Mapping[tuple[str | None, int], ImportRef]
    line_index: LineIndex


def _context(
    parsed: ParsedFile, table: SymbolTable, definitions: Sequence[Definition]
) -> _FileContext:
    assert parsed.line_index is not None  # noqa: S101 - checked by the caller
    line_index = parsed.line_index
    by_position = {(s.location.start_line, s.location.start_col or 0): s for s in table.symbols}
    local_by_binding: dict[tuple[str, int], str] = {}
    for definition in definitions:
        symbol = by_position.get(line_index.position(definition.name_start))
        if symbol is not None and symbol.scope_id >= 0:
            local_by_binding.setdefault((symbol.name, symbol.scope_id), definition.qualified)
    return _FileContext(
        defined=frozenset(d.qualified for d in definitions),
        by_position=by_position,
        local_by_binding=local_by_binding,
        imports={(ref.bound, ref.scope_id): ref for ref in table.imports if ref.bound},
        line_index=line_index,
    )


def extract_call_facts(parsed: ParsedFile, table: SymbolTable) -> CallFacts:
    """Resolve every call of ``parsed`` as far as the file and its symbol table allow."""
    if parsed.tree is None or parsed.line_index is None:
        return CallFacts()
    definitions = definitions_of(parsed)
    context = _context(parsed, table, definitions)
    frame = _Frame()
    pending = list(definitions)
    seen: dict[CallSite, None] = {}
    for position, function in _call_nodes(parsed.tree.root_node):
        text = _text(function)
        if text in _NOT_CALLS:
            continue
        frame.advance(position, pending)
        head, rest = _callee_head(function)
        seen.setdefault(_resolve(head, rest, text, frame, context), None)
    return CallFacts(calls=tuple(seen), definitions=tuple(d.qualified for d in definitions))


def _unresolved(caller: str, text: str) -> CallSite:
    return CallSite(caller=caller, kind="unresolved", target=text[:MAX_TEXT])


def _local_or_unresolved(caller: str, target: str, text: str, context: _FileContext) -> CallSite:
    if target in context.defined:
        return CallSite(caller=caller, kind="local", target=target)
    return _unresolved(caller, text)


def _resolve_bound(
    caller: str, name: str, scope_id: int, context: _FileContext, *, rest: str, text: str
) -> CallSite:
    """A call whose head name has a binding in this file: a definition, an import, or neither."""
    local = context.local_by_binding.get((name, scope_id))
    if local is not None:
        return _local_or_unresolved(caller, f"{local}.{rest}" if rest else local, text, context)
    ref = context.imports.get((name, scope_id))
    if ref is None:
        return _unresolved(caller, text)
    return CallSite(
        caller=caller,
        kind="import",
        target=rest,
        module=ref.module,
        imported=ref.imported or "",
        origin=ref.origin,
    )


def _resolve(
    head: Node | None, rest: str, text: str, frame: _Frame, context: _FileContext
) -> CallSite:
    caller = frame.caller()
    if head is None:
        return _unresolved(caller, text)
    name = _text(head)
    if name in _SELF_NAMES:
        owner = frame.enclosing_class()
        target = f"{owner}.{rest}" if owner and rest else ""
        return _local_or_unresolved(caller, target, text, context)
    symbol = context.by_position.get(context.line_index.position(head.start_byte))
    if symbol is None or symbol.scope_id < 0:
        return _unresolved(caller, text)
    return _resolve_bound(caller, name, symbol.scope_id, context, rest=rest, text=text)


# --- pass two: all files -------------------------------------------------------------------


class _FileInfo:
    __slots__ = ("facts", "ids", "language", "path")

    def __init__(self, path: str, language: Language, facts: CallFacts) -> None:
        self.path = path
        self.language = language
        self.facts = facts
        self.ids = module_ids(path, language)


def _node(module: str, qualified: str) -> str:
    return f"{module}.{qualified}" if qualified else module


def _import_target(site: CallSite, info: _FileInfo) -> str | None:
    """The fully qualified name an ``import`` call site points at, or ``None``."""
    module = site.module or ""
    if info.language is Language.PYTHON:
        is_package = info.path.endswith("__init__.py")
        absolute = _absolute_python(module, info.ids, is_package=is_package)
    else:
        absolute = _absolute_javascript(module, info.path)
    if absolute is None:
        return None
    imported = site.imported or ""
    if imported == "default":
        return None
    parts = [absolute]
    if imported and imported != "*":
        parts.append(imported)
    if site.target:
        parts.append(site.target)
    return ".".join(parts)


def build_call_graph_from_facts(files: Iterable[tuple[str, Language, CallFacts]]) -> CallGraph:
    """Join per-file facts into one graph (the cross-file pass)."""
    infos = [_FileInfo(path, language, facts) for path, language, facts in files]
    defined: set[str] = set()
    for info in infos:
        for module in info.ids:
            defined.update(_node(module, q) for q in info.facts.definitions)
    edges: dict[tuple[str, str], None] = {}
    for info in infos:
        if not info.ids:
            continue
        primary = info.ids[0]
        for site in info.facts.calls:
            caller = _node(primary, site.caller)
            if site.kind == "local":
                callee = _node(primary, site.target)
            elif site.kind == "import":
                full = _import_target(site, info)
                if full is None:
                    callee = f"{UNRESOLVED_PREFIX}{site.module}"
                elif full in defined:
                    callee = full
                elif site.origin == "internal":
                    callee = f"{UNRESOLVED_PREFIX}{full}"
                else:
                    callee = full
            else:
                callee = f"{UNRESOLVED_PREFIX}{site.target}"
            edges.setdefault((caller, callee), None)
    return CallGraph(edges=tuple(sorted(edges)))


def build_call_graph(
    parsed_files: Sequence[ParsedFile], symbol_tables: Mapping[RepoPath, SymbolTable]
) -> CallGraph:
    """Build the call graph of ``parsed_files`` (best effort; see the module docstring)."""
    return build_call_graph_from_facts(
        (parsed.path, parsed.language, extract_call_facts(parsed, symbol_tables[parsed.path]))
        for parsed in parsed_files
        if parsed.path in symbol_tables
    )


__all__ = [
    "CallFacts",
    "CallGraph",
    "CallSite",
    "build_call_graph",
    "build_call_graph_from_facts",
    "extract_call_facts",
    "module_ids",
]
