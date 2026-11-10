"""Signature-only stubs for the callees, class fields and imports a slice uses but does not hold.

Owning epic: E11. MVP; the taint engine later supplies stronger summaries through
``EffectSummary.source``.

``make_stubs(callees, parsed)`` turns the callee occurrences of a slice into ``Stub`` objects: the
normalised signature of the definition, one comment line with the reason it is a stub, and one
comment line with a locally derived effect summary. ``build_stubs`` is the full builder the slicer
calls: it also collects the callees from the segments, adds the class fields and the imports the
segments reference, deduplicates, orders and applies the token budget.

Rules that protect against a stub becoming a leak in its own right (stubs are built from source
that has not been through redaction, so the builder never copies anything it cannot name):

* the body, the docstring and every comment of the original source are never copied: the
  signature is rebuilt from the header only;
* every default value is replaced by ``...``, including a default nested in a destructured
  parameter, and so is every string literal inside the header (an annotation can hold one);
* the effect summary is syntactic and says so (``derived: syntactic``); it reports what the text
  of the function does and never claims that anything is sanitised or safe;
* a callee on the public allowlist gets no stub (it is recognisable by name; the count is kept in
  ``StubStats.omitted_public``), and a callee defined in a file the policy never sends, or in a
  vendored, generated or minified file, gets no stub either (``omitted_excluded``): the documented
  rule is "no stub at all", because even a signature would be code from a file that must not leave.

The stub text is raw code: E09 pseudonymises its names with the same classifier as the segments, so
an internal callee name does not survive into the payload.

**The data path.** When the budget forces a choice, the callees on the data path of the candidate
come first. In M1 that is approximated syntactically: a callee called on the candidate's own line,
or whose result is assigned to a variable that is used on the candidate's line. It is not an
analysis; the taint engine replaces it.
"""

import re
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Final, Literal

from tree_sitter import Node

from codekavach.core.log import get_logger
from codekavach.core.models import Language, Location, RawCode, SliceSegment, Stub, StubReason
from codekavach.parsing import parse
from codekavach.parsing.functions import FunctionRange
from codekavach.parsing.imports import DefaultImportResolver, ImportRef
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.scopes import UNRESOLVED
from codekavach.parsing.symbols import Symbol, SymbolTable
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import IdentifierClass, IdentifierClassifier
from codekavach.privacy.slicing.assemble import assemble
from codekavach.privacy.slicing.budget import estimate
from codekavach.privacy.slicing.elide import comment_prefix
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.shape import (
    CLASS_TYPES,
    FUNCTION_TYPES,
    SUPPORTED,
    first,
    function_node,
    last,
)

_LOG = get_logger("codekavach.privacy.slicing")

SummarySource = Literal["syntactic", "taint"]
NEUTRAL_DEFAULT: Final = "..."
# A JavaScript or TypeScript default must still be an expression, and ``...`` alone is not one.
SCRIPT_NEUTRAL_DEFAULT: Final = "undefined"
MAX_SIGNATURE_CHARS: Final = 600
PLACEHOLDER_BASE: Final = "Base"

REASON_LABELS: Final[Mapping[StubReason, str]] = {
    StubReason.OUT_OF_SLICE_CALLEE: "out_of_slice",
    StubReason.CROSS_FILE_CALLEE: "cross_file",
    StubReason.EXTERNAL_LIBRARY: "third_party",
    StubReason.UNRESOLVED_CALLEE: "unresolved",
    StubReason.TOKEN_BUDGET: "budget",
    StubReason.CLASS_CONTEXT: "class context",
    StubReason.IMPORT_CONTEXT: "import",
}

# Names that are published interfaces, never client names (invariant I6). A starter set: the
# taint engine owns the real sanitiser and sink models, and a name here is only ever reported
# ("calls allowlisted sanitiser: escape"), never taken as proof that input is safe.
_JS_SANITISERS: Final = frozenset(
    {"escape", "encodeURIComponent", "encodeURI", "sanitize", "sanitizeHtml", "escapeHtml"}
)
SANITISER_NAMES: Final[Mapping[Language, frozenset[str]]] = {
    Language.PYTHON: frozenset({"escape", "quote", "quote_plus", "escape_string", "sanitize"}),
    Language.JAVASCRIPT: _JS_SANITISERS,
    Language.TYPESCRIPT: _JS_SANITISERS,
}
_SINK_HEADS: Final[Mapping[Language, Mapping[str, str]]] = {
    Language.PYTHON: {
        "subprocess": "subprocess",
        "pickle": "deserialise",
        "marshal": "deserialise",
    },
    Language.JAVASCRIPT: {"child_process": "subprocess", "cp": "subprocess", "fs": "file"},
}
_SINK_CALLS: Final[Mapping[Language, Mapping[str, str]]] = {
    Language.PYTHON: {
        "os.system": "subprocess",
        "os.popen": "subprocess",
        "yaml.load": "deserialise",
        "eval": "eval",
        "exec": "eval",
        "open": "file",
        "execute": "sql",
        "executemany": "sql",
        "executescript": "sql",
    },
    Language.JAVASCRIPT: {
        "eval": "eval",
        "Function": "eval",
        "query": "sql",
        "execute": "sql",
    },
}
_STATIC_DECORATORS: Final = frozenset(
    {"@staticmethod", "@classmethod", "@abstractmethod", "@abc.abstractmethod"}
)
_RETURNS: Final = frozenset({"return_statement"})
_YIELDS: Final = frozenset({"yield", "yield_expression"})
_RAISES: Final = frozenset({"raise_statement", "throw_statement"})
_CALLS: Final = frozenset({"call", "call_expression", "new_expression"})
_ATTRIBUTES: Final = frozenset({"attribute", "member_expression"})
_IDENTIFIERS: Final = frozenset({"identifier", "shorthand_property_identifier"})
_ASSIGNMENTS: Final = frozenset(
    {
        "assignment",
        "augmented_assignment",
        "variable_declarator",
        "assignment_expression",
        "augmented_assignment_expression",
    }
)
_DEFAULT_FIELDS: Final = {
    "default_parameter": "value",
    "typed_default_parameter": "value",
    "required_parameter": "value",
    "optional_parameter": "value",
    "assignment_pattern": "right",
    "object_assignment_pattern": "right",
}
_STRINGS: Final = frozenset({"string", "template_string", "concatenated_string"})
_SELF_NAMES: Final = frozenset({"self", "cls", "this"})
_NOT_PARAMETERS: Final = frozenset(
    {"keyword_separator", "positional_separator", "comment", "type_annotation"}
)
_CLAUSE: Final = re.compile(
    r"^(?:effects unknown|returns value|returns nothing"
    r"|param_\d+ flows to return|no parameter flows to return"
    r"|no sanitiser|calls allowlisted sanitiser: [A-Za-z_$][\w$]*"
    r"|calls sink family: [a-z]+|raises|derived: (?:syntactic|taint))$"
)


class _Priority(IntEnum):
    """The documented order in which stubs are kept when the budget runs out."""

    DATA_PATH_CALLEE = 0
    OTHER_CALLEE = 1
    CLASS_FIELDS = 2
    IMPORT = 3


@dataclass(frozen=True, slots=True)
class EffectSummary:
    """What the text of a function does, in a fixed grammar (see ``render``).

    ``source`` is ``"syntactic"`` for the analysis in this module and ``"taint"`` when the taint
    engine supplies the summary. ``known`` is false when there is no body to read (a callee in a
    third-party package, or one that cannot be resolved).
    """

    returns_value: bool = False
    flows_to_return: tuple[int, ...] = ()
    sanitiser: str | None = None
    sink_families: tuple[str, ...] = ()
    raises: bool = False
    source: SummarySource = "syntactic"
    known: bool = True

    def clauses(self) -> tuple[str, ...]:
        """The clauses of the summary, in grammar order."""
        out: list[str] = []
        if not self.known:
            out.append("effects unknown")
        else:
            out.append("returns value" if self.returns_value else "returns nothing")
            if self.returns_value:
                out.extend(f"param_{index} flows to return" for index in self.flows_to_return)
                if not self.flows_to_return:
                    out.append("no parameter flows to return")
            out.append(
                f"calls allowlisted sanitiser: {self.sanitiser}"
                if self.sanitiser
                else "no sanitiser"
            )
            out.extend(f"calls sink family: {family}" for family in self.sink_families)
            if self.raises:
                out.append("raises")
        out.append(f"derived: {self.source}")
        return tuple(out)

    def render(self) -> str:
        """One line: the clauses joined by ``"; "``."""
        return "; ".join(self.clauses())


def is_valid_summary(line: str) -> bool:
    """Whether ``line`` uses only the clauses of the fixed grammar and ends with ``derived``."""
    clauses = line.split("; ")
    return all(_CLAUSE.match(clause) for clause in clauses) and clauses[-1].startswith("derived:")


@dataclass(frozen=True, slots=True)
class StubStats:
    """Counts of what the builder left out, and why. Counts only: no name ever appears here."""

    omitted_public: int = 0
    omitted_excluded: int = 0
    stubs_omitted: int = 0
    omitted_reasons: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class StubSet:
    """The stubs of one slice in priority order, and the statistics of building them."""

    stubs: tuple[Stub, ...] = ()
    stats: StubStats = field(default_factory=StubStats)


# --- reading the tree -------------------------------------------------------------------------


def _source_of(file: ParsedFile) -> bytes:
    return (file.tree.root_node.text or b"") if file.tree is not None else b""


def _redactions(nodes: Iterable[Node], marker: str = NEUTRAL_DEFAULT) -> list[tuple[int, int, str]]:
    """Byte ranges of a header to replace: defaults and strings by ``marker``, comments by none."""
    found: list[tuple[int, int, str]] = []
    stack = deque(nodes)
    while stack:
        node = stack.pop()
        if node.type == "comment":
            found.append((node.start_byte, node.end_byte, ""))
            continue
        if node.is_named and node.type in _STRINGS:  # not the keyword ``string`` of a type
            found.append((node.start_byte, node.end_byte, marker))
            continue
        default = node.child_by_field_name(_DEFAULT_FIELDS.get(node.type, ""))
        if default is not None:
            found.append((default.start_byte, default.end_byte, marker))
            stack.extend(child for child in node.children if child.id != default.id)
            continue
        stack.extend(node.children)
    return sorted(found)


def _render(source: bytes, start: int, end: int, redactions: list[tuple[int, int, str]]) -> str:
    """The text of ``source[start:end]`` with the redactions applied and white space collapsed."""
    pieces: list[bytes] = []
    cursor = start
    for begin, stop, replacement in redactions:
        if begin < cursor or begin >= end:
            continue
        pieces.append(source[cursor:begin])
        pieces.append(replacement.encode())
        cursor = stop
    pieces.append(source[cursor:end])
    return " ".join(b"".join(pieces).decode("utf-8", errors="replace").split())


def _text_of(node: Node | None, source: bytes, marker: str = NEUTRAL_DEFAULT) -> str:
    if node is None:
        return ""
    return _render(source, node.start_byte, node.end_byte, _redactions([node], marker))


def _parameter_nodes(node: Node) -> list[Node]:
    holder = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
    if holder is None:
        return []
    if holder.type == "identifier":  # an arrow function with one bare parameter
        return [holder]
    return [child for child in holder.named_children if child.type not in _NOT_PARAMETERS]


def _binding_names(parameter: Node) -> list[str]:
    """The names a parameter binds: one for ``a``, several for a destructured parameter."""
    names: list[str] = []
    stack = [parameter]
    while stack:
        node = stack.pop()
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            names.append((node.text or b"").decode("utf-8", errors="replace"))
            continue
        skip = {
            child.id
            for name in (_DEFAULT_FIELDS.get(node.type, ""), "type")
            if (child := node.child_by_field_name(name)) is not None
        }
        stack.extend(
            child
            for child in reversed(node.children)
            if child.id not in skip and child.type not in {"type_annotation", "comment"}
        )
    return names


def parameter_names(node: Node, *, drop_receiver: bool) -> list[list[str]]:
    """The binding names of each parameter in order, without ``self`` or ``cls`` when asked."""
    groups = [_binding_names(parameter) for parameter in _parameter_nodes(node)]
    if drop_receiver and groups and groups[0] and groups[0][0] in _SELF_NAMES:
        groups = groups[1:]
    return groups


# --- the signature ----------------------------------------------------------------------------


def _python_signature(node: Node, source: bytes) -> str:
    body = node.child_by_field_name("body")
    end = body.start_byte if body is not None else node.end_byte
    parts = [child for child in node.children if body is None or child.id != body.id]
    header = _render(source, node.start_byte, end, _redactions(parts)).rstrip()
    if not header.endswith(":"):
        header += ":"
    lines: list[str] = []
    parent = node.parent
    if parent is not None and parent.type == "decorated_definition":
        for decorator in parent.children:
            if decorator.type == "decorator":
                text = _text_of(decorator, source)
                if text in _STATIC_DECORATORS:
                    lines.append(text)
    lines.append(f"{header} ...")
    return "\n".join(lines)


def _javascript_signature(node: Node, name: str, source: bytes) -> str:
    kinds = {child.type for child in node.children}
    prefix = "async " if "async" in kinds else ""
    star = "*" if node.type.startswith("generator") or "*" in kinds else ""
    marker = SCRIPT_NEUTRAL_DEFAULT
    generics = _text_of(node.child_by_field_name("type_parameters"), source, marker)
    holder = node.child_by_field_name("parameters")
    if holder is not None:
        params = _text_of(holder, source, marker)
    else:
        single = node.child_by_field_name("parameter")
        params = f"({_text_of(single, source, marker)})" if single is not None else "()"
    returns = _text_of(node.child_by_field_name("return_type"), source, marker)
    return f"{prefix}function{star} {name}{generics}{params}{returns} {{}}"


def signature_of(file: ParsedFile, node: Node, name: str) -> str:
    """The normalised signature of a function node: header only, defaults and literals replaced."""
    source = _source_of(file)
    text = (
        _python_signature(node, source)
        if file.language is Language.PYTHON
        else _javascript_signature(node, name, source)
    )
    return text[:MAX_SIGNATURE_CHARS]


def name_only_signature(name: str, language: Language) -> str:
    """The signature of a callee whose definition is unavailable: it accepts anything."""
    if language is Language.PYTHON:
        return f"def {name}(*args, **kwargs): ..."
    return f"function {name}(...args) {{}}"


# --- the effect summary -----------------------------------------------------------------------


def _identifiers_in(node: Node) -> set[str]:
    found: set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in _IDENTIFIERS:
            found.add((current.text or b"").decode("utf-8", errors="replace"))
        stack.extend(current.children)
    return found


def _sink_family(callee: str, language: Language) -> str | None:
    calls = _SINK_CALLS.get(language) or _SINK_CALLS[Language.JAVASCRIPT]
    heads = _SINK_HEADS.get(language) or _SINK_HEADS[Language.JAVASCRIPT]
    if callee in calls:
        return calls[callee]
    head, _, rest = callee.partition(".")
    if rest and head in heads:
        return heads[head]
    last_name = callee.rsplit(".", 1)[-1]
    if "." in callee and last_name in calls and last_name in {"execute", "executemany", "query"}:
        return calls[last_name]
    return None


@dataclass(slots=True)
class _Facts:
    returned: list[Node] = field(default_factory=list)
    yields: bool = False
    raises: bool = False
    callees: list[str] = field(default_factory=list)
    dependencies: dict[str, set[str]] = field(default_factory=dict)


_TARGET_WRAPPERS: Final = frozenset(
    {"await_expression", "parenthesized_expression", "non_null_expression", "as_expression"}
)


def _call_target(call: Node) -> Node | None:
    """What a call calls, looking through ``await``, parentheses and ``!``.

    The TypeScript grammar reads ``await load<T>(x)`` as a call of the ``await`` expression, so a
    lookup that does not unwrap it finds no callee.
    """
    target = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    while target is not None and target.type in _TARGET_WRAPPERS and target.named_children:
        target = target.named_children[0]
    return target


def _scan_body(root: Node) -> _Facts:
    """Walk a function body once, not entering nested functions or classes."""
    facts = _Facts()
    stack = [root]
    while stack:
        node = stack.pop()
        kind = node.type
        if node is not root and (kind in FUNCTION_TYPES or kind in CLASS_TYPES):
            continue
        if kind in _RETURNS:
            value = next((c for c in node.named_children if c.type != "comment"), None)
            if value is not None:
                facts.returned.append(value)
        elif kind in _YIELDS:
            facts.yields = True
            facts.returned.extend(c for c in node.named_children if c.type != "comment")
        elif kind in _RAISES:
            facts.raises = True
        elif kind in _CALLS:
            target = _call_target(node)
            if target is not None:
                facts.callees.append((target.text or b"").decode("utf-8", errors="replace"))
        elif kind in _ASSIGNMENTS:
            _note_assignment(node, facts)
        stack.extend(node.children)
    return facts


def _note_assignment(node: Node, facts: _Facts) -> None:
    left = node.child_by_field_name("left") or node.child_by_field_name("name")
    right = node.child_by_field_name("right") or node.child_by_field_name("value")
    if left is None or right is None or left.type != "identifier":
        return
    name = (left.text or b"").decode("utf-8", errors="replace")
    facts.dependencies.setdefault(name, set()).update(_identifiers_in(right))


def _flows(parameters: list[list[str]], facts: _Facts) -> tuple[int, ...]:
    """Which parameters reach a returned expression, directly or through a local assignment."""
    origin: dict[str, set[int]] = {}
    for index, names in enumerate(parameters):
        for name in names:
            origin.setdefault(name, set()).add(index)
    for _ in range(len(facts.dependencies) + 1):
        changed = False
        for name, needs in facts.dependencies.items():
            reached = set().union(*(origin.get(need, set()) for need in needs))
            if reached - origin.get(name, set()):
                origin.setdefault(name, set()).update(reached)
                changed = True
        if not changed:
            break
    returned = (
        set().union(*(_identifiers_in(node) for node in facts.returned))
        if facts.returned
        else set()
    )
    reaching = set().union(*(origin.get(name, set()) for name in returned))
    return tuple(sorted(reaching))


def effect_summary(node: Node, language: Language, *, drop_receiver: bool = False) -> EffectSummary:
    """The syntactic effect summary of a function node (see the module docstring)."""
    body = node.child_by_field_name("body")
    if body is None:
        return EffectSummary(known=False)
    facts = _scan_body(body)
    returns_value = bool(facts.returned) or facts.yields
    if body.type != "statement_block" and language is not Language.PYTHON:
        facts.returned.append(body)  # an arrow function with an expression body returns it
        returns_value = True
    parameters = parameter_names(node, drop_receiver=drop_receiver)
    callees = sorted(set(facts.callees))
    names = SANITISER_NAMES.get(language, frozenset())
    sanitiser = next((c.rsplit(".", 1)[-1] for c in callees if c.rsplit(".", 1)[-1] in names), None)
    families = sorted({f for c in callees if (f := _sink_family(c, language)) is not None})
    return EffectSummary(
        returns_value=returns_value,
        flows_to_return=_flows(parameters, facts) if returns_value else (),
        sanitiser=sanitiser,
        sink_families=tuple(families),
        raises=facts.raises,
    )


# --- building one stub ------------------------------------------------------------------------


def _block(language: Language, label: str, signature: str, summary: EffectSummary | None) -> str:
    prefix = comment_prefix(language)
    lines = [f"{prefix} {label}", signature]
    if summary is not None:
        lines.append(f"{prefix} {summary.render()}")
    return "\n".join(lines)


def _stub(
    *,
    symbol: str,
    block: str,
    reason: StubReason,
    path: str | None,
    line: int | None,
) -> Stub:
    return Stub(symbol=symbol, signature=RawCode(block), reason=reason, path=path, line=line)


def function_stub(
    parsed: ParseIndex, path: str, function: FunctionRange, reason: StubReason
) -> Stub | None:
    """The stub of the function ``function`` defined in ``path``; ``None`` if it has no node."""
    file = parsed.parsed_of(path)
    node = function_node(file, function)
    if node is None:
        return None
    signature = signature_of(file, node, function.symbol_name)
    summary = effect_summary(node, file.language, drop_receiver=function.kind == "method")
    label = REASON_LABELS[reason]
    if file.language is not Language.PYTHON and any(c.type == "static" for c in node.children):
        label += " (static)"
    return _stub(
        symbol=function.qualified_name,
        block=_block(file.language, label, signature, summary),
        reason=reason,
        path=path,
        line=function.header.start_line,
    )


# --- callees ----------------------------------------------------------------------------------


def _callee_name_node(call: Node) -> Node | None:
    target = _call_target(call)
    if target is None:
        return None
    if target.type in _ATTRIBUTES:
        return target.child_by_field_name("attribute") or target.child_by_field_name("property")
    return target if target.type == "identifier" else None


def _is_resolvable_receiver(call: Node, table: SymbolTable) -> bool:
    """Whether a call can name a definition: a plain name, ``self.m()`` or ``imported.m()``.

    A call on an arbitrary object (``ledger.is_open()``) cannot be resolved without types, and a
    stub for it would say nothing the call site does not already say, so it is not collected.
    """
    target = _call_target(call)
    if target is None or target.type not in _ATTRIBUTES:
        return True
    receiver = target.child_by_field_name("object")
    if receiver is None or receiver.type not in {"identifier", "this"}:
        return False
    name = (receiver.text or b"").decode("utf-8", errors="replace")
    return name in _SELF_NAMES or any(ref.bound == name for ref in table.imports)


def _calls_in(root: Node, start: int, end: int) -> list[Node]:
    """The call nodes of the tree that start on lines ``start`` to ``end``."""
    found: list[Node] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if last(node) < start or first(node) > end:
            continue
        if node.type in _CALLS and start <= first(node) <= end:
            found.append(node)
        stack.extend(node.children)
    return sorted(found, key=lambda n: (n.start_byte, n.end_byte))


def _all_calls(root: Node) -> list[Node]:
    return _calls_in(root, 1, last(root))


def callees_of(segments: Sequence[SliceSegment], parsed: ParseIndex) -> tuple[Symbol, ...]:
    """The callee occurrences in the text of ``segments``, as symbols of the file's table.

    Each call is found in the syntax tree, restricted to the lines of its segment, and matched to
    the symbol table occurrence with the same name on the same line; a call with no such
    occurrence is left out (it cannot be classified, so it is not stubbed), and so is a call on an
    arbitrary object (see ``_is_resolvable_receiver``).
    """
    found: list[Symbol] = []
    per_file: dict[str, tuple[dict[tuple[str, int], Symbol], list[Node]] | None] = {}
    for segment in sorted(segments, key=lambda s: (s.path, s.region.start_line)):
        if segment.path not in per_file:
            per_file[segment.path] = _calls_of_file(parsed, segment.path)
        loaded = per_file[segment.path]
        if loaded is None:
            continue
        by_line, calls = loaded
        table = parsed.symbols_of(segment.path)
        for call in calls:
            if not segment.region.start_line <= first(call) <= segment.region.end_line:
                continue
            name_node = _callee_name_node(call)
            if name_node is None or not _is_resolvable_receiver(call, table):
                continue
            name = (name_node.text or b"").decode("utf-8", errors="replace")
            match = by_line.get((name, first(name_node)))
            if match is None:
                match = _synthetic_callee(name, segment.path, name_node)
            if not match.is_definition:
                found.append(match)
    return tuple(found)


def _calls_of_file(
    parsed: ParseIndex, path: str
) -> tuple[dict[tuple[str, int], Symbol], list[Node]] | None:
    """The first symbol of each ``(name, line)`` and every call of one file, walked once."""
    try:
        file = parsed.parsed_of(path)
    except KeyError:
        return None
    if file.tree is None or file.language not in SUPPORTED:
        return None
    by_line: dict[tuple[str, int], Symbol] = {}
    for symbol in parsed.symbols_of(path).symbols:
        by_line.setdefault((symbol.name, symbol.location.start_line), symbol)
    return by_line, parsed.calls_of(path, _all_calls)


def _synthetic_callee(name: str, path: str, name_node: Node) -> Symbol:
    """A callee occurrence the symbol table did not record (a method name in TypeScript)."""
    where = first(name_node)
    return Symbol(
        name=name,
        kind="function",
        scope_id=UNRESOLVED,
        location=Location(path=path, start_line=where, end_line=where),
        is_definition=False,
    )


class _Classifiers:
    """One identifier classifier per file, built on first use."""

    def __init__(self, parsed: ParseIndex, allowlist: PublicAllowlist | None) -> None:
        self._parsed = parsed
        self._allowlist = allowlist
        self._by_path: dict[str, IdentifierClassifier | None] = {}

    def is_public(self, symbol: Symbol) -> bool:
        path = symbol.location.path
        if path not in self._by_path:
            self._by_path[path] = self._make(path)
        classifier = self._by_path[path]
        if classifier is None:
            return False
        if classifier.classify(symbol) is IdentifierClass.PUBLIC:
            return True
        return self._public_by_name(symbol.name, path)

    def _public_by_name(self, name: str, path: str) -> bool:
        """The rules that depend on the name alone, for an occurrence the table does not hold."""
        try:
            allowlist = self._allowlist or PublicAllowlist.bundled(
                self._parsed.parsed_of(path).language
            )
        except (KeyError, LookupError):
            return False
        return (
            allowlist.is_keyword_or_builtin(name)
            or allowlist.is_magic(name)
            or allowlist.is_framework_contract(name)
            or allowlist.is_extra(name)
        )

    def _make(self, path: str) -> IdentifierClassifier | None:
        try:
            file = self._parsed.parsed_of(path)
            allowlist = self._allowlist
            if allowlist is None or allowlist.language is not file.language:
                allowlist = PublicAllowlist.bundled(file.language)
        except (KeyError, LookupError):
            return None
        classifier = IdentifierClassifier(
            self._parsed.symbols_of(path), DefaultImportResolver(file.language), allowlist
        )
        classifier.attach(file)
        return classifier


def _inside(segments: Sequence[SliceSegment], path: str, function: FunctionRange) -> bool:
    return any(
        s.path == path
        and s.region.start_line <= function.full.start_line
        and function.full.end_line <= s.region.end_line
        for s in segments
    )


@dataclass(slots=True)
class _Tally:
    public: int = 0
    excluded: int = 0
    unmatched: int = 0


def _external_origin(table: SymbolTable, symbol: Symbol) -> bool:
    origin = table.import_origin(symbol.name, symbol.scope_id)
    return origin in {"stdlib", "third_party"}


def _callee_stub(
    symbol: Symbol,
    parsed: ParseIndex,
    segments: Sequence[SliceSegment],
    tally: _Tally,
) -> Stub | None:
    path = symbol.location.path
    found = parsed.definition_of(symbol.name, path)
    if found is not None:
        where, function = found
        excluded, _ = parsed.is_excluded(where)
        if excluded:
            tally.excluded += 1
            return None
        if _inside(segments, where, function):
            return None
        reason = StubReason.OUT_OF_SLICE_CALLEE if where == path else StubReason.CROSS_FILE_CALLEE
        return function_stub(parsed, where, function, reason)
    language = parsed.parsed_of(path).language
    reason = (
        StubReason.EXTERNAL_LIBRARY
        if _external_origin(parsed.symbols_of(path), symbol)
        else StubReason.UNRESOLVED_CALLEE
    )
    block = _block(
        language,
        REASON_LABELS[reason],
        name_only_signature(symbol.name, language),
        EffectSummary(known=False),
    )
    return _stub(symbol=symbol.name, block=block, reason=reason, path=None, line=None)


def make_stubs(
    callees: Sequence[Symbol],
    parsed: ParseIndex,
    *,
    segments: Sequence[SliceSegment] = (),
    allowlist: PublicAllowlist | None = None,
) -> tuple[Stub, ...]:
    """Stubs for ``callees``: one per distinct definition, ordered by qualified name.

    A callee on the public allowlist, one defined in a file that must not be sent, and one defined
    inside ``segments`` get none. See ``build_stubs`` for the statistics and the budget.
    """
    return _function_stubs(callees, parsed, segments, allowlist, _Tally())


def _function_stubs(
    callees: Sequence[Symbol],
    parsed: ParseIndex,
    segments: Sequence[SliceSegment],
    allowlist: PublicAllowlist | None,
    tally: _Tally,
) -> tuple[Stub, ...]:
    classifiers = _Classifiers(parsed, allowlist)
    distinct: dict[tuple[str | None, str, StubReason], Stub] = {}
    for symbol in sorted(callees, key=lambda s: (s.name, s.location.path, s.location.start_line)):
        if classifiers.is_public(symbol):
            tally.public += 1
            continue
        stub = _callee_stub(symbol, parsed, segments, tally)
        if stub is not None:
            distinct.setdefault((stub.path, stub.symbol, stub.reason), stub)
    return tuple(sorted(distinct.values(), key=lambda s: (s.symbol, s.path or "", s.line or 0)))


# --- the data path (an approximation, see the module docstring) --------------------------------


def _data_path_names(parsed: ParseIndex, path: str, line: int) -> set[str]:
    """Callee names on the data path of the candidate line (see the module docstring)."""
    try:
        file = parsed.parsed_of(path)
    except KeyError:
        return set()
    if file.tree is None:
        return set()
    used = {text for where, text in file.identifiers() if where.start_line == line}
    names: set[str] = set()
    for call in parsed.calls_of(path, _all_calls):
        name_node = _callee_name_node(call)
        if name_node is None:
            continue
        name = (name_node.text or b"").decode("utf-8", errors="replace")
        if first(call) <= line <= last(call):
            names.add(name)
            continue
        parent = call.parent
        if parent is None:
            continue
        left = parent.child_by_field_name("left") or parent.child_by_field_name("name")
        if left is not None and (left.text or b"").decode("utf-8", errors="replace") in used:
            names.add(name)
    return names


# --- class context and imports ----------------------------------------------------------------


def _class_of(node: Node | None) -> Node | None:
    while node is not None and node.type not in CLASS_TYPES:
        node = node.parent
    return node


def _field_name_of(node: Node, source: bytes) -> tuple[str, str] | None:
    """A declared class field as ``(name, type text)``; the type is empty when not declared."""
    if node.type in {"field_definition", "public_field_definition"}:
        name = node.child_by_field_name("name")
        if name is None:
            return None
        kind = _text_of(node.child_by_field_name("type"), source, SCRIPT_NEUTRAL_DEFAULT)
        return _text_of(name, source), kind.lstrip(": ")
    if node.type == "expression_statement" and node.named_children:
        inner = node.named_children[0]
        if inner.type == "assignment":
            left = inner.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                return _text_of(left, source), _text_of(inner.child_by_field_name("type"), source)
    return None


def _declared_fields(class_node: Node, source: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    body = class_node.child_by_field_name("body")
    for member in body.named_children if body is not None else ():
        declared = _field_name_of(member, source)
        if declared is not None:
            fields.setdefault(declared[0], declared[1])
    stack = list(body.named_children) if body is not None else []
    while stack:  # ``self.name: T = ...`` and ``self.name = ...`` inside methods
        node = stack.pop()
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "attribute":
                owner = left.child_by_field_name("object")
                attribute = left.child_by_field_name("attribute")
                if (
                    owner is not None
                    and attribute is not None
                    and _text_of(owner, source) == "self"
                ):
                    fields.setdefault(
                        _text_of(attribute, source),
                        _text_of(node.child_by_field_name("type"), source),
                    )
        if node.type not in CLASS_TYPES:
            stack.extend(node.named_children)
    return fields


def _is_callee(node: Node) -> bool:
    """Whether ``node`` is the thing being called by its parent call (a method, not a field)."""
    parent = node.parent
    if parent is None or parent.type not in _CALLS:
        return False
    target = _call_target(parent)
    return target is not None and target.id == node.id


def _referenced_members(method: Node, source: bytes) -> set[str]:
    """Names read or written as ``self.x`` / ``this.x`` in ``method``, other than called methods."""
    members: set[str] = set()
    stack = [method]
    while stack:
        node = stack.pop()
        if node.type in _ATTRIBUTES and not _is_callee(node):
            owner = node.child_by_field_name("object")
            attribute = node.child_by_field_name("attribute") or node.child_by_field_name(
                "property"
            )
            if (
                owner is not None
                and attribute is not None
                and _text_of(owner, source) in _SELF_NAMES
            ):
                members.add(_text_of(attribute, source))
        stack.extend(node.children)
    return members


def _is_public_base(base: str, allowlist: PublicAllowlist) -> bool:
    top = base.split(".", maxsplit=1)[0]
    final = base.rsplit(".", 1)[-1]
    return (
        allowlist.is_framework_contract(final)
        or allowlist.is_well_known(final)
        or allowlist.is_public_module(top)
    )


def _bases_of(class_node: Node, source: bytes, allowlist: PublicAllowlist) -> list[str]:
    heritage = class_node.child_by_field_name("superclasses")
    names: list[str] = []
    if heritage is not None:
        names = [
            _text_of(c, source) for c in heritage.named_children if c.type != "keyword_argument"
        ]
    else:
        for child in class_node.children:
            if child.type == "class_heritage":
                names = [_text_of(c, source) for c in child.named_children]
    return [
        name if _is_public_base(name, allowlist) else PLACEHOLDER_BASE for name in names if name
    ]


def _class_block(
    language: Language, name: str, bases: list[str], fields: list[tuple[str, str]]
) -> str:
    prefix = comment_prefix(language)
    if language is Language.PYTHON:
        heritage = f"({', '.join(bases)})" if bases else ""
        body = [f"    {field_name}: {kind or '...'}" for field_name, kind in fields]
        return "\n".join(
            [
                f"{prefix} {REASON_LABELS[StubReason.CLASS_CONTEXT]}",
                f"class {name}{heritage}:",
                *body,
            ]
        )
    heritage = f" extends {bases[0]}" if bases else ""
    body = [f"  {field_name}{': ' + kind if kind else ''};" for field_name, kind in fields]
    return "\n".join(
        [
            f"{prefix} {REASON_LABELS[StubReason.CLASS_CONTEXT]}",
            f"class {name}{heritage} {{",
            *body,
            "}",
        ]
    )


def class_stubs(
    segments: Sequence[SliceSegment], parsed: ParseIndex, allowlist: PublicAllowlist | None = None
) -> tuple[Stub, ...]:
    """For each class around a method of the slice, a stub of only the fields the methods use."""
    wanted: dict[tuple[str, str], tuple[ParsedFile, Node, set[str]]] = {}
    for path in sorted({segment.path for segment in segments}):
        try:
            file = parsed.parsed_of(path)
        except KeyError:
            continue
        if file.tree is None or file.language not in SUPPORTED:
            continue
        source = _source_of(file)
        for function in parsed.function_ranges_of(path):
            if function.kind != "method" or not _inside(segments, path, function):
                continue
            method = function_node(file, function)
            klass = _class_of(method.parent if method is not None else None)
            if method is None or klass is None or _class_inside(segments, path, klass):
                continue
            name = _text_of(klass.child_by_field_name("name"), source)
            if name:
                entry = wanted.setdefault((path, name), (file, klass, set()))
                entry[2].update(_referenced_members(method, source))
    stubs: list[Stub] = []
    for (path, name), (file, klass, members) in sorted(wanted.items()):
        source = _source_of(file)
        declared = _declared_fields(klass, source)
        chosen = [(n, declared[n]) for n in sorted(members) if n in declared]
        if not chosen:
            continue
        resolved = allowlist or PublicAllowlist.bundled(file.language)
        block = _class_block(file.language, name, _bases_of(klass, source, resolved), chosen)
        stubs.append(
            _stub(
                symbol=name,
                block=block,
                reason=StubReason.CLASS_CONTEXT,
                path=path,
                line=first(klass),
            )
        )
    return tuple(stubs)


def _class_inside(segments: Sequence[SliceSegment], path: str, klass: Node) -> bool:
    return any(
        s.path == path and s.region.start_line <= first(klass) and last(klass) <= s.region.end_line
        for s in segments
    )


def _import_line(ref: ImportRef, language: Language, *, verbatim: bool) -> str | None:
    imported = ref.imported
    bound = ref.bound
    if bound is None:
        return None
    module = ref.module if verbatim else "_internal"
    if language is Language.PYTHON:
        if imported and imported != "*":
            alias = f" as {ref.alias}" if ref.alias else ""
            return f"from {module} import {imported}{alias}"
        return f"import {module} as {bound}" if verbatim and bound != module else f"import {module}"
    if imported and imported != "*":
        alias = f" as {ref.alias}" if ref.alias else ""
        return f'import {{ {imported}{alias} }} from "{module}";'
    return f'import * as {bound} from "{module}";'


def import_stubs(
    segments: Sequence[SliceSegment], parsed: ParseIndex, allowlist: PublicAllowlist | None = None
) -> tuple[Stub, ...]:
    """A one-line stub for each imported name the segments use whose import is not in a segment.

    An allowlisted third-party or standard-library import is kept verbatim (the module name is a
    recognisable public API); any other import loses its module path, which would disclose the
    structure of the repository.
    """
    stubs: dict[tuple[str, str, str], Stub] = {}
    for path in sorted({s.path for s in segments}):
        try:
            file = parsed.parsed_of(path)
        except KeyError:
            continue
        if file.language not in SUPPORTED:
            continue
        resolved = allowlist or PublicAllowlist.bundled(file.language)
        regions = [s.region for s in segments if s.path == path]
        used = {
            text
            for where, text in file.identifiers()
            if any(r.start_line <= where.start_line <= r.end_line for r in regions)
        }
        for ref in parsed.symbols_of(path).imports:
            line = ref.location.start_line
            if (
                ref.bound is None
                or ref.bound not in used
                or any(r.start_line <= line <= r.end_line for r in regions)
            ):
                continue
            top = ref.module.lstrip(".").replace("/", ".").split(".")[0]
            verbatim = ref.origin in {"stdlib", "third_party"} and resolved.is_public_module(top)
            text = _import_line(ref, file.language, verbatim=verbatim)
            if text is None:
                continue
            stubs.setdefault(
                (path, ref.bound, text),
                _stub(
                    symbol=ref.bound,
                    block=text,
                    reason=StubReason.IMPORT_CONTEXT,
                    path=path,
                    line=line,
                ),
            )
    return tuple(sorted(stubs.values(), key=lambda s: (s.path or "", s.line or 0, s.symbol)))


# --- the whole set ----------------------------------------------------------------------------


def build_stubs(
    segments: Sequence[SliceSegment],
    parsed: ParseIndex,
    *,
    candidate_path: str,
    candidate_line: int,
    allowlist: PublicAllowlist | None = None,
    budget_tokens: int | None = None,
) -> StubSet:
    """Every stub of the slice, in priority order, within ``budget_tokens`` when it is given.

    Priority: callees on the data path of the candidate, then the other callees, then the class
    fields, then the imports; inside a tier by qualified name. Stubs are dropped from the end as
    soon as one does not fit, and ``StubStats`` records how many and why.
    """
    tally = _Tally()
    callees = _function_stubs(callees_of(segments, parsed), parsed, segments, allowlist, tally)
    on_path = _data_path_names(parsed, candidate_path, candidate_line)
    ranked: list[tuple[_Priority, Stub]] = [
        (
            _Priority.DATA_PATH_CALLEE
            if stub.symbol.rsplit(".", 1)[-1] in on_path
            else _Priority.OTHER_CALLEE,
            stub,
        )
        for stub in callees
    ]
    ranked += [(_Priority.CLASS_FIELDS, s) for s in class_stubs(segments, parsed, allowlist)]
    ranked += [(_Priority.IMPORT, s) for s in import_stubs(segments, parsed, allowlist)]
    ranked.sort(key=lambda item: (item[0], item[1].symbol, item[1].path or "", item[1].line or 0))
    kept: list[Stub] = []
    used = 0
    dropped: dict[str, int] = {}
    for position, (_, stub) in enumerate(ranked):
        cost = estimate(stub.signature.expose()) + 1
        if budget_tokens is not None and used + cost > budget_tokens:
            for _, left_out in ranked[position:]:
                key = REASON_LABELS[left_out.reason]
                dropped[key] = dropped.get(key, 0) + 1
            break
        kept.append(stub)
        used += cost
    stats = StubStats(
        omitted_public=tally.public,
        omitted_excluded=tally.excluded,
        stubs_omitted=sum(dropped.values()),
        omitted_reasons=tuple(sorted(dropped.items())),
    )
    return StubSet(stubs=tuple(kept), stats=stats)


def fit_stubs(
    stub_set: StubSet,
    segments: Sequence[SliceSegment],
    *,
    language: Language,
    labels: Callable[[str], str],
    max_tokens: int,
) -> tuple[StubSet, int]:
    """The stubs that parse and, with the segments, fit ``max_tokens``; and the assembled estimate.

    A stub whose text does not parse is dropped (fail closed: a smaller slice, never a broken
    one). Then the lowest-priority stubs are dropped until the assembled text fits. Everything
    dropped here is added to the statistics.
    """
    kept = [stub for stub in stub_set.stubs if _parses(stub, language)]
    total = estimate(assemble(segments, kept, language=language, labels=labels))
    while kept and total > max_tokens:
        kept.pop()
        total = estimate(assemble(segments, kept, language=language, labels=labels))
    dropped: dict[str, int] = dict(stub_set.stats.omitted_reasons)
    left_out = [stub for stub in stub_set.stubs if stub not in kept]
    for stub in left_out:
        label = REASON_LABELS[stub.reason]
        dropped[label] = dropped.get(label, 0) + 1
    stats = replace(
        stub_set.stats,
        stubs_omitted=stub_set.stats.stubs_omitted + len(left_out),
        omitted_reasons=tuple(sorted(dropped.items())),
    )
    return StubSet(stubs=tuple(kept), stats=stats), total


def _parses(stub: Stub, language: Language) -> bool:
    result = parse("stub", language, stub.signature.expose())
    return result.error_count == 0


__all__ = [
    "NEUTRAL_DEFAULT",
    "SCRIPT_NEUTRAL_DEFAULT",
    "EffectSummary",
    "StubSet",
    "StubStats",
    "build_stubs",
    "callees_of",
    "class_stubs",
    "effect_summary",
    "fit_stubs",
    "function_node",
    "function_stub",
    "import_stubs",
    "is_valid_summary",
    "make_stubs",
    "name_only_signature",
    "parameter_names",
    "signature_of",
]
