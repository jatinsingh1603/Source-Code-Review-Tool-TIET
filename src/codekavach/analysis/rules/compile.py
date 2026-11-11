"""Compiling a rule pattern into a structural pattern over a tree-sitter tree (E16-02).

Owning epic: E16.

**Backend decision.** Patterns are compiled to *structural matchers built in this package*, not to
tree-sitter queries and not to ast-grep. The three criteria of the issue:

1. *Ellipsis and variadic arguments.* A tree-sitter query cannot say "any run of sibling statements"
   or "any argument list"; a structural comparison over node kinds with holes can. This decided it.
2. *Pinned grammar.* The matcher reads the grammar version from the ``LanguageSpec`` of the
   language and folds it into the cache key (``Matcher.cache_key``), so a grammar bump is a cache
   miss and never a silent change of behaviour.
3. *Dependency.* None is added. ast-grep (MIT) would pass the licence gate, but its rule objects
   would put a second pattern engine between the DSL and the trees the parse stage already builds.

The ``Matcher`` interface does not expose the backend, so the choice can be revisited.

**How a pattern is read.** Metavariables are not valid identifiers in most grammars, so the pattern
text is rewritten to identifier-safe placeholders before parsing (``$X`` to ``__ckmv_X__``,
``$...ARGS`` to ``__ckva_ARGS__``, a bare ``...`` to ``__ckel__``; text inside string literals is
left alone) and the placeholders are recognised again in the parsed tree. A bare ``_`` identifier
is an anonymous wildcard. A string literal whose content is exactly ``...`` matches any string.
A snippet with several statements is a sequence pattern.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Final

from tree_sitter import Node, Tree

from codekavach.config import Settings
from codekavach.core.models import Language
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.parser import ParseUnavailableError, SourceTooLargeError, parse
from codekavach.parsing.spec import REGISTRY, UnknownLanguageError

MV_PREFIX: Final = b"__ckmv_"
VA_PREFIX: Final = b"__ckva_"
ELLIPSIS: Final = b"__ckel__"
WILDCARD: Final = b"_"
_STRINGS: Final = re.compile(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')")
_VARIADIC: Final = re.compile(r"\$\.\.\.([A-Z][A-Z0-9_]*)")
_SINGLE: Final = re.compile(r"\$([A-Z][A-Z0-9_]*)")
_BARE_ELLIPSIS: Final = re.compile(r"(?<![\w.$])\.\.\.(?![\w.])")
_WRAPPERS: Final = frozenset({"expression_statement"})
_TRIVIA: Final = frozenset({"comment"})
STRING_KINDS: Final = frozenset(
    {
        "string",
        "string_literal",
        "interpreted_string_literal",
        "raw_string_literal",
        "template_string",
    }
)


class PatternSyntaxError(ValueError):
    """The pattern does not parse in the declared language (``CK-RULE-011``)."""

    code = "CK-RULE-011"


NODE: Final = 0
METAVAR: Final = 1
WILDCARD_NODE: Final = 2
ANY_STRING: Final = 3
LEAF: Final = 4
ITEM_NODE: Final = 0
ITEM_ELL: Final = 1
ITEM_VAR: Final = 2
_EMPTY_STRING: Final = re.compile(rb"[A-Za-z]{0,2}(\"\"\"|'''|\"|'|`)\.\.\.\1")


@dataclass(frozen=True, slots=True)
class PNode:
    """A pattern node reduced to what matching needs, so no tree-sitter call is made per try."""

    kind: int
    type: str
    text: bytes
    name: str
    items: "tuple[PItem, ...]"


@dataclass(frozen=True, slots=True)
class PItem:
    """One element of a pattern's child sequence: a node, an ellipsis or a variadic capture."""

    kind: int
    node: PNode | None
    name: str = ""
    lead_comma: bool = False
    trail_comma: bool = False


def significant(children: Sequence[Node]) -> list[Node]:
    """``children`` without comments and other extras."""
    return [child for child in children if child.type not in _TRIVIA and not child.is_extra]


def plan_node(node: Node) -> PNode:
    """Reduce a parsed pattern node to a :class:`PNode`."""
    text = node.text or b""
    children = node.children
    if not children:
        if text.startswith(MV_PREFIX):
            return PNode(METAVAR, node.type, text, "$" + text[len(MV_PREFIX) : -2].decode(), ())
        if text == WILDCARD:
            return PNode(WILDCARD_NODE, node.type, text, "", ())
    if node.type in STRING_KINDS and _EMPTY_STRING.fullmatch(text):
        return PNode(ANY_STRING, node.type, text, "", ())
    if not children:
        return PNode(LEAF, node.type, text, "", ())
    return PNode(NODE, node.type, text, "", plan_items(children))


def required_texts(node: PNode) -> tuple[bytes, ...]:
    """Literal words every match of ``node`` must contain, for a cheap rejection test."""
    found: set[bytes] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.kind == LEAF and len(current.text) >= 2 and current.text[:1].isalnum():
            found.add(current.text)
        stack.extend(item.node for item in current.items if item.node is not None)
    return tuple(sorted(found, key=len, reverse=True))


def _hole(node: Node) -> tuple[int, str] | None:
    while node.type in _WRAPPERS:
        inner = significant(node.named_children)
        if len(inner) != 1:
            return None
        node = inner[0]
    text = node.text or b""
    if text == ELLIPSIS:
        return ITEM_ELL, ""
    if text.startswith(VA_PREFIX) and not node.children:
        return ITEM_VAR, "$..." + text[len(VA_PREFIX) : -2].decode()
    return None


def plan_items(children: Sequence[Node]) -> tuple[PItem, ...]:
    """Classify pattern children; a comma beside an ellipsis becomes part of the ellipsis."""
    raw: list[PItem] = []
    for child in significant(children):
        hole = _hole(child)
        raw.append(PItem(hole[0], None, hole[1]) if hole else PItem(ITEM_NODE, plan_node(child)))
    items: list[PItem] = []
    index = 0
    while index < len(raw):
        item = raw[index]
        if item.kind != ITEM_NODE:
            previous = items[-1] if items else None
            lead = bool(previous and previous.node and previous.node.type == ",")
            if lead:
                items.pop()
            following = raw[index + 1] if index + 1 < len(raw) else None
            trail = bool(not lead and following and following.node and following.node.type == ",")
            if trail:
                index += 1
            item = PItem(item.kind, None, item.name, lead, trail)
        items.append(item)
        index += 1
    return tuple(items)


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    """A pattern ready to match: the parsed snippet, its holes and its anchor kind.

    ``tree`` is kept so the nodes stay valid. ``roots`` is one node for an ordinary pattern and
    several for a sequence pattern, where the first is the anchor.
    """

    text: str
    language: Language
    tree: Tree
    roots: tuple[Node, ...]
    names: frozenset[str]
    root: PNode
    items: tuple[PItem, ...]
    required: tuple[bytes, ...] = ()

    @property
    def anchor_kind(self) -> str:
        """Node type the matcher looks for in a target tree."""
        return self.roots[0].type

    @property
    def is_sequence(self) -> bool:
        """True for a pattern of several statements."""
        return len(self.roots) > 1


def rewrite(text: str) -> tuple[str, frozenset[str]]:
    """Replace metavariables and bare ellipses by identifier-safe placeholders."""
    names: set[str] = set()

    def segment(piece: str) -> str:
        names.update(_VARIADIC.findall(piece))
        names.update(_SINGLE.findall(_VARIADIC.sub("", piece)))
        piece = _VARIADIC.sub(lambda m: f"__ckva_{m.group(1)}__", piece)
        piece = _SINGLE.sub(lambda m: f"__ckmv_{m.group(1)}__", piece)
        return _BARE_ELLIPSIS.sub("__ckel__", piece)

    parts = _STRINGS.split(text)
    rebuilt = [part if index % 2 else segment(part) for index, part in enumerate(parts)]
    return "".join(rebuilt), frozenset(names)


def unwrap(node: Node) -> Node:
    """The expression inside an expression statement, else ``node``."""
    while node.type in _WRAPPERS:
        inner = [child for child in node.named_children if child.type not in _TRIVIA]
        if len(inner) != 1:
            break
        node = inner[0]
    return node


def is_placeholder(node: Node) -> bool:
    """True when ``node`` is a metavariable, a variadic metavariable or an ellipsis."""
    if node.children:
        return False
    text = node.text or b""
    return text.startswith((MV_PREFIX, VA_PREFIX)) or text == ELLIPSIS


_STATEMENT_LANGUAGES: Final = frozenset({Language.C, Language.CPP})
_WRAP_HEAD: Final = "void __ck_wrapper__(void) {" + chr(10)


def _parse(text: str, language: Language) -> ParsedFile:
    try:
        return parse("pattern.txt", language, text, settings=Settings().parsing)
    except (ParseUnavailableError, SourceTooLargeError) as error:
        raise PatternSyntaxError(f"no grammar for {language.value}") from error


def _wrap_statements(text: str) -> str:
    """C-family patterns are statements: put them in a function body and end each line.

    A bare ellipsis line and the final line get a semicolon so ``f(x)`` or ``free(p); ... p->v``
    parse as statements; a pattern that already ends a statement is left alone.
    """
    lines = text.strip().splitlines()
    fixed = [line + ";" if line.strip() == "__ckel__" else line for line in lines]
    body = chr(10).join(fixed)
    if not body.rstrip().endswith((";", "}")):
        body += ";"
    return f"{_WRAP_HEAD}{body}{chr(10)}}}{chr(10)}"


def _wrapped_statements(root: Node) -> list[Node]:
    for child in root.named_children:
        if child.type == "function_definition":
            body = child.child_by_field_name("body")
            if body is not None:
                return significant(body.named_children)
    return []


@lru_cache(maxsize=2048)
def _compile(text: str, language: Language, grammar: str) -> CompiledPattern:
    del grammar  # part of the cache key: a grammar change must recompile
    rewritten, names = rewrite(text)
    parsed = _parse(rewritten, language)
    top: list[Node] = []
    if parsed.tree is not None and parsed.error_count == 0:
        top = significant(parsed.tree.root_node.named_children)
    elif language in _STATEMENT_LANGUAGES:
        wrapped = _wrap_statements(rewritten)
        parsed = _parse(wrapped, language)
        if parsed.tree is None or parsed.error_count != 0:
            raise PatternSyntaxError("the pattern does not parse")
        top = _wrapped_statements(parsed.tree.root_node)
    else:
        raise PatternSyntaxError("the pattern does not parse")
    if not top:
        raise PatternSyntaxError("the pattern is empty")
    roots = tuple(unwrap(item) for item in top)
    if any(is_placeholder(root) for root in roots[:1]):
        raise PatternSyntaxError("the pattern starts with a bare metavariable")
    root = plan_node(roots[0])
    return CompiledPattern(
        text, language, parsed.tree, roots, names, root, plan_items(roots), required_texts(root)
    )


def compile_pattern(pattern: str, language: Language) -> CompiledPattern:
    """Parse ``pattern`` with the grammar of ``language``; raises ``PatternSyntaxError``.

    Results are cached per ``(pattern, language, grammar version)``.
    """
    return _compile(pattern, language, grammar_version(language))


def grammar_version(language: Language) -> str:
    """The pinned grammar version of ``language``, or ``unpinned`` when no spec is registered."""
    try:
        return REGISTRY.get(language).grammar_version
    except UnknownLanguageError:
        return "unpinned"


def clear_cache() -> None:
    """Forget compiled patterns (tests)."""
    _compile.cache_clear()
