"""Internal or public: the decision for every identifier occurrence of a parsed file (E09-02).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

``IdentifierClassifier`` says, for each identifier occurrence in a ``SymbolTable``, whether the
renamer may rewrite it (``INTERNAL``) or must keep it (``PUBLIC``). ``classify_all`` runs it over
one parsed file and returns a ``ClassificationResult``: one decision per occurrence, counters of
every conservative choice, the names that stay in clear, and the allowlist version. The renamer
(E09-04), the literal rules (E09-03) and the payload provenance read this result.

**Every ambiguity is INTERNAL.** A name is public only by one of the rules below, each of which
rests on a fact a reviewer can check: the name is a keyword or builtin of the language, a dunder
name, a framework contract or decorator, a well-known source, sink or sanitiser, an extra name the
user chose, a member of a package the file imports, or bound by an import whose module is stdlib
or allowlisted. Everything else is INTERNAL, and an unresolved reference or member with no known
base is INTERNAL too, counted.

**The kind of an imported name.** A decision carries the kind a renamer gives the name's token.
A name bound by an import and called in the text is a function (a class when written in
PascalCase), so the slice that imports it and the slice that defines it use the same ``fn_N`` or
``cls_N`` (E09-FU). It is a heuristic read from the call syntax; an exact kind needs the
definition, which only the slicer's index knows.

**Member names are decided by name within the file.** The renamer cannot tell which object an
attribute belongs to (``x.args`` is an external occurrence with no binding), so a member name must
get one decision per file, or a renamed definition and an unrenamed access would disagree and
break the code. The base of a chain (``request.args.get``) therefore sharpens the *reason* and
the *packages* used to check keyword arguments, it does not change the decision for the name.
``cur.execute(sql, params=values)`` is public on the name ``execute`` because the file imports a
DB-API driver, which is why the keyword ``params`` survives while ``values`` does not.

**Keyword arguments follow their callee.** A keyword name is PUBLIC only when the callee is public
and the keyword is a member of the callee's packages (``type=`` on ``request.args.get``). On an
internal callee it is INTERNAL. A parameter definition is classified by name, so a keyword and the
parameter it binds can differ when the name is public by name; the renamer must rename a keyword
and its parameter together, which E09-04 owns.

**An incomplete table is never public by default.** A parse with error nodes, or a parse that
timed out, has a symbol table whose imports, bases and callees may be wrong. A decision that
depends on the table (an import origin, an in-scope package, a base, a callee) becomes INTERNAL
and is counted in ``incomplete_table``. Only decisions that depend on the name alone (keyword,
builtin, dunder, framework contract or decorator, well-known name) stay PUBLIC.

**Dynamic names: the trade-off.** ``getattr(account, "festival_bonus_rate")`` and
``Reflect.get(obj, "name")`` hold an identifier inside a string literal, and ``obj["name"]``
indexes by one. Four treatments were considered for a name N that a literal refers to. (a)
Rewrite the definition and the string together when N is bound to exactly one definition in this
file and every occurrence of N is bound there (``DYNAMIC_NAME``): the code stays consistent and
the name is protected. This is used when it can be proved. (b) Leave the definition, every
occurrence and the string alone, and count it (``kept_identifier``): the name stays in clear, but
the payload provenance lists it and the report says so. This is used when the rewrite cannot be
proved, typically when the attribute is defined in another file. (c) Fail the candidate closed
on every dynamic access: rejected, because a literal-keyed ``getattr`` is common in real code and
would make the tool unusable on it. (d) Rename the definition and not the string: rejected, since
it leaves inconsistent code and leaks the name anyway. Option (b) is therefore the honest default
for unprovable names, and it is a measured disclosure, not a hidden one. A subscript with a
literal key is treated as dynamic only when the key is an identifier of the file; any other string
is left to the literal rules of E09-03, so ordinary dictionary keys do not enter the provenance.
``eval``, ``exec``, ``compile`` and ``Function`` execute text the classifier cannot see; their
occurrences carry ``DYNAMIC_CODE`` so that a file containing one is treated as opaque.

**Serialisation fields.** A class-body field of a dataclass, a Pydantic model or a Marshmallow
schema is INTERNAL with ``SERIALISATION_FIELD``, so that E09-04 renames the definition and its
string form together. JSON keys written as string literals are E09-03's concern.

**The allowlist is a disclosure.** ``kept_public_names()`` lists every name that leaves in clear,
and the allowlist version is recorded with it, so the leakage harness can count the stack that the
allowlist discloses (docs/research/INSIGHTS.md section 3.3 item 1). Nothing here claims to hide
the technology stack.

**How the syntax is read.** A member's base, a keyword's callee and a literal's container are
found from the source text around the occurrence, by absolute character offsets: a symbol ending
just before a ``.`` is the base, the nearest unmatched ``(`` before a keyword names its callee.
A tree-sitter node lookup costs more than a whole symbol's decision, so the tree is used only for
the rare class-field check. The limit is stated, not hidden: a chain or call split across lines by
a line break before the ``.`` is seen as an unresolved base, and a string holding a parenthesis
can confuse the scan; both lead to INTERNAL or to a counted unresolved base, never to a public
default the table does not support.
"""

from enum import StrEnum
from typing import TYPE_CHECKING, Final, NamedTuple

from tree_sitter import Node

from codekavach.core.log import get_logger
from codekavach.core.models import Language, Location
from codekavach.parsing.imports import DefaultImportResolver, ImportRef, ImportResolver
from codekavach.parsing.scopes import UNRESOLVED
from codekavach.parsing.symbols import Symbol, SymbolTable
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist

if TYPE_CHECKING:
    from codekavach.parsing.models import ParsedFile

_log = get_logger("codekavach.privacy.pseudonymise.classify")

_SERIALISED_BASES: Final = ("BaseModel", "Schema", "TypedDict", "NamedTuple", "Struct")
_FIELD_KINDS: Final = frozenset({"field", "variable", "constant"})
_MAX_CLASS_DEPTH: Final = 8
_MAX_CALL_SCAN: Final = 4000  # characters a backward scan may cross to find the enclosing call
_QUOTES: Final = "'\""


class IdentifierClass(StrEnum):
    """The decision: the renamer rewrites an ``INTERNAL`` occurrence and keeps a ``PUBLIC`` one."""

    INTERNAL = "internal"
    PUBLIC = "public"


class ClassificationNote(StrEnum):
    """A fact the renamer must act on besides the decision itself."""

    SERIALISATION_FIELD = "serialisation_field"
    DYNAMIC_NAME = "dynamic_name"
    DYNAMIC_CODE = "dynamic_code"


_NO_NOTES: Final[frozenset[ClassificationNote]] = frozenset()


class Rule(StrEnum):
    """The rule that decided an occurrence; the name-only rules are in ``NAME_ONLY_RULES``."""

    MAGIC = "magic"
    KEYWORD_OR_BUILTIN = "keyword_or_builtin"
    EXTRA = "extra"
    FRAMEWORK_CONTRACT = "framework_contract"
    FRAMEWORK_DECORATOR = "framework_decorator"
    WELL_KNOWN = "well_known"
    RECEIVER = "receiver"
    MEMBER_NAME = "member_name"
    MEMBER_OF_PUBLIC = "member_of_public"
    STDLIB_IMPORT = "stdlib_import"
    ALLOWLISTED_IMPORT = "allowlisted_import"
    UNLISTED_IMPORT = "unlisted_import"
    INTERNAL_IMPORT = "internal_import"
    KEYWORD_OF_PUBLIC = "keyword_of_public"
    KEYWORD_NOT_LISTED = "keyword_not_listed"
    KEYWORD_OF_INTERNAL = "keyword_of_internal"
    KEPT_DYNAMIC = "kept_dynamic"
    INCOMPLETE_TABLE = "incomplete_table"
    DEFAULT_INTERNAL = "default_internal"


# Rules that decide PUBLIC from the name alone. An incomplete table can still rely on these.
NAME_ONLY_RULES: Final = frozenset(
    {
        Rule.MAGIC,
        Rule.KEYWORD_OR_BUILTIN,
        Rule.EXTRA,
        Rule.FRAMEWORK_CONTRACT,
        Rule.FRAMEWORK_DECORATOR,
        Rule.WELL_KNOWN,
    }
)


class ClassificationDecision(NamedTuple):
    """The decision for one identifier occurrence, the rule that made it, and its notes."""

    name: str
    kind: str
    location: Location
    classification: IdentifierClass
    rule: Rule
    notes: frozenset[ClassificationNote]


class ConservativeCounts(NamedTuple):
    """How often a conservative choice was made in one file.

    ``unresolved_base``: a member access whose base is not a resolved binding and not a known
    package member, decided by name. ``unresolved_name``: a plain name with no visible binding
    that is INTERNAL. ``incomplete_table``: a PUBLIC-by-table decision forced to INTERNAL.
    ``kept_identifier``: a dynamic name left in clear. ``dynamic_name_marked``: a dynamic name
    rewritten consistently. ``dynamic_code``: a call that executes text.
    """

    unresolved_base: int = 0
    unresolved_name: int = 0
    incomplete_table: int = 0
    kept_identifier: int = 0
    dynamic_name_marked: int = 0
    dynamic_code: int = 0


class ClassificationResult(NamedTuple):
    """Every decision of one file, in source order, with the provenance the payload records."""

    decisions: tuple[ClassificationDecision, ...]
    counts: ConservativeCounts
    allowlist_version: str
    kept_dynamic: frozenset[str]

    def kept_public_names(self) -> tuple[str, ...]:
        """The distinct names that leave in clear: every PUBLIC occurrence and every kept name.

        This is the set the leakage harness counts as the disclosed stack fingerprint.
        """
        names = {d.name for d in self.decisions if d.classification is IdentifierClass.PUBLIC}
        return tuple(sorted(names | self.kept_dynamic))


class _Verdict(NamedTuple):
    classification: IdentifierClass
    rule: Rule
    packages: tuple[str, ...] = ()
    notes: frozenset[ClassificationNote] = _NO_NOTES
    depends_on_table: bool = False


# Shared verdicts for the common outcomes: no allocation per occurrence.
_MAGIC_VERDICT: Final = _Verdict(IdentifierClass.PUBLIC, Rule.MAGIC)
_EXTRA_VERDICT: Final = _Verdict(IdentifierClass.PUBLIC, Rule.EXTRA)
_DEFAULT_VERDICT: Final = _Verdict(IdentifierClass.INTERNAL, Rule.DEFAULT_INTERNAL)
_RECEIVER_VERDICT: Final = _Verdict(IdentifierClass.PUBLIC, Rule.RECEIVER, depends_on_table=True)

_JAVA_LIBRARY_ROOTS: Final = frozenset({"java", "javax", "jakarta"})
_ANNOTATIONS: Final = frozenset({"annotation", "marker_annotation"})
_CALL_BOUND_METHODS: Final = frozenset({Language.JAVA, Language.GO})
_QUALIFIED_KINDS: Final = frozenset({"class", "variable", "method", "constant"})
_JAVA_PACKAGE_SEGMENTS: Final = 2  # java.sql, org.springframework
_GO_HOST_SEGMENTS: Final = 3  # github.com/owner/repo
# The conventional spellings of the receiver of a method. Only these are kept in clear, so that a
# receiver spelled after the client (``account``) is still renamed.
_RECEIVER_NAMES: Final = frozenset({"self", "cls"})
_NEWLINE: Final = chr(10)


class _Tally:
    """Mutable counters of one run; frozen into ``ConservativeCounts`` at the end."""

    __slots__ = (
        "dynamic_code",
        "dynamic_name_marked",
        "incomplete_table",
        "kept_identifier",
        "unresolved_base",
        "unresolved_name",
    )

    def __init__(self) -> None:
        self.unresolved_base = 0
        self.unresolved_name = 0
        self.incomplete_table = 0
        self.kept_identifier = 0
        self.dynamic_name_marked = 0
        self.dynamic_code = 0

    def freeze(self) -> ConservativeCounts:
        return ConservativeCounts(
            unresolved_base=self.unresolved_base,
            unresolved_name=self.unresolved_name,
            incomplete_table=self.incomplete_table,
            kept_identifier=self.kept_identifier,
            dynamic_name_marked=self.dynamic_name_marked,
            dynamic_code=self.dynamic_code,
        )


def _top_package(module: str, language: Language) -> str:
    """The package of a module string: ``flask.ext`` is ``flask``, ``@x/y/z`` is ``@x/y``.

    Java keys a package by its first two segments (``java.sql``, ``org.springframework``); Go
    keys a standard-library package by its whole path and a hosted module by its first three
    elements (``github.com/gin-gonic/gin``).
    """
    if language is Language.PYTHON:
        return module.split(".", 1)[0]
    if language is Language.JAVA:
        return ".".join(module.split(".")[:_JAVA_PACKAGE_SEGMENTS])
    if language is Language.GO:
        parts = module.split("/")
        # ``fmt`` and ``database/sql`` are whole; ``github.com/o/r/sub`` is ``github.com/o/r``.
        return "/".join(parts[:_GO_HOST_SEGMENTS]) if "." in parts[0] else module
    text = module.removeprefix("node:")
    parts = text.split("/")
    if text.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


def _contains(outer: Location, inner: Location) -> bool:
    if outer.path != inner.path:
        return False
    start = (outer.start_line, outer.start_col or 0)
    end = (outer.end_line, outer.end_col or 0)
    inner_start = (inner.start_line, inner.start_col or 0)
    inner_end = (inner.end_line, inner.end_col or 0)
    return start <= inner_start and inner_end <= end


def _identifier_like(text: str) -> bool:
    return bool(text) and text.replace("$", "_").isidentifier()


def _is_word(char: str) -> bool:
    return char.isalnum() or char in "_$"


def _line_starts(source: str) -> list[int]:
    r"""The character offset of the first character of every line, split on ``\n`` only."""
    starts: list[int] = []
    offset = 0
    for line in source.split("\n"):
        starts.append(offset)
        offset += len(line) + 1
    return starts


class _TreeContext:
    """The syntax tree of one file, reached from a symbol by byte offset.

    Used for the rare class-field check only: a node lookup costs more than a symbol's whole
    decision, so the other rules read the source text instead.
    """

    __slots__ = ("_line_starts", "_lines", "root")

    def __init__(self, root: Node) -> None:
        self.root = root
        self._lines = (root.text or b"").split(b"\n")
        starts: list[int] = []
        offset = 0
        for line in self._lines:
            starts.append(offset)
            offset += len(line) + 1
        self._line_starts = starts

    def node_for(self, location: Location, name: str) -> Node | None:
        """The node whose span is exactly the identifier ``name`` at ``location``, or ``None``."""
        line = location.start_line
        if line < 1 or line > len(self._lines):
            return None
        raw = self._lines[line - 1]
        column = max((location.start_col or 1) - 1, 0)
        if not raw.isascii():
            column = len(raw.decode("utf-8", errors="replace")[:column].encode("utf-8"))
        start = self._line_starts[line - 1] + column
        node = self.root.descendant_for_byte_range(start, start + len(name.encode("utf-8")))
        if node is None or node.start_byte != start:
            return None
        return node


class _Run:
    """One classification of one file. Holds the memo and the counters; discarded afterwards."""

    def __init__(
        self, table: SymbolTable, allowlist: PublicAllowlist, parsed: "ParsedFile | None"
    ) -> None:
        self._table = table
        self._symbols = table.symbols
        self._allowlist = allowlist
        self._language = allowlist.language
        self._parsed = parsed
        tree = parsed.tree if parsed is not None else None
        self._root: Node | None = None if tree is None else tree.root_node
        self._tree_context: _TreeContext | None = None
        self._source = (
            "" if self._root is None else (self._root.text or b"").decode("utf-8", errors="replace")
        )
        self._incomplete = parsed is None or tree is None or parsed.error_count != 0
        self._refs: dict[tuple[str, int], ImportRef] = {}
        for ref in table.imports:
            if ref.bound is not None:
                self._refs.setdefault((ref.bound, ref.scope_id), ref)
        self._refs_by_name: dict[str, ImportRef] = {}
        for ref in table.imports:
            if ref.bound is not None:
                self._refs_by_name.setdefault(ref.bound, ref)
        self._listing = self._scope_listing()
        self._memo: list[_Verdict | None] = [None] * len(table.symbols)
        self._named_listed: dict[str, _Verdict | None] = {}
        self._named_plain: dict[str, _Verdict | None] = {}
        self._tally = _Tally()
        self._receivers: dict[int, str | None] = {}
        self._line_starts = _line_starts(self._source) if self._root is not None else []
        # Character offsets of every identifier's end, to find the symbol that ends just before a
        # ``.`` (its base) or a ``(`` (its callee).
        self._by_end: dict[int, int] = {}
        for index, symbol in enumerate(self._symbols):
            if self._root is not None:
                end = self._offset(symbol.location.start_line, symbol.location.start_col)
                if end >= 0:
                    self._by_end[end + len(symbol.name)] = index

    # --- positions --------------------------------------------------------------------------

    def _offset(self, line: int | None, col: int | None) -> int:
        """The character offset of (line, code-point column), or -1 when it is out of range."""
        if line is None or line < 1 or line > len(self._line_starts):
            return -1
        return self._line_starts[line - 1] + max((col or 1) - 1, 0)

    def _start_of(self, index: int) -> int:
        location = self._symbols[index].location
        return self._offset(location.start_line, location.start_col)

    # --- the packages in scope, and the name-level decision ---------------------------------

    def _scope_listing(self) -> dict[str, tuple[str, ...]]:
        allowlist = self._allowlist
        scope: set[str] = set()
        for package in allowlist.package_names():
            if allowlist.kind_of(package) in ("builtin", "pseudo"):
                scope.add(package)
        for ref in self._table.imports:
            if ref.conservative or ref.origin == "internal":
                continue
            top = _top_package(ref.module, self._language)
            if ref.origin == "stdlib" or allowlist.is_public_module(top):
                scope.add(top)
        return dict(allowlist.listing_for(frozenset(scope)))

    def _name_level(self, name: str, *, listed: bool) -> _Verdict | None:
        """The PUBLIC decision a name earns by itself, in rule order, or ``None``.

        ``listed`` says whether a member name of an imported package counts. It is true for
        attribute names, module path segments and class-level fields, which the renamer cannot
        bind to one definition, and false for a bound local, parameter or function, which is
        renamed by its binding and must not become public just because a package lists its name.
        The answer depends only on the name and ``listed``, so it is memoised for the run.
        """
        cache = self._named_listed if listed else self._named_plain
        if name not in cache:
            cache[name] = self._name_level_uncached(name, listed=listed)
        return cache[name]

    def _name_level_uncached(self, name: str, *, listed: bool) -> _Verdict | None:
        listing = self._listing.get(name, ()) if listed else ()
        by_name = self._name_only_rule(name, listing)
        if by_name is not None:
            return _Verdict(IdentifierClass.PUBLIC, by_name[0], by_name[1])
        if listing:
            return _Verdict(
                IdentifierClass.PUBLIC, Rule.MEMBER_NAME, listing, depends_on_table=True
            )
        return None

    def _name_only_rule(
        self, name: str, listing: tuple[str, ...]
    ) -> tuple[Rule, tuple[str, ...]] | None:
        """The rule that makes ``name`` public on its own, with its packages, or ``None``."""
        allowlist = self._allowlist
        if allowlist.is_keyword_or_builtin(name):
            return Rule.KEYWORD_OR_BUILTIN, ("builtins", *listing)
        if allowlist.is_extra(name):
            return Rule.EXTRA, listing
        if allowlist.is_framework_contract(name):
            return Rule.FRAMEWORK_CONTRACT, listing
        owner = allowlist.decorator_package(name)
        if owner is not None:
            return Rule.FRAMEWORK_DECORATOR, (owner,)
        if allowlist.is_well_known(name):
            return Rule.WELL_KNOWN, listing
        return None

    # --- decisions --------------------------------------------------------------------------

    def verdict(self, index: int) -> _Verdict:
        cached = self._memo[index]
        if cached is None:
            cached = self._decide(index)
            self._memo[index] = cached
        return cached

    def _decide(self, index: int) -> _Verdict:
        symbol = self._symbols[index]
        name = symbol.name
        scope = symbol.scope_id
        allowlist = self._allowlist
        if name[:2] == "__" and allowlist.is_magic(name):
            return _MAGIC_VERDICT
        if allowlist.is_extra(name):
            # The user's extra names are public wherever they occur, so that the setting only ever
            # adds to the public set, whatever rule would otherwise have decided the occurrence.
            return _EXTRA_VERDICT
        if scope >= 0 and self._refs:
            # Any binding of an imported name in the import's scope takes the import's origin.
            # The kind is not checked: a JavaScript ``const fs = require("fs")`` binds a variable.
            ref = self._refs.get((name, scope))
            if ref is not None:
                return self._import(ref)
        external = scope == UNRESOLVED and not symbol.is_definition
        if external and symbol.kind != "field" and self._member_base(index) is None:
            # A package named by an import that binds no symbol of its own (Go ``fmt``).
            ref = self._refs_by_name.get(name)
            if ref is not None:
                return self._import(ref)
        if external:
            return self._external(index, symbol)
        return self._bound(index, symbol)

    def _annotation_element(self, index: int, symbol: Symbol) -> _Verdict | None:
        """The name of an annotation element (``@Column(name = "x")``) of a public annotation.

        The element names are the annotation type's contract, so they stay with it. An element of
        an annotation the file declares is renamed with the ``@interface`` method.
        """
        context = self._tree()
        node = None if context is None else context.node_for(symbol.location, symbol.name)
        pair = None if node is None else node.parent
        if pair is None or pair.type != "element_value_pair":
            return None
        key = pair.child_by_field_name("key")
        if key is None or key.start_byte != (node.start_byte if node else -1):
            return None
        annotation = pair.parent
        while annotation is not None and annotation.type not in _ANNOTATIONS:
            annotation = annotation.parent
        named = None if annotation is None else annotation.child_by_field_name("name")
        if named is None:
            return None
        simple = (named.text or b"").decode("utf-8", errors="replace").rsplit(".", 1)[-1]
        ref = self._refs_by_name.get(simple)
        allowlist = self._allowlist
        if ref is not None:
            public = self._import(ref).classification is IdentifierClass.PUBLIC
        else:
            public = allowlist.is_keyword_or_builtin(simple) or (
                allowlist.decorator_package(simple) is not None
            )
        if not public:
            return None
        return _Verdict(IdentifierClass.PUBLIC, Rule.KEYWORD_OF_PUBLIC, depends_on_table=True)

    def _external(self, index: int, symbol: Symbol) -> _Verdict:
        """An occurrence with no visible binding: a module segment, a member or a keyword."""
        if self._language is Language.JAVA:
            if symbol.kind in {"field", "parameter", "variable"}:
                element = self._annotation_element(index, symbol)
                if element is not None:
                    return element
            if self._java_library_path(index):
                return _Verdict(IdentifierClass.PUBLIC, Rule.MEMBER_OF_PUBLIC, ("builtins",))
        if symbol.kind == "module":
            return self._module_segment(symbol)
        if symbol.kind == "field" or (symbol.kind in _QUALIFIED_KINDS and self._after_dot(index)):
            return self._member(index, symbol)  # ``pkg.Name``: a type or value of a package
        if symbol.kind == "parameter":
            return self._keyword(index, symbol)
        # An unbound plain name is not an attribute, so it is decided like a bound name.
        return self._bound(index, symbol)

    def _receiver_of(self, scope: int) -> str | None:
        """The name of the receiver of the method that ``scope`` is, or ``None``.

        The receiver is the first parameter of a function defined directly in a class body that
        is not a ``@staticmethod``. It is decided by that position, so a plain function, a nested
        function and a static method have none; its spelling only has to be a conventional one
        (``self`` or ``cls``) for the name to stay in clear. Without a parsed tree the decorators
        cannot be read, and the answer is ``None``.
        """
        if scope in self._receivers:
            return self._receivers[scope]
        found = self._find_receiver(scope)
        self._receivers[scope] = found
        return found

    def _find_receiver(self, scope: int) -> str | None:
        if self._language is not Language.PYTHON or self._root is None:
            return None
        scopes = self._table.scopes
        if not 0 <= scope < len(scopes) or scopes[scope].kind != "function":
            return None
        parent = scopes[scope].parent_id
        if parent is None or scopes[parent].kind != "class":
            return None
        first: tuple[int, int] | None = None
        name = ""
        for symbol in self._symbols:
            if symbol.scope_id == scope and symbol.is_definition and symbol.kind == "parameter":
                position = (symbol.location.start_line or 0, symbol.location.start_col or 0)
                if first is None or position < first:
                    first, name = position, symbol.name
        if first is None or name not in _RECEIVER_NAMES:
            return None
        return None if self._is_static(first) else name

    def _is_static(self, parameter: tuple[int, int]) -> bool:
        """Whether the ``def`` that holds the parameter at (line, col) carries ``@staticmethod``."""
        end = self._offset(*parameter)
        start = self._source.rfind("def", 0, end) if end >= 0 else -1
        if start < 0:
            return True  # an unreadable position is not trusted to be a method
        lines = self._source[:start].split(_NEWLINE)
        decorators: list[str] = []
        for text in reversed(lines[:-1]):
            stripped = text.strip()
            if not stripped.startswith("@"):
                break
            decorators.append(stripped.removeprefix("@").split("(")[0].split(".")[-1])
        return "staticmethod" in decorators

    def _bound(self, index: int, symbol: Symbol) -> _Verdict:
        """A name the file binds (a local, a parameter, a function, a class or a class field)."""
        scope = symbol.scope_id
        is_receiver_name = symbol.name in _RECEIVER_NAMES
        if scope >= 0 and is_receiver_name and self._receiver_of(scope) == symbol.name:
            return _RECEIVER_VERDICT
        in_class = symbol.is_definition and scope >= 0 and self._table.scopes[scope].kind == "class"
        if in_class and symbol.kind == "method" and self._language in _CALL_BOUND_METHODS:
            # A Java or Go method is called by its bare name too; deciding the definition by a
            # package listing and the call without one would rename only the call.
            in_class = False
        named = self._name_level(symbol.name, listed=in_class)
        if named is not None:
            return named
        if scope == UNRESOLVED:
            self._tally.unresolved_name += 1
        if in_class:
            notes = self._serialised(index, symbol)
            if notes:
                return _Verdict(IdentifierClass.INTERNAL, Rule.DEFAULT_INTERNAL, (), notes)
        return _DEFAULT_VERDICT

    def _import(self, ref: ImportRef) -> _Verdict:
        top = _top_package(ref.module, self._language)
        if ref.conservative or ref.origin == "internal":
            return _Verdict(IdentifierClass.INTERNAL, Rule.INTERNAL_IMPORT, depends_on_table=True)
        if ref.origin == "stdlib":
            return _Verdict(
                IdentifierClass.PUBLIC, Rule.STDLIB_IMPORT, (top,), depends_on_table=True
            )
        if self._allowlist.is_public_module(top):
            return _Verdict(
                IdentifierClass.PUBLIC, Rule.ALLOWLISTED_IMPORT, (top,), depends_on_table=True
            )
        return _Verdict(IdentifierClass.INTERNAL, Rule.UNLISTED_IMPORT, depends_on_table=True)

    def _module_segment(self, symbol: Symbol) -> _Verdict:
        """A module path (``billing`` in ``from billing.engine import x``).

        The first segment is the import's module and takes its origin; a later segment is a
        member of that package and is decided by name.
        """
        for ref in self._table.imports:
            if _contains(ref.location, symbol.location) and (
                self._language is Language.JAVA or ref.module.split(".", 1)[0] == symbol.name
            ):
                # Java: every segment of ``java.sql`` or ``com.bank.util`` takes the origin of
                # the import, so the qualifier of a class library import is not renamed.
                return self._import(ref)
        named = self._name_level(symbol.name, listed=True)
        if named is not None:
            return named
        return _DEFAULT_VERDICT

    def _java_library_path(self, index: int) -> bool:
        """Whether the identifier is a segment of a qualified name that starts at ``java.``.

        ``java.lang.reflect.Field`` written in code, without an import, is the class library by
        its first segment, so every segment stays; a qualified name that starts anywhere else is
        decided segment by segment.
        """
        source = self._source
        position = self._start_of(index)
        if position <= 0 or source[position - 1] != ".":
            return False
        while position > 0 and source[position - 1] == ".":
            start = position - 1
            while start > 0 and (source[start - 1].isalnum() or source[start - 1] in "_$"):
                start -= 1
            if start == position - 1:
                return False
            position = start
        end = position
        while end < len(source) and (source[end].isalnum() or source[end] in "_$"):
            end += 1
        return source[position:end] in _JAVA_LIBRARY_ROOTS

    def _after_dot(self, index: int) -> bool:
        """Whether the identifier is written right after a ``.`` (a member, whatever its base)."""
        dot = self._start_of(index) - 1
        if not 0 <= dot < len(self._source):
            return False
        return self._source[dot] == "." or self._source[dot - 1 : dot + 1] == "::"

    def _member_base(self, index: int) -> int | None:
        """The symbol of the identifier that an attribute access is taken from, if it is one.

        The base is the identifier ending just before the ``.`` in front of the member. A call,
        a subscript or a literal before the dot ends in ``)``, ``]`` or a quote, which no
        identifier ends with, so it has no base here.
        """
        if not self._source:
            return None
        dot = self._start_of(index) - 1
        if dot < 0 or self._source[dot] != ".":
            return None
        return self._by_end.get(dot)

    def _member(self, index: int, symbol: Symbol) -> _Verdict:
        base_index = self._member_base(index)
        base: _Verdict | None = None
        if base_index is not None:
            base = self.verdict(base_index)
            if base.classification is IdentifierClass.PUBLIC and base.packages:
                in_base = tuple(
                    package
                    for package in base.packages
                    if symbol.name in self._allowlist.members_of(package)
                )
                if in_base:
                    return _Verdict(
                        IdentifierClass.PUBLIC,
                        Rule.MEMBER_OF_PUBLIC,
                        in_base,
                        depends_on_table=True,
                    )
        # A base is resolved when it is a bound name or a member of a known package; anything
        # else (a call, a builtin object, an unbound name) is an unresolved base.
        resolved = False
        if base is not None and base_index is not None:
            resolved = self._symbols[base_index].scope_id != UNRESOLVED or bool(base.packages)
        if not resolved:
            self._tally.unresolved_base += 1
        named = self._name_level(symbol.name, listed=True)
        if named is not None:
            return named
        return _DEFAULT_VERDICT

    def _enclosing_paren(self, start: int) -> tuple[int | None, int]:
        """The ``(`` that encloses offset ``start``, and the top-level commas between it and start.

        The scan goes backwards over the source, skipping nested brackets, and gives up after
        ``_MAX_CALL_SCAN`` characters. ``None`` when no enclosing ``(`` is found in that range.
        """
        source = self._source
        depth = 0
        commas = 0
        floor = max(-1, start - _MAX_CALL_SCAN)
        position = start - 1
        while position > floor:
            char = source[position]
            if char in ")]}":
                depth += 1
            elif char in "([{":
                if depth == 0:
                    return (position if char == "(" else None), commas
                depth -= 1
            elif char == "," and depth == 0:
                commas += 1
            position -= 1
        return None, commas

    def _kind_of(self, index: int, symbol: Symbol) -> str:
        """The kind a renamer should give ``symbol``'s name: an imported name that is called.

        The pseudonym includes the kind, and the slice that defines a function or a class calls
        its token ``fn_N`` or ``cls_N``, so the slice that only imports it must not call it
        ``mod_N``: the model would meet one function under two names (E09-FU). A name bound by an
        import and called in the text is a function, or a class when it is written in PascalCase,
        which is how every supported language marks a constructor. The convention is a heuristic;
        an exact kind needs the definition (``ParseIndex.definition_of``), which this module
        does not see.
        """
        if symbol.kind != "import" or symbol.is_definition or self._root is None:
            return symbol.kind
        start = self._start_of(index)
        if start < 0:
            return symbol.kind
        end = start + len(symbol.name)
        while end < len(self._source) and self._source[end] in " 	":
            end += 1
        if end >= len(self._source) or self._source[end] != "(":
            return symbol.kind
        first = symbol.name[:1]
        return "class" if first.isupper() and not symbol.name.isupper() else "function"

    def _callee_at(self, paren: int) -> int | None:
        """The symbol of the callee whose name ends just before the ``(`` at ``paren``."""
        end = paren
        while end > 0 and self._source[end - 1] in " \t":
            end -= 1
        return self._by_end.get(end)

    def _keyword(self, index: int, symbol: Symbol) -> _Verdict:
        paren, _ = self._enclosing_paren(self._start_of(index))
        callee_index = None if paren is None else self._callee_at(paren)
        if callee_index is None:
            return _Verdict(
                IdentifierClass.INTERNAL, Rule.KEYWORD_OF_INTERNAL, depends_on_table=True
            )
        target = self.verdict(callee_index)
        if target.classification is not IdentifierClass.PUBLIC:
            return _Verdict(
                IdentifierClass.INTERNAL, Rule.KEYWORD_OF_INTERNAL, depends_on_table=True
            )
        if any(symbol.name in self._allowlist.members_of(p) for p in target.packages):
            return _Verdict(
                IdentifierClass.PUBLIC,
                Rule.KEYWORD_OF_PUBLIC,
                target.packages,
                depends_on_table=True,
            )
        return _Verdict(IdentifierClass.INTERNAL, Rule.KEYWORD_NOT_LISTED, depends_on_table=True)

    def _tree(self) -> _TreeContext | None:
        if self._root is None:
            return None
        if self._tree_context is None:
            self._tree_context = _TreeContext(self._root)
        return self._tree_context

    def _serialised(self, index: int, symbol: Symbol) -> frozenset[ClassificationNote]:
        """``SERIALISATION_FIELD`` for a field of a dataclass or a schema class (Python)."""
        if self._language is not Language.PYTHON or symbol.kind not in _FIELD_KINDS:
            return _NO_NOTES
        context = self._tree()
        node = None if context is None else context.node_for(symbol.location, symbol.name)
        for _ in range(_MAX_CLASS_DEPTH):
            if node is None or node.type == "class_definition":
                break
            node = node.parent
        if node is None or node.type != "class_definition":
            return _NO_NOTES
        if self._is_serialised_class(node):
            return frozenset({ClassificationNote.SERIALISATION_FIELD})
        return _NO_NOTES

    @staticmethod
    def _is_serialised_class(node: Node) -> bool:
        parent = node.parent
        if parent is not None and parent.type == "decorated_definition":
            for child in parent.named_children:
                if child.type == "decorator" and b"dataclass" in (child.text or b""):
                    return True
        supers = node.child_by_field_name("superclasses")
        text = (supers.text or b"").decode("utf-8", errors="replace") if supers else ""
        return any(base in text for base in _SERIALISED_BASES)

    # --- dynamic names and the whole file ----------------------------------------------------

    def _is_reflective_callee(self, paren: int) -> bool:
        """Whether the call whose ``(`` is at ``paren`` is an attribute-name reflection call."""
        callee = self._callee_at(paren)
        if callee is None:
            return False
        symbol = self._symbols[callee]
        if symbol.scope_id == UNRESOLVED and symbol.kind == "field":
            base = self._member_base(callee)
            base_name = "" if base is None else self._symbols[base].name
            return self._allowlist.is_reflection_method(
                base_name, symbol.name
            ) or self._allowlist.is_attribute_call(symbol.name)
        return symbol.scope_id == UNRESOLVED and self._allowlist.is_attribute_call(symbol.name)

    def _dynamic_literals(self, names: set[str]) -> set[str]:
        """Names that a string literal refers to: attribute-call arguments and literal subscripts.

        A literal is looked at only when it could matter: it is an identifier that names something
        in this file (a subscript), or the file calls a reflection function.
        """
        if self._root is None or self._parsed is None:
            return set()
        found: set[str] = set()
        reflective = not self._allowlist.reflection_triggers().isdisjoint(names)
        source = self._source
        for span in self._parsed.string_literals():
            value = span.raw_text
            if not _identifier_like(value):
                continue
            if not reflective and value not in names:
                continue
            location = span.location
            start = self._offset(location.start_line, location.start_col)
            if start < 1 or source[start - 1] not in _QUOTES:
                continue
            before = start - 2
            while before >= 0 and source[before] in " \t":
                before -= 1
            if before < 0:
                continue
            previous = source[before]
            if previous == "[" and before >= 1 and _is_word(source[before - 1]):
                if value in names:
                    found.add(value)
            elif reflective and previous == ("," if self._allowlist.name_argument else "("):
                paren, commas = self._enclosing_paren(start - 1)
                if (
                    paren is not None
                    and commas == self._allowlist.name_argument
                    and self._is_reflective_callee(paren)
                ):
                    found.add(value)
        return found

    def run(self) -> ClassificationResult:
        symbols = self._symbols
        verdicts = [self.verdict(index) for index in range(len(symbols))]
        classes = [v.classification for v in verdicts]
        rules = [v.rule for v in verdicts]
        notes: dict[int, set[ClassificationNote]] = {
            index: set(v.notes) for index, v in enumerate(verdicts) if v.notes
        }

        if self._incomplete:
            for index, verdict in enumerate(verdicts):
                if verdict.depends_on_table and verdict.classification is IdentifierClass.PUBLIC:
                    classes[index] = IdentifierClass.INTERNAL
                    rules[index] = Rule.INCOMPLETE_TABLE
                    self._tally.incomplete_table += 1

        by_name: dict[str, list[int]] = {}
        dynamic_code = self._allowlist.is_dynamic_code_call
        for index, symbol in enumerate(symbols):
            by_name.setdefault(symbol.name, []).append(index)
            if (
                symbol.scope_id == UNRESOLVED
                and not symbol.is_definition
                and dynamic_code(symbol.name)
            ):
                notes.setdefault(index, set()).add(ClassificationNote.DYNAMIC_CODE)
                self._tally.dynamic_code += 1

        kept: set[str] = set()
        for name in sorted(self._dynamic_literals(set(by_name))):
            if self._name_level(name, listed=True) is not None:
                continue  # already public by its name; nothing to protect
            occurrences = by_name.get(name, [])
            bindings = {symbols[i].scope_id for i in occurrences}
            provable = (
                bool(occurrences)
                and len(bindings) == 1
                and UNRESOLVED not in bindings
                and any(symbols[i].is_definition for i in occurrences)
            )
            if provable:
                self._tally.dynamic_name_marked += 1
                for index in occurrences:
                    notes.setdefault(index, set()).add(ClassificationNote.DYNAMIC_NAME)
                continue
            kept.add(name)
            self._tally.kept_identifier += 1
            for index in occurrences:
                if classes[index] is IdentifierClass.INTERNAL:
                    classes[index] = IdentifierClass.PUBLIC
                    rules[index] = Rule.KEPT_DYNAMIC

        decisions = tuple(
            ClassificationDecision(
                symbol.name,
                self._kind_of(index, symbol),
                symbol.location,
                classes[index],
                rules[index],
                frozenset(notes[index]) if index in notes else _NO_NOTES,
            )
            for index, symbol in enumerate(symbols)
        )
        if self._incomplete:
            _log.debug("classify_incomplete_table", symbols=len(symbols))
        return ClassificationResult(
            decisions=decisions,
            counts=self._tally.freeze(),
            allowlist_version=self._allowlist.version(),
            kept_dynamic=frozenset(kept),
        )


class IdentifierClassifier:
    """Decides, for each occurrence of a symbol table, whether it is internal or public.

    Construct it with the symbol table of a file (imports attached by E07-04), the import resolver
    the table was built with, and the allowlist of the file's language. ``attach`` gives the
    classifier the parsed file, which enables the attribute-chain, keyword and dynamic-name rules;
    without it ``classify`` still works, conservatively. ``classify`` then answers for one symbol,
    and ``classify_file`` returns the whole ``ClassificationResult``.
    """

    def __init__(
        self, symbols: SymbolTable, imports: ImportResolver, allowlist: PublicAllowlist
    ) -> None:
        self._symbols = symbols
        self._imports = imports
        self._allowlist = allowlist
        self._parsed: ParsedFile | None = None
        self._result: ClassificationResult | None = None
        self._positions: dict[tuple[int, int, str], int] | None = None

    def attach(self, parsed: "ParsedFile") -> None:
        """Use ``parsed`` (the file the symbol table was built from) for the syntax-based rules."""
        self._parsed = parsed
        self._result = None

    def classify_file(self) -> ClassificationResult:
        """The decisions of every occurrence of the table, computed once."""
        if self._result is None:
            self._result = _Run(self._symbols, self._allowlist, self._parsed).run()
        return self._result

    def classify(self, symbol: Symbol) -> IdentifierClass:
        """The decision for ``symbol``; a symbol that is not in the table is INTERNAL."""
        if self._positions is None:
            self._positions = {
                (s.location.start_line, s.location.start_col or 0, s.name): position
                for position, s in enumerate(self._symbols.symbols)
            }
        key = (symbol.location.start_line, symbol.location.start_col or 0, symbol.name)
        index = self._positions.get(key)
        if index is None:
            _log.debug("classify_unknown_symbol")
            return IdentifierClass.INTERNAL
        return self.classify_file().decisions[index].classification


def classify_all(
    parsed: "ParsedFile",
    symbols: SymbolTable,
    *,
    allowlist: PublicAllowlist | None = None,
    imports: ImportResolver | None = None,
) -> ClassificationResult:
    """Classify every identifier occurrence of ``parsed``, whose symbol table is ``symbols``.

    ``allowlist`` defaults to the bundled allowlist of the file's language; pass one built with
    ``PublicAllowlist.from_settings`` to apply ``privacy.public_allowlist_extra``.

    Raises:
        NoAllowlistError: no allowlist is bundled for the file's language.
    """
    resolved = allowlist or PublicAllowlist.bundled(parsed.language)
    resolver = imports or DefaultImportResolver(parsed.language)
    classifier = IdentifierClassifier(symbols, resolver, resolved)
    classifier.attach(parsed)
    return classifier.classify_file()


__all__ = [
    "NAME_ONLY_RULES",
    "ClassificationDecision",
    "ClassificationNote",
    "ClassificationResult",
    "ConservativeCounts",
    "IdentifierClass",
    "IdentifierClassifier",
    "Rule",
    "classify_all",
]
