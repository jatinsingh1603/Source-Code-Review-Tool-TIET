"""A small, language-neutral intermediate representation for taint analysis (E17-01).

Owning epic: E17. ``docs/ARCHITECTURE.md`` section 2 makes tree-sitter the only parsing layer: it
gives syntax, with no name resolution and no types. Taint analysis needs explicit assignments,
calls, returns and branches, so each function is lowered into the nodes below, grouped in basic
blocks. The representation is deliberately small and must not grow into a compiler IR: anything a
lowering cannot express becomes ``Unknown`` and is treated conservatively.

Statements (one per instruction, the last of a block is a terminator): ``Assign``, ``Call``,
``Return``, ``Branch``, ``Loop``, ``Goto``, ``Raise``, ``Unknown``. Expressions: ``Place``,
``Const``, ``Op`` and ``Unknown``. ``Phi`` is analysis machinery created by ``defuse``, never by a
lowering, and never part of a path shown to a reader.

Everything here is client data (symbols, literals, locations): ``DATA_CLASSIFICATION`` is
``RAW`` and nothing in this package may be reachable from ``codekavach.llm`` (invariant I2).
``Const.shape`` keeps the skeleton of a string, not its text.
"""

from typing import ClassVar, Final, Literal

from pydantic import Field

from codekavach.core.models import DataClassification, KavachModel, Location

ANY_INDEX: Final = "[*]"
MAX_SHAPE: Final = 200
UNKNOWN_FUNCTION: Final = "<unknown>"
MODULE_FUNCTION: Final = "<module>"

ConstKind = Literal["str", "int", "bool", "none", "regex", "other"]
OpStyle = Literal[
    "concat", "fstring", "format", "template", "binary", "unary", "compare", "bool", "collection"
]


class _IRModel(KavachModel):
    """Base of every node: frozen, raw client data."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW


class Place(_IRModel):
    """A bounded access path: a base symbol and attribute or index steps.

    A step is ``.name`` or ``[*]`` (any index). ``truncated`` marks a path cut at
    ``taint.max_access_path``; a truncated path matches any extension of itself, which errs
    towards false positives rather than false negatives.
    """

    op: Literal["place"] = "place"
    base: str
    steps: tuple[str, ...] = ()
    truncated: bool = False

    @property
    def text(self) -> str:
        """The path as written, ``a.b[*]``; a truncated path ends in ``...``."""
        return self.base + "".join(self.steps) + ("..." if self.truncated else "")

    def extend(self, step: str, limit: int) -> "Place":
        """This path one step longer, or this path marked truncated when it is at ``limit``."""
        if self.truncated:
            return self
        if len(self.steps) >= limit:
            return self.model_copy(update={"truncated": True})
        return self.model_copy(update={"steps": (*self.steps, step)})

    def related(self, other: "Place") -> bool:
        """Whether one path is a prefix of the other (the pair can denote the same storage)."""
        if self.base != other.base:
            return False
        shared = min(len(self.steps), len(other.steps))
        return self.steps[:shared] == other.steps[:shared]

    def strong(self) -> bool:
        """Whether an assignment to this path replaces what it held (no unknown index, no cut)."""
        return not self.truncated and ANY_INDEX not in self.steps


class Const(_IRModel):
    """A literal. ``shape`` is the skeleton of a string (its text with values blanked)."""

    op: Literal["const"] = "const"
    kind: ConstKind
    shape: str | None = Field(default=None, max_length=MAX_SHAPE)


class Op(_IRModel):
    """A value computed from ``operands``: string building, arithmetic, a collection literal."""

    op: Literal["op"] = "op"
    operator: str
    style: OpStyle
    operands: tuple["Expr", ...] = ()

    @property
    def is_string(self) -> bool:
        """True for concatenation, f-strings, formatting and templates."""
        return self.style in {"concat", "fstring", "format", "template"}


class Unknown(_IRModel):
    """A construct the lowering does not express. Conservative: it defines and uses ``mentions``."""

    op: Literal["unknown"] = "unknown"
    mentions: tuple[Place, ...] = ()
    reason: str = ""
    location: Location | None = None


Expr = Place | Const | Op | Unknown
Op.model_rebuild()


class CalleeRef(_IRModel):
    """What a call names: the resolved dotted symbol when the symbol table gives one."""

    text: str = Field(max_length=512)
    symbol: str | None = Field(default=None, max_length=512)


class Assign(_IRModel):
    """``target = value``."""

    op: Literal["assign"] = "assign"
    target: Place
    value: Expr
    location: Location


class Call(_IRModel):
    """A call. ``handler`` is the first block of the enclosing ``try`` handlers, if any."""

    op: Literal["call"] = "call"
    callee: CalleeRef
    args: tuple[Expr, ...] = ()
    kwargs: tuple[tuple[str, Expr], ...] = ()
    result: Place | None = None
    receiver: Place | None = None
    handler: int | None = None
    location: Location


class Return(_IRModel):
    """``return value``; ``implicit`` for the fall-off-the-end return a lowering adds."""

    op: Literal["return"] = "return"
    value: Expr | None = None
    implicit: bool = False
    location: Location | None = None


class Branch(_IRModel):
    """Two-way conditional; a terminator."""

    op: Literal["branch"] = "branch"
    condition: Expr
    then_block: int
    else_block: int
    location: Location | None = None


class Loop(_IRModel):
    """A loop header: ``body_block`` while the loop runs, ``exit_block`` when it ends."""

    op: Literal["loop"] = "loop"
    header_block: int
    body_block: int
    exit_block: int
    location: Location | None = None


class Goto(_IRModel):
    """An unconditional jump; a loop's back edge is a ``Goto`` to its header."""

    op: Literal["goto"] = "goto"
    target: int


class Raise(_IRModel):
    """``raise`` or ``throw``; flows to the handler, or leaves the function."""

    op: Literal["raise"] = "raise"
    value: Expr | None = None
    handler: int | None = None
    location: Location | None = None


class Phi(_IRModel):
    """Where several definitions of ``place`` meet. Created by ``defuse`` only."""

    op: Literal["phi"] = "phi"
    place: Place
    block: int
    sources: tuple[int, ...] = ()


Stmt = Assign | Call | Return | Branch | Loop | Goto | Raise | Unknown
TERMINATORS: Final = (Return, Branch, Loop, Goto, Raise)


class IRBlock(_IRModel):
    """Straight-line statements ending in a terminator. Ids are assigned in source order."""

    id: int
    stmts: tuple[Stmt, ...] = ()


class IRFunction(_IRModel):
    """One lowered function, method, lambda or the module body."""

    name: str = Field(max_length=512)
    qualname: str = Field(max_length=1024)
    params: tuple[str, ...] = ()
    decorators: tuple[str, ...] = ()
    location: Location
    blocks: tuple[IRBlock, ...] = ()
    node_count: int = 0
    degraded_reason: str | None = None
    skipped_reason: str | None = None

    @property
    def is_analysed(self) -> bool:
        """False for a function the size caps skipped."""
        return self.skipped_reason is None


class IRModule(_IRModel):
    """The lowered functions of one file, in source order, the module body first."""

    path: str
    language: str
    lowering_version: str
    functions: tuple[IRFunction, ...] = ()
    degraded_reason: str | None = None

    def function(self, qualname: str) -> IRFunction | None:
        """The function with this qualified name, or ``None``."""
        return next((f for f in self.functions if f.qualname == qualname), None)
