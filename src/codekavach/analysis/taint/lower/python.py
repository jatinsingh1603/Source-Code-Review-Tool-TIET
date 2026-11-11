"""The Python lowering (E17-01).

Owning epic: E17. Functions, methods, lambdas, comprehensions, assignments of every shape,
attribute and subscript access, calls, ``return``, ``yield``, ``raise``, ``if``, ``while``,
``for``, ``with`` and ``try``, f-strings, ``%`` and ``.format`` formatting, concatenation and
decorators. Anything else becomes ``Unknown`` carrying the names it mentions.

A subscript read is a call to ``<base>.__getitem__`` so that a source such as
``request.args["to"]`` is a call with a receiver, like ``request.args.get("to")``; a subscript
that is assigned to is a ``Place`` path ending in ``[*]``. Exceptions: every call in a ``try``
body has an edge to the dispatch block of its handlers; a ``finally`` body is lowered once, after
the normal flow and the handlers join, and exits that skip it are not modelled.
"""

from collections.abc import Callable, Sequence
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.taint.ir import (
    Assign,
    Branch,
    Call,
    Const,
    Expr,
    IRFunction,
    IRModule,
    Loop,
    Op,
    OpStyle,
    Place,
    Raise,
    Return,
    Unknown,
)
from codekavach.analysis.taint.lower.common import (
    Context,
    FunctionBuilder,
    Skip,
    any_index,
    const_of,
    mentions_of,
    unknown,
    with_step,
)
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable

VERSION: Final = "1"
IDENTIFIERS: Final = frozenset({"identifier"})
TRIVIA: Final = frozenset(
    {"comment", "pass_statement", "import_statement", "import_from_statement"}
)
SKIPPED_STATEMENTS: Final = frozenset(
    {"global_statement", "nonlocal_statement", "future_import_statement", "type_alias_statement"}
)
FUNCTIONS: Final = frozenset({"function_definition"})
COLLECTIONS: Final = frozenset({"list", "tuple", "set", "expression_list", "pattern_list"})
COMPREHENSIONS: Final = frozenset(
    {"list_comprehension", "set_comprehension", "generator_expression", "dictionary_comprehension"}
)
FORMAT_METHODS: Final = frozenset({"format", "format_map"})
TARGET_LISTS: Final = frozenset({"pattern_list", "tuple_pattern", "list_pattern", "tuple", "list"})


class _Function:
    """A function waiting to be lowered: its node, qualified name and decorators."""

    def __init__(self, node: Node, qualname: str, decorators: tuple[str, ...]) -> None:
        self.node = node
        self.qualname = qualname
        self.decorators = decorators


class PythonLowering:
    """Lowers a parsed Python file."""

    language: ClassVar[Language] = Language.PYTHON
    version: str = VERSION
    grammar_version: str

    def __init__(self, settings: TaintSettings | None = None) -> None:
        self.settings = settings or TaintSettings()
        from codekavach.parsing.loader import grammar_version  # noqa: PLC0415

        self.grammar_version = grammar_version(self.language)

    def lower(self, parsed: ParsedFile, symbols: SymbolTable) -> IRModule:
        """The functions of ``parsed``, the module body first; never raises on odd code."""
        if parsed.tree is None:
            return IRModule(
                path=parsed.path,
                language=self.language.value,
                lowering_version=VERSION,
                degraded_reason="no syntax tree",
            )
        ctx = Context(parsed, symbols, self.settings, self.language)
        root = parsed.tree.root_node
        queue: list[_Function] = []
        functions = [_Lowerer(ctx, queue).module(root)]
        while queue:
            pending = queue.pop(0)
            functions.append(_Lowerer(ctx, queue).function(pending))
        return IRModule(
            path=parsed.path,
            language=self.language.value,
            lowering_version=VERSION,
            functions=tuple(functions),
            degraded_reason="syntax errors in the file" if root.has_error else None,
        )


class _Lowerer:
    """Lowers one function body (or the module body) into a ``FunctionBuilder``."""

    def __init__(self, ctx: Context, queue: list[_Function]) -> None:
        self.ctx = ctx
        self.queue = queue
        self.b = FunctionBuilder(ctx)
        self.scope = ""
        self._used_dest = False

    # --- entry points ------------------------------------------------------------------------

    def module(self, root: Node) -> IRFunction:
        """The module body as a pseudo-function; definitions inside it are queued."""
        self.scope = ""
        try:
            self.statements(root.named_children)
            blocks = self.b.finish(root)
            skipped = None
        except Skip as stop:
            blocks, skipped = (), stop.reason
        return IRFunction(
            name="<module>",
            qualname="<module>",
            location=self.ctx.loc(root),
            blocks=blocks,
            node_count=self.b.nodes,
            degraded_reason="syntax errors in the file" if root.has_error else None,
            skipped_reason=skipped,
        )

    def function(self, pending: _Function) -> IRFunction:
        """One queued function lowered on its own."""
        node = pending.node
        self.scope = pending.qualname
        name = self.ctx.text(node.child_by_field_name("name")) or "<lambda>"
        params = self.parameters(node.child_by_field_name("parameters"))
        blocks: tuple = ()  # type: ignore[type-arg]
        skipped = None
        try:
            self.b.tick(len(params))
            body = node.child_by_field_name("body")
            if body is not None and node.type == "lambda":
                self.return_value(body, node)
            elif body is not None:
                self.statements(body.named_children)
            blocks = self.b.finish(node)
        except Skip as stop:
            skipped = stop.reason
        return IRFunction(
            name=name,
            qualname=pending.qualname,
            params=params,
            decorators=pending.decorators,
            location=self.ctx.loc(node),
            blocks=blocks,
            node_count=self.b.nodes,
            degraded_reason="syntax error in the function" if node.has_error else None,
            skipped_reason=skipped,
        )

    def parameters(self, node: Node | None) -> tuple[str, ...]:
        """The parameter names, in order."""
        if node is None:
            return ()
        names: list[str] = []
        for child in node.named_children:
            target = child
            while target.type not in {"identifier"} and target.named_children:
                field = target.child_by_field_name("name")
                target = field if field is not None else target.named_children[0]
            if target.type == "identifier":
                names.append(self.ctx.text(target))
        return tuple(names)

    # --- statements --------------------------------------------------------------------------

    def statements(self, nodes: Sequence[Node]) -> None:
        for node in nodes:
            self.statement(node)

    def statement(self, node: Node) -> None:
        kind = node.type
        if kind in TRIVIA or kind in SKIPPED_STATEMENTS:
            return
        handler: Callable[[Node], object] | None = {
            "expression_statement": self.expression_statement,
            "return_statement": self.return_statement,
            "raise_statement": self.raise_statement,
            "if_statement": self.if_statement,
            "while_statement": self.while_statement,
            "for_statement": self.for_statement,
            "with_statement": self.with_statement,
            "try_statement": self.try_statement,
            "break_statement": self.break_statement,
            "continue_statement": self.continue_statement,
            "assert_statement": self.assert_statement,
            "function_definition": self.definition,
            "decorated_definition": self.definition,
            "class_definition": self.class_definition,
            "block": lambda n: self.statements(n.named_children),
        }.get(kind)
        if handler is not None:
            handler(node)
            return
        self.b.emit(unknown(node, self.ctx, IDENTIFIERS, kind))

    def expression_statement(self, node: Node) -> None:
        for child in node.named_children:
            if child.type == "assignment":
                self.assignment(child)
            elif child.type == "augmented_assignment":
                self.augmented(child)
            else:
                self.expr(child, discard=True)

    def assignment(self, node: Node) -> Place | None:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None:
            self.b.emit(unknown(node, self.ctx, IDENTIFIERS, "assignment"))
            return None
        if right is None:  # an annotation without a value defines nothing
            return None
        if right.type == "assignment":  # a = b = value
            inner = self.assignment(right)
            value: Expr = inner if inner is not None else const_of("other")
            self.assign_to(left, value, node)
            return self.target_place(left)
        if left.type in TARGET_LISTS:
            self.assign_to(left, self.expr(right), node)
            return None
        dest = self.target_place(left)
        self._used_dest = False
        value = self.expr(right, dest=dest)
        if not self._used_dest:
            self.b.emit(Assign(target=dest, value=value, location=self.ctx.loc(node)))
        return dest

    def target_place(self, node: Node) -> Place:
        """The place an assignment to ``node`` writes (a name, attribute path or ``x[*]``)."""
        if node.type == "identifier":
            return Place(base=self.ctx.text(node))
        if node.type == "attribute":
            owner = node.child_by_field_name("object")
            attr = self.ctx.text(node.child_by_field_name("attribute"))
            return with_step(self.place_of(owner), "." + attr, self.ctx)
        if node.type == "subscript":
            value = node.child_by_field_name("value")
            for index in node.children_by_field_name("subscript"):
                self.expr(index)
            return any_index(self.place_of(value), self.ctx)
        if node.type == "parenthesized_expression" and node.named_children:
            return self.target_place(node.named_children[0])
        if node.type in {"list_splat_pattern", "list_splat"} and node.named_children:
            return self.target_place(node.named_children[0])
        return self.b.temp()

    def assign_to(self, target: Node, value: Expr, node: Node) -> None:
        """Assign ``value`` to ``target``; unpacking gives every element the whole value."""
        if target.type in TARGET_LISTS:
            for element in target.named_children:
                self.assign_to(element, value, node)
            return
        self.b.emit(
            Assign(target=self.target_place(target), value=value, location=self.ctx.loc(node))
        )

    def augmented(self, node: Node) -> None:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            self.b.emit(unknown(node, self.ctx, IDENTIFIERS, "augmented_assignment"))
            return
        place = self.target_place(left)
        operator = self.ctx.text(node.child_by_field_name("operator")).removesuffix("=")
        value = Op(
            operator=operator,
            style="concat" if operator == "+" else "binary",
            operands=(place, self.expr(right)),
        )
        self.b.emit(Assign(target=place, value=value, location=self.ctx.loc(node)))

    def return_value(self, node: Node, anchor: Node) -> None:
        self.b.emit(Return(value=self.expr(node), location=self.ctx.loc(anchor)))

    def return_statement(self, node: Node) -> None:
        children = node.named_children
        value = self.expr(children[0]) if children else None
        self.b.emit(Return(value=value, location=self.ctx.loc(node)))

    def raise_statement(self, node: Node) -> None:
        children = node.named_children
        value = self.expr(children[0]) if children else None
        self.b.emit(Raise(value=value, handler=self.b.handler, location=self.ctx.loc(node)))

    def assert_statement(self, node: Node) -> None:
        for child in node.named_children:
            self.expr(child, discard=True)

    def break_statement(self, node: Node) -> None:
        if self.b.loops:
            self.b.goto(self.b.loops[-1][1])

    def continue_statement(self, node: Node) -> None:
        if self.b.loops:
            self.b.goto(self.b.loops[-1][0])

    def if_statement(self, node: Node) -> None:
        condition = node.child_by_field_name("condition")
        cond = self.expr(condition) if condition is not None else const_of("other")
        then_block, else_block, join = self.b.new_block(), self.b.new_block(), self.b.new_block()
        self.b.emit(
            Branch(
                condition=cond,
                then_block=then_block,
                else_block=else_block,
                location=self.ctx.loc(node),
            )
        )
        self.b.switch(then_block)
        consequence = node.child_by_field_name("consequence")
        if consequence is not None:
            self.statements(consequence.named_children)
        self.b.goto(join)
        self.b.switch(else_block)
        self.alternatives(node.children_by_field_name("alternative"), join)
        self.b.goto(join)
        self.b.switch(join)

    def alternatives(self, clauses: Sequence[Node], join: int) -> None:
        """The ``elif`` and ``else`` clauses of an ``if``, as nested conditionals."""
        if not clauses:
            return
        clause, rest = clauses[0], clauses[1:]
        if clause.type == "elif_clause":
            condition = clause.child_by_field_name("condition")
            cond = self.expr(condition) if condition is not None else const_of("other")
            then_block, else_block = self.b.new_block(), self.b.new_block()
            self.b.emit(
                Branch(
                    condition=cond,
                    then_block=then_block,
                    else_block=else_block,
                    location=self.ctx.loc(clause),
                )
            )
            self.b.switch(then_block)
            consequence = clause.child_by_field_name("consequence")
            if consequence is not None:
                self.statements(consequence.named_children)
            self.b.goto(join)
            self.b.switch(else_block)
            self.alternatives(rest, join)
        else:
            body = clause.child_by_field_name("body")
            self.statements(body.named_children if body is not None else clause.named_children)

    def loop(self, node: Node, header_work: object = None) -> tuple[int, int, int]:
        """Open a loop: the header block (already current) ends in ``Loop``; returns the ids."""
        raise NotImplementedError  # pragma: no cover - the two loop kinds are written out below

    def while_statement(self, node: Node) -> None:
        header, body_block, exit_block = self.b.new_block(), self.b.new_block(), self.b.new_block()
        self.b.goto(header)
        self.b.switch(header)
        condition = node.child_by_field_name("condition")
        if condition is not None:
            self.expr(condition, discard=True)
        self.b.emit(
            Loop(
                header_block=header,
                body_block=body_block,
                exit_block=exit_block,
                location=self.ctx.loc(node),
            )
        )
        self.b.switch(body_block)
        self.b.loops.append((header, exit_block))
        body = node.child_by_field_name("body")
        if body is not None:
            self.statements(body.named_children)
        self.b.loops.pop()
        self.b.goto(header)
        self.b.switch(exit_block)
        self.else_clause(node)

    def for_statement(self, node: Node) -> None:
        right, left = node.child_by_field_name("right"), node.child_by_field_name("left")
        iterable = self.expr(right) if right is not None else const_of("other")
        header, body_block, exit_block = self.b.new_block(), self.b.new_block(), self.b.new_block()
        self.b.goto(header)
        self.b.switch(header)
        self.b.emit(
            Loop(
                header_block=header,
                body_block=body_block,
                exit_block=exit_block,
                location=self.ctx.loc(node),
            )
        )
        self.b.switch(body_block)
        self.b.loops.append((header, exit_block))
        if left is not None:
            item = (
                any_index(iterable, self.ctx)
                if isinstance(iterable, Place)
                else Op(operator="iter", style="collection", operands=(iterable,))
            )
            self.assign_to(left, item, node)
        body = node.child_by_field_name("body")
        if body is not None:
            self.statements(body.named_children)
        self.b.loops.pop()
        self.b.goto(header)
        self.b.switch(exit_block)
        self.else_clause(node)

    def else_clause(self, node: Node) -> None:
        for clause in node.children_by_field_name("alternative"):
            body = clause.child_by_field_name("body")
            self.statements(body.named_children if body is not None else clause.named_children)

    def with_statement(self, node: Node) -> None:
        for clause in node.named_children:
            if clause.type != "with_clause":
                continue
            for item in clause.named_children:
                self.with_item(item)
        body = node.child_by_field_name("body")
        if body is not None:
            self.statements(body.named_children)

    def with_item(self, item: Node) -> None:
        value = item.child_by_field_name("value")
        if value is None and item.named_children:
            value = item.named_children[0]
        if value is None:
            return
        if value.type != "as_pattern":
            self.expr(value, discard=True)
            return
        parts = value.named_children
        alias = value.child_by_field_name("alias")
        target = alias.named_children[0] if alias is not None and alias.named_children else alias
        if not parts:
            return
        dest = self.target_place(target) if target is not None else None
        self._used_dest = False
        result = self.expr(parts[0], dest=dest)
        if dest is not None and not self._used_dest:
            self.b.emit(Assign(target=dest, value=result, location=self.ctx.loc(item)))

    def try_statement(self, node: Node) -> None:
        body = node.child_by_field_name("body")
        excepts = [
            c for c in node.named_children if c.type in {"except_clause", "except_group_clause"}
        ]
        finals = [c for c in node.named_children if c.type == "finally_clause"]
        elses = [c for c in node.named_children if c.type == "else_clause"]
        dispatch = self.b.new_block() if excepts else None
        handler_blocks = [self.b.new_block() for _ in excepts]
        final_block = self.b.new_block() if finals else None
        after = self.b.new_block()
        join = final_block if final_block is not None else after
        if dispatch is not None:
            self.b.handlers.append(dispatch)
        if body is not None:
            self.statements(body.named_children)
        if dispatch is not None:
            self.b.handlers.pop()
        for clause in elses:
            self.statements(self.block_of(clause))
        self.b.goto(join)
        if dispatch is not None:
            self.b.switch(dispatch)
            for index, block in enumerate(handler_blocks):
                if index == len(handler_blocks) - 1:
                    self.b.goto(block)
                else:
                    next_dispatch = self.b.new_block()
                    self.b.emit(
                        Branch(
                            condition=Unknown(reason="exception type"),
                            then_block=block,
                            else_block=next_dispatch,
                        )
                    )
                    self.b.switch(next_dispatch)
        for clause, block in zip(excepts, handler_blocks, strict=True):
            self.b.switch(block)
            self.except_clause(clause)
            self.b.goto(join)
        if final_block is not None:
            self.b.switch(final_block)
            for clause in finals:
                self.statements(self.block_of(clause))
            self.b.goto(after)
        self.b.switch(after)

    def except_clause(self, clause: Node) -> None:
        for child in clause.named_children:
            if child.type == "as_pattern":
                alias = child.child_by_field_name("alias")
                name = (
                    alias.named_children[0] if alias is not None and alias.named_children else alias
                )
                if name is not None:
                    self.b.emit(
                        Assign(
                            target=self.target_place(name),
                            value=const_of("other"),
                            location=self.ctx.loc(clause),
                        )
                    )
        self.statements(self.block_of(clause))

    @staticmethod
    def block_of(clause: Node) -> list[Node]:
        for child in clause.named_children:
            if child.type == "block":
                return list(child.named_children)
        return []

    def definition(self, node: Node) -> None:
        decorators: list[str] = []
        target = node
        if node.type == "decorated_definition":
            decorators = [
                self.ctx.text(c).lstrip("@").strip()
                for c in node.named_children
                if c.type == "decorator"
            ]
            definition = node.child_by_field_name("definition")
            if definition is None:
                return
            target = definition
        if target.type == "class_definition":
            self.class_definition(target)
            return
        name = self.ctx.text(target.child_by_field_name("name"))
        qualname = f"{self.scope}.{name}" if self.scope else name
        self.queue.append(_Function(target, qualname, tuple(decorators)))

    def class_definition(self, node: Node) -> None:
        name = self.ctx.text(node.child_by_field_name("name"))
        previous = self.scope
        self.scope = f"{previous}.{name}" if previous else name
        body = node.child_by_field_name("body")
        if body is not None:
            self.statements(body.named_children)
        self.scope = previous

    # --- expressions -------------------------------------------------------------------------

    def place_of(self, node: Node | None) -> Place:
        """The access path of an expression; anything else is evaluated into a temporary."""
        if node is None:
            return self.b.temp()
        if node.type == "identifier":
            return Place(base=self.ctx.text(node))
        if node.type == "attribute":
            attr = self.ctx.text(node.child_by_field_name("attribute"))
            return with_step(
                self.place_of(node.child_by_field_name("object")), "." + attr, self.ctx
            )
        if node.type == "parenthesized_expression" and node.named_children:
            return self.place_of(node.named_children[0])
        value = self.expr(node)
        if isinstance(value, Place):
            return value
        temp = self.b.temp()
        self.b.emit(Assign(target=temp, value=value, location=self.ctx.loc(node)))
        return temp

    def expr(self, node: Node, dest: Place | None = None, discard: bool = False) -> Expr:  # noqa: PLR0911, PLR0912
        """Lower an expression; calls are emitted as statements and referred to by their result."""
        self.b.tick()
        kind = node.type
        if kind == "identifier":
            return Place(base=self.ctx.text(node))
        if kind == "attribute":
            return self.place_of(node)
        if kind == "call":
            return self.call(node, dest, discard)
        if kind == "subscript":
            return self.subscript(node, dest)
        if kind in {"string", "concatenated_string"}:
            return self.string(node)
        if kind in {"integer", "float"}:
            return const_of("int")
        if kind in {"true", "false"}:
            return const_of("bool")
        if kind == "none":
            return const_of("none")
        if kind == "binary_operator":
            return self.binary(node)
        if kind in {"parenthesized_expression", "await", "list_splat", "dictionary_splat"}:
            inner = node.named_children
            return self.expr(inner[0], dest, discard) if inner else const_of("other")
        if kind == "named_expression":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is None or value is None:
                return unknown(node, self.ctx, IDENTIFIERS, kind)
            place = Place(base=self.ctx.text(name))
            self.b.emit(Assign(target=place, value=self.expr(value), location=self.ctx.loc(node)))
            return place
        if kind in {
            "boolean_operator",
            "comparison_operator",
            "not_operator",
            "unary_operator",
            "conditional_expression",
        }:
            operands = tuple(self.expr(c) for c in node.named_children)
            style: OpStyle = "compare" if kind == "comparison_operator" else "bool"
            return Op(
                operator=kind,
                style="unary" if kind == "unary_operator" else style,
                operands=operands,
            )
        if kind in COLLECTIONS or kind == "dictionary":
            return Op(
                operator=kind,
                style="collection",
                operands=tuple(self.expr(c) for c in node.named_children),
            )
        if kind == "pair":
            return Op(
                operator="pair",
                style="collection",
                operands=tuple(self.expr(c) for c in node.named_children),
            )
        if kind in COMPREHENSIONS:
            return self.comprehension(node)
        if kind == "lambda":
            self.queue.append(_Function(node, f"{self.scope}.<lambda>".lstrip("."), ()))
            return const_of("other", "lambda")
        if kind == "yield":
            inner = node.named_children
            self.b.emit(
                Assign(
                    target=Place(base="$yield"),
                    value=self.expr(inner[0]) if inner else const_of("none"),
                    location=self.ctx.loc(node),
                )
            )
            return const_of("other")
        if kind in {"ellipsis", "type", "slice"}:
            return const_of("other")
        return unknown(node, self.ctx, IDENTIFIERS, kind)

    def call(self, node: Node, dest: Place | None, discard: bool) -> Expr:
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        receiver: Place | None = None
        if function is not None and function.type == "attribute":
            receiver = self.place_of(function.child_by_field_name("object"))
        args: list[Expr] = []
        kwargs: list[tuple[str, Expr]] = []
        if arguments is not None and arguments.type == "argument_list":
            for argument in arguments.named_children:
                if argument.type == "keyword_argument":
                    value = argument.child_by_field_name("value")
                    name = self.ctx.text(argument.child_by_field_name("name"))
                    kwargs.append(
                        (name, self.expr(value) if value is not None else const_of("other"))
                    )
                elif argument.type != "comment":
                    args.append(self.expr(argument))
        elif arguments is not None:
            args.append(self.expr(arguments))
        text = self.ctx.text(function)
        result = None if discard else (dest if dest is not None else self.b.temp())
        if dest is not None and not discard:
            self._used_dest = True
        self.b.emit(
            Call(
                callee=self.ctx.callee(function, text),
                args=tuple(args),
                kwargs=tuple(kwargs),
                result=result,
                receiver=receiver,
                handler=self.b.handler,
                location=self.ctx.loc(node),
            )
        )
        return result if result is not None else const_of("none")

    def subscript(self, node: Node, dest: Place | None) -> Expr:
        value = node.child_by_field_name("value")
        base = self.place_of(value)
        indexes = tuple(self.expr(i) for i in node.children_by_field_name("subscript"))
        result = dest if dest is not None else self.b.temp()
        if dest is not None:
            self._used_dest = True
        self.b.emit(
            Call(
                callee=self.ctx.callee(None, f"{base.text}.__getitem__"),
                args=indexes,
                result=result,
                receiver=base,
                handler=self.b.handler,
                location=self.ctx.loc(node),
            )
        )
        return result

    def string(self, node: Node) -> Expr:
        if node.type == "concatenated_string":
            parts = tuple(self.string(c) for c in node.named_children)
            return Op(operator="+", style="concat", operands=parts)
        interpolations = [c for c in node.named_children if c.type == "interpolation"]
        text = "".join(self.ctx.text(c) for c in node.named_children if c.type == "string_content")
        if not interpolations:
            return const_of("str", self.ctx.shape(text))
        operands: list[Expr] = []
        for child in node.named_children:
            if child.type == "string_content":
                operands.append(const_of("str", self.ctx.shape(self.ctx.text(child))))
            elif child.type == "interpolation":
                inner = child.child_by_field_name("expression")
                operands.append(self.expr(inner) if inner is not None else const_of("other"))
        return Op(operator="f", style="fstring", operands=tuple(operands))

    def binary(self, node: Node) -> Expr:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        operator = self.ctx.text(node.child_by_field_name("operator"))
        if left is None or right is None:
            return unknown(node, self.ctx, IDENTIFIERS, "binary_operator")
        lhs, rhs = self.expr(left), self.expr(right)
        if operator == "+" and (self.stringish(lhs) or self.stringish(rhs)):
            operands: list[Expr] = []
            for side in (lhs, rhs):
                if isinstance(side, Op) and side.style == "concat":
                    operands.extend(side.operands)
                else:
                    operands.append(side)
            return Op(operator="+", style="concat", operands=tuple(operands))
        if operator == "%" and isinstance(lhs, Const) and lhs.kind == "str":
            return Op(operator="%", style="format", operands=(lhs, rhs))
        return Op(operator=operator, style="binary", operands=(lhs, rhs))

    @staticmethod
    def stringish(value: Expr) -> bool:
        return (isinstance(value, Const) and value.kind == "str") or (
            isinstance(value, Op) and value.is_string
        )

    def comprehension(self, node: Node) -> Expr:
        operands: list[Expr] = []
        for clause in node.named_children:
            if clause.type == "for_in_clause":
                left, right = (
                    clause.child_by_field_name("left"),
                    clause.child_by_field_name("right"),
                )
                if left is not None and right is not None:
                    iterable = self.expr(right)
                    item = (
                        any_index(iterable, self.ctx)
                        if isinstance(iterable, Place)
                        else Op(operator="iter", style="collection", operands=(iterable,))
                    )
                    self.assign_to(left, item, clause)
            elif clause.type == "if_clause":
                for child in clause.named_children:
                    self.expr(child, discard=True)
        body = node.child_by_field_name("body")
        if body is not None:
            operands.append(self.expr(body))
        return Op(operator="comprehension", style="collection", operands=tuple(operands))


__all__ = ["PythonLowering", "mentions_of"]
