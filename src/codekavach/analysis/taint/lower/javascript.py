"""The JavaScript and TypeScript lowering (E17-01).

Owning epic: E17. Functions, arrow functions, methods, ``var``/``let``/``const`` with
destructuring, assignment, member and index access, calls and ``new``, template strings,
concatenation, ``return``, ``throw``, ``if``, ``while``, ``do``, ``for``, ``for..of``/``in``,
``switch`` and ``try``. Callback arguments that are functions are queued as functions of their own,
named ``<outer>.<callback>`` in source order. Anything else is ``Unknown``.

As in the Python lowering, an index read is a call to ``<base>.__getitem__``.
"""

from collections.abc import Callable, Sequence
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.taint.ir import (
    Assign,
    Branch,
    Call,
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
    unknown,
    with_step,
)
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable

VERSION: Final = "1"
IDENTIFIERS: Final = frozenset({"identifier", "shorthand_property_identifier"})
FUNCTION_TYPES: Final = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    }
)
TRIVIA: Final = frozenset(
    {
        "comment",
        "import_statement",
        "empty_statement",
        "interface_declaration",
        "type_alias_declaration",
        "enum_declaration",
    }
)
PATTERNS: Final = frozenset({"object_pattern", "array_pattern"})


class _Pending:
    def __init__(self, node: Node, qualname: str) -> None:
        self.node = node
        self.qualname = qualname


class JavaScriptLowering:
    """Lowers a parsed JavaScript or TypeScript file."""

    language: ClassVar[Language] = Language.JAVASCRIPT
    version: str = VERSION
    grammar_version: str

    def __init__(
        self, settings: TaintSettings | None = None, language: Language | None = None
    ) -> None:
        self.settings = settings or TaintSettings()
        self._language = language or Language.JAVASCRIPT
        from codekavach.parsing.loader import grammar_version  # noqa: PLC0415

        self.grammar_version = grammar_version(self._language)

    def lower(self, parsed: ParsedFile, symbols: SymbolTable) -> IRModule:
        """The functions of ``parsed``, the module body first; never raises on odd code."""
        if parsed.tree is None:
            return IRModule(
                path=parsed.path,
                language=self._language.value,
                lowering_version=VERSION,
                degraded_reason="no syntax tree",
            )
        ctx = Context(parsed, symbols, self.settings, self._language)
        root = parsed.tree.root_node
        queue: list[_Pending] = []
        functions = [_Lowerer(ctx, queue).module(root)]
        while queue:
            functions.append(_Lowerer(ctx, queue).function(queue.pop(0)))
        return IRModule(
            path=parsed.path,
            language=self._language.value,
            lowering_version=VERSION,
            functions=tuple(functions),
            degraded_reason="syntax errors in the file" if root.has_error else None,
        )


class _Lowerer:
    def __init__(self, ctx: Context, queue: list[_Pending]) -> None:
        self.ctx = ctx
        self.queue = queue
        self.b = FunctionBuilder(ctx)
        self.scope = ""
        self._used_dest = False
        self._callbacks = 0

    def module(self, root: Node) -> IRFunction:
        try:
            self.statements(root.named_children)
            blocks, skipped = self.b.finish(root), None
        except Skip as stop:
            blocks, skipped = (), stop.reason
        return IRFunction(
            name="<module>",
            qualname="<module>",
            location=self.ctx.loc(root),
            blocks=blocks,
            node_count=self.b.nodes,
            skipped_reason=skipped,
            degraded_reason="syntax errors in the file" if root.has_error else None,
        )

    def function(self, pending: _Pending) -> IRFunction:
        node = pending.node
        self.scope = pending.qualname
        name = (
            self.ctx.text(node.child_by_field_name("name")) or pending.qualname.rsplit(".", 1)[-1]
        )
        params = self.parameters(node)
        blocks: tuple = ()  # type: ignore[type-arg]
        skipped = None
        try:
            body = node.child_by_field_name("body")
            if body is not None and body.type == "statement_block":
                self.statements(body.named_children)
            elif body is not None:
                self.b.emit(Return(value=self.expr(body), location=self.ctx.loc(node)))
            blocks = self.b.finish(node)
        except Skip as stop:
            skipped = stop.reason
        return IRFunction(
            name=name,
            qualname=pending.qualname,
            params=params,
            location=self.ctx.loc(node),
            blocks=blocks,
            node_count=self.b.nodes,
            skipped_reason=skipped,
            degraded_reason="syntax error in the function" if node.has_error else None,
        )

    def parameters(self, node: Node) -> tuple[str, ...]:
        holder = node.child_by_field_name("parameters")
        single = node.child_by_field_name("parameter")
        names: list[str] = []
        for param in (holder.named_children if holder is not None else []) + (
            [single] if single else []
        ):
            names.extend(self.pattern_names(param))
        return tuple(names)

    def pattern_names(self, node: Node) -> list[str]:
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            return [self.ctx.text(node)]
        found: list[str] = []
        for child in node.named_children:
            if child.type in {"type_annotation", "comment"}:
                continue
            found.extend(self.pattern_names(child))
        return found

    # --- statements --------------------------------------------------------------------------

    def statements(self, nodes: Sequence[Node]) -> None:
        for node in nodes:
            self.statement(node)

    def statement(self, node: Node) -> None:
        kind = node.type
        if kind in TRIVIA:
            return
        handler: Callable[[Node], object] | None = {
            "expression_statement": lambda n: [
                self.expr(c, discard=True) for c in n.named_children
            ],
            "lexical_declaration": self.declaration,
            "variable_declaration": self.declaration,
            "return_statement": self.return_statement,
            "throw_statement": self.throw_statement,
            "if_statement": self.if_statement,
            "while_statement": self.while_statement,
            "do_statement": self.do_statement,
            "for_statement": self.for_statement,
            "for_in_statement": self.for_in_statement,
            "switch_statement": self.switch_statement,
            "try_statement": self.try_statement,
            "break_statement": lambda n: self.jump(1),
            "continue_statement": lambda n: self.jump(0),
            "statement_block": lambda n: self.statements(n.named_children),
            "function_declaration": self.defer_function,
            "generator_function_declaration": self.defer_function,
            "class_declaration": self.class_declaration,
            "export_statement": lambda n: self.statements(n.named_children),
            "labeled_statement": lambda n: self.statements(n.named_children[1:]),
        }.get(kind)
        if handler is None:
            self.b.emit(unknown(node, self.ctx, IDENTIFIERS, kind))
            return
        handler(node)

    def jump(self, which: int) -> None:
        if self.b.loops:
            self.b.goto(self.b.loops[-1][which])

    def defer_function(self, node: Node) -> None:
        name = self.ctx.text(node.child_by_field_name("name"))
        self.queue.append(_Pending(node, f"{self.scope}.{name}" if self.scope else name))

    def class_declaration(self, node: Node) -> None:
        name = self.ctx.text(node.child_by_field_name("name"))
        previous = self.scope
        self.scope = f"{previous}.{name}" if previous else name
        body = node.child_by_field_name("body")
        for member in body.named_children if body is not None else []:
            if member.type == "method_definition":
                method = self.ctx.text(member.child_by_field_name("name"))
                self.queue.append(_Pending(member, f"{self.scope}.{method}"))
        self.scope = previous

    def declaration(self, node: Node) -> None:
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name, value = (
                declarator.child_by_field_name("name"),
                declarator.child_by_field_name("value"),
            )
            if name is None or value is None:
                continue
            self.assign_into(name, value, declarator)

    def assign_into(self, target: Node, value: Node, anchor: Node) -> None:
        if target.type in PATTERNS:
            result = self.expr(value)
            for pname in self.pattern_names(target):
                self.b.emit(
                    Assign(target=Place(base=pname), value=result, location=self.ctx.loc(anchor))
                )
            return
        dest = self.target_place(target)
        self._used_dest = False
        result = self.expr(value, dest=dest)
        if not self._used_dest:
            self.b.emit(Assign(target=dest, value=result, location=self.ctx.loc(anchor)))

    def target_place(self, node: Node) -> Place:
        if node.type == "identifier":
            return Place(base=self.ctx.text(node))
        if node.type == "member_expression":
            prop = self.ctx.text(node.child_by_field_name("property"))
            return with_step(
                self.place_of(node.child_by_field_name("object")), "." + prop, self.ctx
            )
        if node.type == "subscript_expression":
            index = node.child_by_field_name("index")
            if index is not None:
                self.expr(index, discard=True)
            return any_index(self.place_of(node.child_by_field_name("object")), self.ctx)
        if (
            node.type in {"parenthesized_expression", "non_null_expression", "as_expression"}
            and node.named_children
        ):
            return self.target_place(node.named_children[0])
        return self.b.temp()

    def return_statement(self, node: Node) -> None:
        children = node.named_children
        self.b.emit(
            Return(value=self.expr(children[0]) if children else None, location=self.ctx.loc(node))
        )

    def throw_statement(self, node: Node) -> None:
        children = node.named_children
        self.b.emit(
            Raise(
                value=self.expr(children[0]) if children else None,
                handler=self.b.handler,
                location=self.ctx.loc(node),
            )
        )

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
            self.statement(consequence)
        self.b.goto(join)
        self.b.switch(else_block)
        alternative = node.child_by_field_name("alternative")
        if alternative is not None:
            self.statements(alternative.named_children)
        self.b.goto(join)
        self.b.switch(join)

    def open_loop(self, node: Node) -> tuple[int, int, int]:
        header, body_block, exit_block = self.b.new_block(), self.b.new_block(), self.b.new_block()
        self.b.goto(header)
        self.b.switch(header)
        return header, body_block, exit_block

    def close_header(self, node: Node, header: int, body_block: int, exit_block: int) -> None:
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

    def end_loop(self, header: int, exit_block: int) -> None:
        self.b.loops.pop()
        self.b.goto(header)
        self.b.switch(exit_block)

    def while_statement(self, node: Node) -> None:
        header, body_block, exit_block = self.open_loop(node)
        condition = node.child_by_field_name("condition")
        if condition is not None:
            self.expr(condition, discard=True)
        self.close_header(node, header, body_block, exit_block)
        body = node.child_by_field_name("body")
        if body is not None:
            self.statement(body)
        self.end_loop(header, exit_block)

    def do_statement(self, node: Node) -> None:
        header, body_block, exit_block = self.open_loop(node)
        self.close_header(node, header, body_block, exit_block)
        body = node.child_by_field_name("body")
        if body is not None:
            self.statement(body)
        condition = node.child_by_field_name("condition")
        if condition is not None:
            self.expr(condition, discard=True)
        self.end_loop(header, exit_block)

    def for_statement(self, node: Node) -> None:
        initializer = node.child_by_field_name("initializer")
        if initializer is not None:
            self.statement(initializer)
        header, body_block, exit_block = self.open_loop(node)
        condition = node.child_by_field_name("condition")
        if condition is not None and condition.type != "empty_statement":
            for child in condition.named_children or [condition]:
                self.expr(child, discard=True)
        self.close_header(node, header, body_block, exit_block)
        body = node.child_by_field_name("body")
        if body is not None:
            self.statement(body)
        increment = node.child_by_field_name("increment")
        if increment is not None:
            self.expr(increment, discard=True)
        self.end_loop(header, exit_block)

    def for_in_statement(self, node: Node) -> None:
        right, left = node.child_by_field_name("right"), node.child_by_field_name("left")
        iterable = self.expr(right) if right is not None else const_of("other")
        header, body_block, exit_block = self.open_loop(node)
        self.close_header(node, header, body_block, exit_block)
        if left is not None:
            item = (
                any_index(iterable, self.ctx)
                if isinstance(iterable, Place)
                else Op(operator="iter", style="collection", operands=(iterable,))
            )
            for name in self.pattern_names(left):
                self.b.emit(
                    Assign(target=Place(base=name), value=item, location=self.ctx.loc(node))
                )
        body = node.child_by_field_name("body")
        if body is not None:
            self.statement(body)
        self.end_loop(header, exit_block)

    def switch_statement(self, node: Node) -> None:
        value = node.child_by_field_name("value")
        if value is not None:
            self.expr(value, discard=True)
        body = node.child_by_field_name("body")
        cases = list(body.named_children) if body is not None else []
        end = self.b.new_block()
        self.b.loops.append((end, end))
        blocks = [self.b.new_block() for _ in cases]
        for index, block in enumerate(blocks):
            nxt = self.b.new_block() if index < len(blocks) - 1 else end
            self.b.emit(Branch(condition=Unknown(reason="case"), then_block=block, else_block=nxt))
            if nxt != end:
                self.b.switch(nxt)
        if not blocks:
            self.b.goto(end)
        for index, (case, block) in enumerate(zip(cases, blocks, strict=True)):
            self.b.switch(block)
            self.statements(case.children_by_field_name("body"))
            self.b.goto(blocks[index + 1] if index + 1 < len(blocks) else end)
        self.b.loops.pop()
        self.b.switch(end)

    def try_statement(self, node: Node) -> None:
        body = node.child_by_field_name("body")
        catch = node.child_by_field_name("handler")
        final = node.child_by_field_name("finalizer")
        dispatch = self.b.new_block() if catch is not None else None
        final_block = self.b.new_block() if final is not None else None
        after = self.b.new_block()
        join = final_block if final_block is not None else after
        if dispatch is not None:
            self.b.handlers.append(dispatch)
        if body is not None:
            self.statements(body.named_children)
        if dispatch is not None:
            self.b.handlers.pop()
        self.b.goto(join)
        if dispatch is not None and catch is not None:
            self.b.switch(dispatch)
            param = catch.child_by_field_name("parameter")
            if param is not None:
                for name in self.pattern_names(param):
                    self.b.emit(
                        Assign(
                            target=Place(base=name),
                            value=const_of("other"),
                            location=self.ctx.loc(catch),
                        )
                    )
            catch_body = catch.child_by_field_name("body")
            if catch_body is not None:
                self.statements(catch_body.named_children)
            self.b.goto(join)
        if final_block is not None and final is not None:
            self.b.switch(final_block)
            final_body = final.child_by_field_name("body") or final
            self.statements(final_body.named_children)
            self.b.goto(after)
        self.b.switch(after)

    # --- expressions -------------------------------------------------------------------------

    def place_of(self, node: Node | None) -> Place:
        if node is None:
            return self.b.temp()
        if node.type in {"identifier", "this"}:
            return Place(base=self.ctx.text(node))
        if node.type == "member_expression":
            prop = self.ctx.text(node.child_by_field_name("property"))
            return with_step(
                self.place_of(node.child_by_field_name("object")), "." + prop, self.ctx
            )
        if (
            node.type in {"parenthesized_expression", "non_null_expression", "as_expression"}
            and node.named_children
        ):
            return self.place_of(node.named_children[0])
        value = self.expr(node)
        if isinstance(value, Place):
            return value
        temp = self.b.temp()
        self.b.emit(Assign(target=temp, value=value, location=self.ctx.loc(node)))
        return temp

    def expr(self, node: Node, dest: Place | None = None, discard: bool = False) -> Expr:  # noqa: PLR0911, PLR0912
        self.b.tick()
        kind = node.type
        if kind in {"identifier", "this", "member_expression"}:
            return self.place_of(node)
        if kind in {"call_expression", "new_expression"}:
            return self.call(node, dest, discard)
        if kind == "subscript_expression":
            return self.subscript(node, dest)
        if kind == "string":
            return const_of(
                "str",
                self.ctx.shape(
                    "".join(
                        self.ctx.text(c) for c in node.named_children if c.type == "string_fragment"
                    )
                ),
            )
        if kind == "template_string":
            return self.template(node)
        if kind == "number":
            return const_of("int")
        if kind in {"true", "false"}:
            return const_of("bool")
        if kind in {"null", "undefined"}:
            return const_of("none")
        if kind == "regex":
            return const_of("regex", self.ctx.shape(self.ctx.text(node)))
        if kind == "binary_expression":
            return self.binary(node)
        if kind == "assignment_expression":
            return self.assignment(node)
        if kind == "augmented_assignment_expression":
            return self.augmented(node)
        if kind in {
            "parenthesized_expression",
            "await_expression",
            "non_null_expression",
            "as_expression",
            "spread_element",
            "satisfies_expression",
        }:
            inner = node.named_children
            return self.expr(inner[0], dest, discard) if inner else const_of("other")
        if kind in {"ternary_expression", "unary_expression", "update_expression"}:
            return Op(
                operator=kind,
                style="bool" if kind == "ternary_expression" else "unary",
                operands=tuple(self.expr(c) for c in node.named_children),
            )
        if kind in {"array", "object", "pair"}:
            return Op(
                operator=kind,
                style="collection",
                operands=tuple(self.expr(c) for c in node.named_children),
            )
        if kind == "shorthand_property_identifier":
            return Place(base=self.ctx.text(node))
        if kind in FUNCTION_TYPES:
            self._callbacks += 1
            self.queue.append(
                _Pending(node, f"{self.scope}.<callback{self._callbacks}>".lstrip("."))
            )
            return const_of("other", "function")
        if kind == "sequence_expression":
            last: Expr = const_of("other")
            for child in node.named_children:
                last = self.expr(child, discard=True)
            return last
        if kind in {"comment", "type_annotation"}:
            return const_of("other")
        return unknown(node, self.ctx, IDENTIFIERS, kind)

    def assignment(self, node: Node) -> Expr:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            return unknown(node, self.ctx, IDENTIFIERS, "assignment")
        self.assign_into(left, right, node)
        return self.target_place(left) if left.type not in PATTERNS else const_of("other")

    def augmented(self, node: Node) -> Expr:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            return unknown(node, self.ctx, IDENTIFIERS, "augmented")
        place = self.target_place(left)
        operator = self.ctx.text(node.child_by_field_name("operator")).removesuffix("=")
        self.b.emit(
            Assign(
                target=place,
                location=self.ctx.loc(node),
                value=Op(
                    operator=operator,
                    style="concat" if operator == "+" else "binary",
                    operands=(place, self.expr(right)),
                ),
            )
        )
        return place

    def call(self, node: Node, dest: Place | None, discard: bool) -> Expr:
        function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        arguments = node.child_by_field_name("arguments")
        receiver = (
            self.place_of(function.child_by_field_name("object"))
            if function is not None and function.type == "member_expression"
            else None
        )
        args = tuple(
            self.expr(a)
            for a in (arguments.named_children if arguments is not None else [])
            if a.type != "comment"
        )
        result = None if discard else (dest if dest is not None else self.b.temp())
        if dest is not None and not discard:
            self._used_dest = True
        text = self.ctx.text(function)
        if node.type == "new_expression":
            text = "new " + text
        callee = self.ctx.callee(function, text)
        if node.type == "new_expression" and callee.symbol is None:
            callee = callee.model_copy(update={"symbol": None})
        self.b.emit(
            Call(
                callee=callee,
                args=args,
                result=result,
                receiver=receiver,
                handler=self.b.handler,
                location=self.ctx.loc(node),
            )
        )
        return result if result is not None else const_of("none")

    def subscript(self, node: Node, dest: Place | None) -> Expr:
        base = self.place_of(node.child_by_field_name("object"))
        index = node.child_by_field_name("index")
        result = dest if dest is not None else self.b.temp()
        if dest is not None:
            self._used_dest = True
        self.b.emit(
            Call(
                callee=self.ctx.callee(None, f"{base.text}.__getitem__"),
                args=(self.expr(index),) if index is not None else (),
                result=result,
                receiver=base,
                handler=self.b.handler,
                location=self.ctx.loc(node),
            )
        )
        return result

    def template(self, node: Node) -> Expr:
        operands: list[Expr] = []
        substituted = False
        for child in node.named_children:
            if child.type == "string_fragment":
                operands.append(const_of("str", self.ctx.shape(self.ctx.text(child))))
            elif child.type == "template_substitution":
                substituted = True
                inner = child.named_children
                operands.append(self.expr(inner[0]) if inner else const_of("other"))
        if not substituted:
            return const_of(
                "str",
                self.ctx.shape(
                    "".join(
                        self.ctx.text(c) for c in node.named_children if c.type == "string_fragment"
                    )
                ),
            )
        return Op(operator="`", style="template", operands=tuple(operands))

    def binary(self, node: Node) -> Expr:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        operator = self.ctx.text(node.child_by_field_name("operator"))
        if left is None or right is None:
            return unknown(node, self.ctx, IDENTIFIERS, "binary")
        lhs, rhs = self.expr(left), self.expr(right)
        if operator == "+":
            parts: list[Expr] = []
            for side in (lhs, rhs):
                if isinstance(side, Op) and side.style == "concat":
                    parts.extend(side.operands)
                else:
                    parts.append(side)
            return Op(operator="+", style="concat", operands=tuple(parts))
        style: OpStyle = (
            "compare" if operator in {"==", "===", "!=", "!==", "<", ">", "<=", ">="} else "binary"
        )
        return Op(operator=operator, style=style, operands=(lhs, rhs))


__all__ = ["JavaScriptLowering"]
