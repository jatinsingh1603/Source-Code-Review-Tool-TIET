"""Symbol resolution for catalogue entries (E16-03).

Owning epic: E16. A catalogue entry names code by a fully qualified dotted ``symbol`` such as
``flask.request.args`` or ``child_process.exec``. This module reads the imports of a file into an
alias table and resolves an attribute chain through it, so ``from flask import request`` followed
by ``request.args`` is ``flask.request.args``, while a local variable called ``request`` in a module
that never imports the framework is not.

Three outcomes, strongest first:

* ``exact``: the chain resolves through the import table to the symbol, or is a bare builtin name
  that nothing in the file rebinds (``eval`` for ``builtins.eval``).
* ``partial``: resolution is unavailable. Either the last two segments of the chain equal the last
  two of the symbol while the first segment is not imported, or the symbol is a method of a class
  (the segment before the last starts with a capital letter, ``sqlite3.Cursor.execute``) and the
  chain ends with that method on a receiver whose type is not known. A caller lowers the rule's
  confidence one step and records ``rule.resolution = partial``.
* no match.

A bare identifier is never a match for a dotted symbol, and a chain whose first segment is an
imported module that differs from the symbol's module is never a partial match: that is how a
pattern engine earns a reputation for noise.
"""

from typing import Final, Literal

from tree_sitter import Node

from codekavach.core.models import Language

Resolution = Literal["exact", "partial"]
PYTHON_BUILTINS: Final = "builtins"
JS_GLOBALS: Final = ("globalThis", "global", "window")
_CHAIN_TYPES: Final = frozenset(
    {"attribute", "member_expression", "field_expression", "selector_expression"}
)
_NAME_TYPES: Final = frozenset(
    {"identifier", "property_identifier", "field_identifier", "name", "simple_identifier"}
)


def _text(node: Node) -> str:
    return (node.text or b"").decode("utf-8", errors="replace")


def chain(node: Node) -> list[str] | None:
    """The dotted segments of ``a.b.c``; ``None`` when the expression is not a plain chain."""
    parts: list[str] = []
    current: Node | None = node
    while current is not None:
        if current.type in _NAME_TYPES:
            parts.append(_text(current))
            return parts[::-1]
        if current.type in {"this", "self"}:
            parts.append(_text(current))
            return parts[::-1]
        if current.type not in _CHAIN_TYPES:
            return None
        tail = current.child_by_field_name("attribute") or current.child_by_field_name("property")
        if tail is None:
            return None
        parts.append(_text(tail))
        current = current.child_by_field_name("object")
    return None


def _python_dotted(node: Node) -> str:
    return ".".join(_text(child) for child in node.children if child.type == "identifier")


def _python_aliases(root: Node) -> dict[str, str]:  # noqa: PLR0912 - one branch per import form
    found: dict[str, str] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type == "aliased_import":
                    name, alias = (
                        child.child_by_field_name("name"),
                        child.child_by_field_name("alias"),
                    )
                    if name is not None and alias is not None:
                        found[_text(alias)] = _python_dotted(name)
                elif child.type == "dotted_name":
                    first = _python_dotted(child).split(".")[0]
                    found.setdefault(first, first)
        elif node.type == "import_from_statement":
            module = node.child_by_field_name("module_name")
            if module is not None and module.type == "dotted_name":
                base = _python_dotted(module)
                for child in node.named_children:
                    if child is module:
                        continue
                    if child.type == "aliased_import":
                        name = child.child_by_field_name("name")
                        alias = child.child_by_field_name("alias")
                        if name is not None and alias is not None:
                            found[_text(alias)] = f"{base}.{_python_dotted(name)}"
                    elif child.type == "dotted_name":
                        found[_python_dotted(child)] = f"{base}.{_python_dotted(child)}"
            continue
        else:
            stack.extend(node.children)
    return found


def _string_value(node: Node) -> str | None:
    for child in node.named_children:
        if child.type in {"string_fragment", "string_content"}:
            return _text(child)
    return None


def _required_module(call: Node) -> str | None:
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    if function is None or _text(function) != "require" or arguments is None:
        return None
    for argument in arguments.named_children:
        if argument.type == "string":
            return _string_value(argument)
    return None


def _js_declarator(node: Node, found: dict[str, str]) -> None:
    name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
    if name is None or value is None or value.type != "call_expression":
        return
    module = _required_module(value)
    if module is None:
        return
    if name.type == "identifier":
        found[_text(name)] = module
    elif name.type == "object_pattern":
        for child in name.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                found[_text(child)] = f"{module}.{_text(child)}"
            elif child.type == "pair_pattern":
                key, local = child.child_by_field_name("key"), child.child_by_field_name("value")
                if key is not None and local is not None and local.type == "identifier":
                    found[_text(local)] = f"{module}.{_text(key)}"


def _js_import(node: Node, found: dict[str, str]) -> None:
    source = node.child_by_field_name("source")
    module = _string_value(source) if source is not None else None
    if module is None:
        return
    for clause in node.named_children:
        if clause.type != "import_clause":
            continue
        for part in clause.named_children:
            if part.type == "identifier":
                found[_text(part)] = module
            elif part.type == "namespace_import":
                names = [c for c in part.named_children if c.type == "identifier"]
                if names:
                    found[_text(names[0])] = module
            elif part.type == "named_imports":
                for spec in part.named_children:
                    names = [c for c in spec.named_children if c.type == "identifier"]
                    if names:
                        local = _text(names[-1])
                        found[local] = f"{module}.{_text(names[0])}"


def _js_aliases(root: Node) -> dict[str, str]:
    found: dict[str, str] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "import_statement":
            _js_import(node, found)
        elif node.type == "variable_declarator":
            _js_declarator(node, found)
            stack.extend(node.children)
        else:
            stack.extend(node.children)
    return found


def import_aliases(root: Node, language: Language) -> dict[str, str]:
    """Local name to qualified name, from the import statements of one file."""
    if language is Language.PYTHON:
        return _python_aliases(root)
    if language in {Language.JAVASCRIPT, Language.TYPESCRIPT}:
        return _js_aliases(root)
    return {}


def symbol_match(  # noqa: PLR0911 - one exit per way a name can resolve
    symbol: str, node: Node, aliases: dict[str, str], language: Language
) -> Resolution | None:
    """How ``node`` (an attribute chain or a name) relates to the dotted ``symbol``."""
    parts = chain(node)
    if not parts:
        return None
    wanted = symbol.split(".")
    first = parts[0]
    if first in aliases:
        resolved = [*aliases[first].split("."), *parts[1:]]
        if resolved == wanted:
            return "exact"
        # An imported name that resolves elsewhere is a different symbol, not a partial match.
        if not (len(wanted) > 2 and wanted[-2][:1].isupper() and parts[-1] == wanted[-1]):
            return None
        return "partial" if resolved[: len(wanted) - 2] == wanted[:-2] else None
    if len(parts) == 1 and _is_builtin(wanted, parts[0], language):
        return "exact"
    if len(wanted) == 1 and parts == wanted:
        return "exact"  # a bare global function: PHP system(), Ruby system
    if len(parts) >= 2 and parts[0] in JS_GLOBALS and language is not Language.PYTHON:
        return "exact" if parts[1:] == wanted[1:] and wanted[0] in JS_GLOBALS else None
    return _partial(wanted, parts)


def _is_builtin(wanted: list[str], name: str, language: Language) -> bool:
    if language is Language.PYTHON:
        return wanted == [PYTHON_BUILTINS, name]
    return len(wanted) == 2 and wanted[0] in JS_GLOBALS and wanted[1] == name


def _partial(wanted: list[str], parts: list[str]) -> Resolution | None:
    if len(wanted) >= 3 and wanted[-2][:1].isupper():
        return "partial" if len(parts) >= 2 and parts[-1] == wanted[-1] else None
    if len(wanted) >= 2 and len(parts) >= 2 and parts[-2:] == wanted[-2:]:
        return "partial"
    return None
