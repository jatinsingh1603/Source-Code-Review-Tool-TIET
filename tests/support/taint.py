"""Helpers to lower a source snippet for the taint tests."""

from pathlib import Path

from codekavach.analysis.taint.ir import Call, IRFunction, IRModule, Stmt
from codekavach.analysis.taint.lowering import get_lowering
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language
from codekavach.parsing import parse
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.spec import REGISTRY
from codekavach.parsing.symbols import build_symbol_table

SUFFIX = {Language.PYTHON: "py", Language.JAVASCRIPT: "js", Language.TYPESCRIPT: "ts"}


def lower_source(
    code: str,
    language: Language = Language.PYTHON,
    settings: TaintSettings | None = None,
    path: str | None = None,
) -> IRModule:
    """Parse ``code`` and lower it."""
    parsed = parse(path or f"snippet.{SUFFIX[language]}", language, code)
    table = attach_imports(
        build_symbol_table(parsed, REGISTRY.get(language)),
        parsed,
        DefaultImportResolver(language),
        project_root=Path(),
    )
    return get_lowering(language, settings).lower(parsed, table)


def function_of(module: IRModule, qualname: str) -> IRFunction:
    """The function ``qualname`` of ``module``, failing the test when it is absent."""
    found = module.function(qualname)
    assert found is not None, [f.qualname for f in module.functions]
    return found


def statements(function: IRFunction) -> list[Stmt]:
    """Every statement of ``function`` in block order."""
    return [stmt for block in function.blocks for stmt in block.stmts]


def calls(function: IRFunction) -> list[Call]:
    """Every call of ``function``."""
    return [stmt for stmt in statements(function) if isinstance(stmt, Call)]
