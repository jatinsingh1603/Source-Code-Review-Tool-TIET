"""Helpers to lower a source snippet for the taint tests."""

from functools import lru_cache
from pathlib import Path

from codekavach.analysis.rules.loader import load_pack
from codekavach.analysis.rules.pack import Catalogue
from codekavach.analysis.taint.catalogue import Binding
from codekavach.analysis.taint.ir import Call, IRFunction, IRModule, Stmt
from codekavach.analysis.taint.lowering import get_lowering
from codekavach.analysis.taint.path import cap_per_sink
from codekavach.analysis.taint.propagate import Budget, FlowWitness, propagate_bound
from codekavach.analysis.taint.stage import candidates_for
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Candidate, Language
from codekavach.core.models.text import split_lines
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


@lru_cache(maxsize=1)
def shipped_catalogues() -> tuple[Catalogue, ...]:
    """The catalogues of the shipped default pack."""
    root = Path(__file__).resolve().parents[2] / "rules" / "mit" / "packs" / "default"
    return load_pack(root).catalogues


def flows_of(
    code: str,
    language: Language = Language.PYTHON,
    settings: TaintSettings | None = None,
) -> list[tuple[IRFunction, FlowWitness]]:
    """Every flow found in ``code`` with its function, using the shipped catalogues."""
    module = lower_source(code, language, settings)
    binding = Binding(shipped_catalogues(), module.aliases, language.value)
    found: list[tuple[IRFunction, FlowWitness]] = []
    for function in module.functions:
        flows = propagate_bound(function, binding, budget=Budget.of(10), settings=settings)
        found.extend((function, flow) for flow in flows)
    return found


def candidates_of(
    code: str,
    language: Language = Language.PYTHON,
    settings: TaintSettings | None = None,
    path: str = "app.py",
) -> list[Candidate]:
    """The candidates the stage would emit for ``code``."""
    config = settings or TaintSettings()
    module = lower_source(code, language, settings, path=path)
    binding = Binding(shipped_catalogues(), module.aliases, language.value)
    lines = split_lines(code)
    found: list[Candidate] = []
    for function in module.functions:
        flows = propagate_bound(function, binding, budget=Budget.of(10), settings=config)
        flows = cap_per_sink(flows, config.max_paths_per_sink)
        found.extend(candidates_for(flows, function, lines, language, path, config.max_path_steps))
    return found
