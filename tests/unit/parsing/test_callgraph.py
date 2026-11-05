"""The best-effort call graph (E07-04)."""

from dataclasses import replace
from pathlib import Path
from textwrap import dedent

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.callgraph import (
    CallFacts,
    CallGraph,
    build_call_graph,
    build_call_graph_from_facts,
    extract_call_facts,
    module_ids,
)
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable, build_symbol_table


def _analyse(
    path: str, language: Language, source: str, internal: frozenset[str] = frozenset()
) -> tuple[ParsedFile, SymbolTable]:
    parsed = parse(path, language, dedent(source).lstrip("\n"))
    table = build_symbol_table(parsed, REGISTRY.get(language))
    resolver = DefaultImportResolver(language, internal_names=internal)
    return parsed, attach_imports(table, parsed, resolver, project_root=Path())


def _graph(*files: tuple[str, Language, str], internal: frozenset[str] = frozenset()) -> CallGraph:
    analysed = [_analyse(p, lang, src, internal) for p, lang, src in files]
    return build_call_graph(
        [parsed for parsed, _ in analysed], {parsed.path: table for parsed, table in analysed}
    )


def test_module_ids_python() -> None:
    assert module_ids("src/billing/engine.py", Language.PYTHON) == (
        "billing.engine",
        "src.billing.engine",
    )
    assert module_ids("pkg/__init__.py", Language.PYTHON) == ("pkg",)
    assert module_ids("top.py", Language.PYTHON) == ("top",)
    assert module_ids("lib/a/b.pyi", Language.PYTHON) == ("a.b", "lib.a.b")


def test_module_ids_javascript() -> None:
    assert module_ids("src/a/index.ts", Language.TYPESCRIPT) == ("src/a",)
    assert module_ids("x/y.d.ts", Language.TYPESCRIPT) == ("x/y",)
    assert module_ids("x/y.mjs", Language.JAVASCRIPT) == ("x/y",)


def test_local_calls_within_a_file_are_resolved() -> None:
    graph = _graph(
        (
            "m.py",
            Language.PYTHON,
            """
            def a():
                b()
                c.d()

            def b():
                pass

            class K:
                def run(self):
                    self.step()
                    a()

                def step(self):
                    pass
            """,
        )
    )
    assert graph.callees("m.a") == ("?c.d", "m.b")
    assert graph.callees("m.K.run") == ("m.K.step", "m.a")
    assert graph.callers("m.K.step") == ("m.K.run",)
    assert graph.callers("m.a") == ("m.K.run",)


def test_module_level_calls_are_attributed_to_the_module() -> None:
    graph = _graph(("m.py", Language.PYTHON, "def f():\n    pass\n\nf()\n"))
    assert graph.callees("m") == ("m.f",)


def test_shadowing_does_not_create_a_false_local_edge() -> None:
    graph = _graph(
        (
            "m.py",
            Language.PYTHON,
            """
            def f():
                pass

            def g(f):
                f()
            """,
        )
    )
    assert graph.callees("m.g") == ("?f",)


def test_cross_file_edges_resolve_through_imports_in_python() -> None:
    graph = _graph(
        (
            "src/app/main.py",
            Language.PYTHON,
            """
            import hashlib
            import numpy as np
            from billing.engine import accrue
            from . import helpers
            from .helpers import log as lg

            def handle():
                helpers.log(1)
                lg(2)
                hashlib.sha256()
                np.zeros(1)
                accrue(1)
                nothing()
            """,
        ),
        ("src/app/helpers.py", Language.PYTHON, "def log(x):\n    pass\n"),
        ("src/billing/engine.py", Language.PYTHON, "def accrue(x):\n    pass\n"),
        internal=frozenset({"billing", "app"}),
    )
    assert graph.callees("app.main.handle") == (
        "?nothing",
        "app.helpers.log",
        "billing.engine.accrue",
        "hashlib.sha256",
        "numpy.zeros",
    )


def test_an_internal_import_with_no_matching_definition_is_marked_unresolved() -> None:
    graph = _graph(
        ("a.py", Language.PYTHON, "from b import gone\n\ndef f():\n    gone()\n"),
        ("b.py", Language.PYTHON, "def other():\n    pass\n"),
        internal=frozenset({"b"}),
    )
    assert graph.callees("a.f") == ("?b.gone",)


def test_cross_file_edges_in_typescript() -> None:
    graph = _graph(
        (
            "src/main.ts",
            Language.TYPESCRIPT,
            """
            import { helper } from "./util";
            import * as u from "./util";
            import { createHash } from "node:crypto";

            export function main(): void {
              helper();
              u.helper();
              createHash("md5");
              missing();
            }
            """,
        ),
        ("src/util.ts", Language.TYPESCRIPT, "export function helper() { return 1; }\n"),
    )
    assert graph.callees("src/main.main") == (
        "?missing",
        "node:crypto.createHash",
        "src/util.helper",
    )


def test_callgraph_is_independent_of_input_order() -> None:
    files = [
        ("a.py", Language.PYTHON, "from b import g\n\ndef f():\n    g()\n"),
        ("b.py", Language.PYTHON, "def g():\n    pass\n"),
    ]
    forward = _graph(*files, internal=frozenset({"b"}))
    backward = _graph(*reversed(files), internal=frozenset({"b"}))
    assert forward == backward
    assert forward.edges == tuple(sorted(forward.edges))


def test_facts_round_trip_through_json_and_rebuild_the_same_graph() -> None:
    parsed, table = _analyse("m.py", Language.PYTHON, "def f():\n    g()\n\ndef g():\n    h()\n")
    facts = extract_call_facts(parsed, table)
    restored = CallFacts.model_validate_json(facts.model_dump_json())
    assert restored == facts
    assert build_call_graph_from_facts([("m.py", Language.PYTHON, restored)]).edges == (
        ("m.f", "m.g"),
        ("m.g", "?h"),
    )


def test_a_file_without_a_tree_contributes_nothing() -> None:
    parsed, table = _analyse("m.py", Language.PYTHON, "def f():\n    g()\n")
    detached = replace(parsed, tree=None)
    assert extract_call_facts(detached, table) == CallFacts()


def test_a_relative_import_above_the_top_is_unresolved_not_a_crash() -> None:
    graph = _graph(("m.py", Language.PYTHON, "from ... import x\n\ndef f():\n    x()\n"))
    assert graph.callees("m.f") == ("?...",)
