"""Summaries bottom-up over the project call graph (E17-03).

Owning epic: E17. ``ProjectIndex`` resolves a call to a function of the project (Python dotted
imports and same-file names, JavaScript relative ``require`` and import specifiers). The call graph
is condensed into strongly connected components (iterative Tarjan) and summaries are computed in
reverse topological order, callees first. A component with a cycle is iterated to a fixed point,
at most ``RECURSION_ITERATIONS`` times; when it does not settle its summaries are widened (any
tainted parameter taints the return value) and marked ``degraded`` with the reason, so recursion
always terminates and the auditor can see where the answer is a guess.

Method calls on instances are not resolved (the symbol table gives no receiver types): such a call
is an unknown callee and follows ``taint.unknown_callee``.
"""

import posixpath
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Final

from codekavach.analysis.taint.catalogue import Binding
from codekavach.analysis.taint.ir import Call, IRFunction, IRModule
from codekavach.analysis.taint.propagate import SummaryLookup
from codekavach.analysis.taint.summary import FunctionSummary, compute_summary
from codekavach.config.models.taint import TaintSettings
from codekavach.core.log import get_logger

RECURSION_ITERATIONS: Final = 4
_JS_SUFFIXES: Final = (".js", ".mjs", ".cjs", ".ts", ".tsx", "/index.js", "/index.ts")
_LOG = get_logger("codekavach.analysis.taint.interproc")
FunctionKey = tuple[str, str]


def _dotted(path: str) -> str:
    stem = posixpath.splitext(path)[0]
    return stem.replace("/", ".").removesuffix(".__init__")


@dataclass(slots=True)
class ProjectIndex:
    """Every lowered function of the project, addressable by (path, qualified name)."""

    modules: dict[str, IRModule] = field(default_factory=dict)
    functions: dict[FunctionKey, IRFunction] = field(default_factory=dict)
    _dotted: dict[str, list[str]] = field(default_factory=dict)

    def add(self, module: IRModule) -> None:
        """Register ``module`` and its functions."""
        self.modules[module.path] = module
        for function in module.functions:
            self.functions.setdefault((module.path, function.qualname), function)
        self._dotted.setdefault(_dotted(module.path).rsplit(".", 1)[-1], []).append(module.path)

    def _python_module(self, name: str, caller: str) -> list[str]:
        tail = name.rsplit(".", 1)[-1]
        found = [p for p in self._dotted.get(tail, []) if _dotted(p).endswith(name)]
        found.sort(key=lambda p: -len(posixpath.commonprefix([posixpath.dirname(p), caller])))
        return found

    def resolve(self, call: Call, caller_path: str, language: str) -> FunctionKey | None:
        """The project function ``call`` invokes, or ``None`` when it cannot be told."""
        text = call.callee.text.removeprefix("new ")
        symbol = call.callee.symbol
        if symbol is None and "." not in text and (caller_path, text) in self.functions:
            return caller_path, text
        if symbol is None:
            return None
        if language == "python":
            return self._resolve_python(symbol)
        return self._resolve_js(symbol, caller_path)

    def _resolve_python(self, symbol: str) -> FunctionKey | None:
        parts = symbol.split(".")
        for split in range(len(parts) - 1, 0, -1):
            module, qual = ".".join(parts[:split]), ".".join(parts[split:])
            for path in self._python_module(module, ""):
                if (path, qual) in self.functions:
                    return path, qual
        return None

    def _resolve_js(self, symbol: str, caller_path: str) -> FunctionKey | None:
        if not symbol.startswith("."):
            return None
        head, _, tail = symbol.rpartition("/")
        module_part, dot, name = tail.rpartition(".") if "." in tail.lstrip(".") else (tail, "", "")
        if not dot or not name:
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(caller_path), head, module_part))
        for suffix in ("", *_JS_SUFFIXES):
            path = base + suffix
            if path in self.modules and (path, name) in self.functions:
                return path, name
        return None


def _calls(function: IRFunction) -> Iterable[Call]:
    for block in function.blocks:
        for stmt in block.stmts:
            if isinstance(stmt, Call):
                yield stmt


def call_graph(index: ProjectIndex) -> dict[FunctionKey, set[FunctionKey]]:
    """Resolved caller to callee edges between project functions."""
    graph: dict[FunctionKey, set[FunctionKey]] = {}
    for (path, qual), function in index.functions.items():
        module = index.modules[path]
        targets = graph.setdefault((path, qual), set())
        for call in _calls(function):
            resolved = index.resolve(call, path, module.language)
            if resolved is not None and resolved in index.functions:
                targets.add(resolved)
    return graph


def sccs(graph: dict[FunctionKey, set[FunctionKey]]) -> list[list[FunctionKey]]:
    """Strongly connected components, callees before callers (iterative Tarjan)."""
    counter = 0
    stack: list[FunctionKey] = []
    on_stack: set[FunctionKey] = set()
    number: dict[FunctionKey, int] = {}
    low: dict[FunctionKey, int] = {}
    result: list[list[FunctionKey]] = []
    for root in sorted(graph):
        if root in number:
            continue
        work: list[tuple[FunctionKey, list[FunctionKey]]] = [(root, sorted(graph[root]))]
        number[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, pending = work[-1]
            if pending:
                nxt = pending.pop()
                if nxt not in graph:
                    continue
                if nxt not in number:
                    number[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, sorted(graph[nxt])))
                elif nxt in on_stack:
                    low[node] = min(low[node], number[nxt])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == number[node]:
                component: list[FunctionKey] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                result.append(sorted(component))
    return result


def make_lookup(
    index: ProjectIndex, summaries: dict[FunctionKey, FunctionSummary], path: str
) -> SummaryLookup:
    """The callee-summary lookup for calls made in the file ``path``."""
    language = index.modules[path].language

    def lookup(call: Call) -> FunctionSummary | None:
        resolved = index.resolve(call, path, language)
        return None if resolved is None else summaries.get(resolved)

    return lookup


def compute_summaries(
    index: ProjectIndex,
    binder: Callable[[str], Binding],
    settings: TaintSettings,
    *,
    block_unknown: bool = False,
) -> dict[FunctionKey, FunctionSummary]:
    """Summaries of every function of ``index``, bottom-up, with bounded recursion."""
    graph = call_graph(index)
    summaries: dict[FunctionKey, FunctionSummary] = {}
    for component in sccs(graph):
        recursive = len(component) > 1 or component[0] in graph[component[0]]
        settled = False
        for _ in range(RECURSION_ITERATIONS if recursive else 1):
            changed = False
            for key in component:
                path, qual = key
                function = index.functions[key]
                try:
                    new = compute_summary(
                        function,
                        binder(path),
                        settings=settings,
                        lookup=make_lookup(index, summaries, path),
                        block_unknown=block_unknown,
                        key=f"{path}:{qual}",
                    )
                except Exception:  # noqa: BLE001 - one function must not lose the summaries
                    _LOG.warning("taint_summary_failed")
                    new = FunctionSummary(f"{path}:{qual}", function.params).widened("error")
                old = summaries.get(key)
                if old is None or old.signature() != new.signature():
                    changed = True
                summaries[key] = new
            if not changed:
                settled = True
                break
        if recursive and not settled:
            for key in component:
                summaries[key] = summaries[key].widened("recursion bound reached")
    return summaries
