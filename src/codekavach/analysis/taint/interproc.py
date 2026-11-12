"""Summaries bottom-up over the project call graph (E17-03).

Owning epic: E17. ``ProjectIndex`` resolves a call to a function of the project (Python dotted
imports and same-file names, JavaScript relative ``require`` and import specifiers). The call graph
is condensed into strongly connected components (iterative Tarjan) and summaries are computed in
reverse topological order, callees first. A component with a cycle is iterated to a fixed point,
at most ``taint.recursion_iterations`` times; when it does not settle its summaries are widened (any
tainted parameter taints the return value) and marked ``degraded`` with the reason, so recursion
always terminates and the auditor can see where the answer is a guess.

Method calls on instances are resolved from what the code itself shows, since the symbol table
gives no receiver types: ``self.m()`` and ``this.m()`` to a method of the enclosing class,
``obj.m()`` where ``obj`` was assigned from a constructor call of a project class in the same
function, and ``self.attr.m()`` where some method of the class assigns ``self.attr`` from such a
constructor call. Inheritance, annotations and values passed in as parameters are not followed;
such a call is an unknown callee and follows ``taint.unknown_callee``.
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
    _sites: dict[str, dict[tuple[int, int, str], FunctionKey]] = field(default_factory=dict)
    _attr_types: dict[tuple[str, str], dict[str, FunctionKey]] = field(default_factory=dict)

    def add(self, module: IRModule) -> None:
        """Register ``module`` and its functions."""
        self.modules[module.path] = module
        for function in module.functions:
            self.functions.setdefault((module.path, function.qualname), function)
        self._dotted.setdefault(_dotted(module.path).rsplit(".", 1)[-1], []).append(module.path)

    def _is_class(self, path: str, name: str) -> bool:
        prefix = name + "."
        return any(p == path and q.startswith(prefix) for p, q in self.functions)

    def _class_of(self, call: Call, caller_path: str, language: str) -> FunctionKey | None:  # noqa: PLR0911 - one return per resolution rule
        """The project class a constructor call instantiates, as (path, class name)."""
        text = call.callee.text.removeprefix("new ")
        if "." not in text and self._is_class(caller_path, text):
            return caller_path, text
        symbol = call.callee.symbol
        if symbol is None:
            return None
        if language == "python":
            parts = symbol.split(".")
            for split in range(len(parts) - 1, 0, -1):
                module, qual = ".".join(parts[:split]), ".".join(parts[split:])
                for path in self._python_module(module, ""):
                    if self._is_class(path, qual):
                        return path, qual
            return None
        resolved = self._resolve_js(symbol, caller_path)
        if resolved is not None:
            return None  # a plain function, not a class
        head, _, tail = symbol.rpartition("/")
        module_part, dot, name = tail.rpartition(".") if "." in tail.lstrip(".") else (tail, "", "")
        if symbol.startswith(".") and dot and name:
            base = posixpath.normpath(
                posixpath.join(posixpath.dirname(caller_path), head, module_part)
            )
            for suffix in ("", *_JS_SUFFIXES):
                if base + suffix in self.modules and self._is_class(base + suffix, name):
                    return base + suffix, name
        return None

    def _class_attrs(self, path: str, cls: str) -> dict[str, FunctionKey]:
        """``self.x`` places of class ``cls`` that a method assigns from a constructor."""
        key = (path, cls)
        if key in self._attr_types:
            return self._attr_types[key]
        found: dict[str, FunctionKey] = {}
        self._attr_types[key] = found
        language = self.modules[path].language
        for (fpath, qual), function in self.functions.items():
            if fpath != path or not qual.startswith(cls + "."):
                continue
            for name, klass in self._local_types(function, path, language).items():
                if "." in name:
                    found.setdefault(name, klass)
        return found

    def _local_types(
        self, function: IRFunction, path: str, language: str
    ) -> dict[str, FunctionKey]:
        """Places of ``function`` assigned from a project class constructor."""
        types: dict[str, FunctionKey] = {}
        for call in _calls(function):
            if call.result is None:
                continue
            klass = self._class_of(call, path, language)
            if klass is not None:
                types[call.result.text] = klass
        return types

    def resolve_method(self, call: Call, path: str, function: IRFunction) -> FunctionKey | None:
        """The project method a call on an instance invokes, or ``None`` when it cannot be told."""
        receiver = call.receiver
        if receiver is None:
            return None
        method = call.callee.text.removeprefix("new ").rsplit(".", 1)[-1]
        language = self.modules[path].language
        enclosing = function.qualname.rsplit(".", 1)[0] if "." in function.qualname else None
        klass: FunctionKey | None = None
        if receiver.text in {"self", "cls", "this"} and enclosing:
            klass = (path, enclosing)
        else:
            klass = self._local_types(function, path, language).get(receiver.text)
            if klass is None and enclosing and receiver.text.startswith(("self.", "this.")):
                klass = self._class_attrs(path, enclosing).get(receiver.text)
        if klass is None:
            return None
        found = (klass[0], f"{klass[1]}.{method}")
        return found if found in self.functions else None

    def method_sites(self, path: str) -> dict[tuple[int, int, str], FunctionKey]:
        """Resolved instance-method calls of the file, by call-site position and callee text."""
        cached = self._sites.get(path)
        if cached is not None:
            return cached
        sites: dict[tuple[int, int, str], FunctionKey] = {}
        self._sites[path] = sites
        for function in self.modules[path].functions:
            for call in _calls(function):
                found = self.resolve_method(call, path, function)
                if found is not None:
                    loc = call.location
                    sites[(loc.start_line, loc.start_col or 0, call.callee.text)] = found
        return sites

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
            resolved = index.resolve(call, path, module.language) or index.resolve_method(
                call, path, function
            )
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
        loc = call.location
        resolved = index.method_sites(path).get(
            (loc.start_line, loc.start_col or 0, call.callee.text)
        ) or index.resolve(call, path, language)
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
        for _ in range(settings.recursion_iterations if recursive else 1):
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
