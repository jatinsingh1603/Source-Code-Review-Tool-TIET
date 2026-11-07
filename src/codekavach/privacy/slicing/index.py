"""The per-scan, read-only view of the parsed repository that a slicing strategy works on.

Owning epic: E11.

``ParseIndex`` holds references to what the earlier stages produced (files, syntax trees, symbol
tables, the call graph) and copies none of it; it is built once per scan. Its accessors answer the
questions a strategy asks: the source of a file, the functions it defines with exact ranges, the
function around a location, where a name is defined, and whether a file may be sliced at all.

``is_excluded`` consults three sources and returns the reason, so a slice can record why a callee
was not expanded and a refusal can name its cause: the ``never-send`` rules, the ingestion flags
for vendored, generated and minified files, and the file inventory itself (a path the scan never
saw is excluded). Sending third-party code is a free re-identification for an adversary, which is
why vendored files are excluded and not merely deprioritised.
"""

from collections.abc import Callable, Mapping
from typing import Any, Final

from codekavach.config import Settings
from codekavach.core.models import Location, RawCode, RepoPath
from codekavach.ingest.models import SourceFile
from codekavach.parsing.functions import FunctionRange, function_ranges
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.spec import REGISTRY, UnknownLanguageError
from codekavach.parsing.symbols import SymbolTable
from codekavach.privacy.policy.resolve import PolicyResolver

NeverSend = Callable[[str], bool]
_EMPTY_TABLE: Final = SymbolTable(scopes=(), symbols=())


def never_send_matcher(settings: Settings) -> NeverSend:
    """A predicate over repository paths built from the ``never_send`` settings.

    The rules and their glob semantics belong to ``PolicyResolver`` (E13-02); this is its
    ``is_never_send`` as a plain predicate. Both ``privacy.never_send`` and the ``privacy.paths``
    rules with ``never_send = true`` count.
    """
    return PolicyResolver(settings).is_never_send


class ParseIndex:
    """Read-only access to files, symbols, syntax trees and the call graph of one scan."""

    def __init__(
        self,
        *,
        files: Mapping[str, SourceFile],
        ast: Mapping[str, ParsedFile],
        symbols: Mapping[str, SymbolTable] | None = None,
        callgraph: Any = None,
        never_send: NeverSend | None = None,
    ) -> None:
        self._files = files
        self._ast = ast
        self._symbols = symbols or {}
        self._callgraph = callgraph
        self._never_send: NeverSend = never_send or (lambda _path: False)
        self._ranges: dict[str, tuple[FunctionRange, ...]] = {}

    @property
    def callgraph(self) -> Any:
        """The call graph of the scan, or ``None`` when the stage was not run."""
        return self._callgraph

    @property
    def total_lines(self) -> int:
        """Lines over every file of the inventory: the denominator of a repository fraction."""
        return sum(file.line_count for file in self._files.values())

    def line_count_of(self, path: str) -> int:
        """Lines of ``path`` according to the inventory; ``0`` for a path the scan did not see."""
        file = self._files.get(path)
        return file.line_count if file is not None else 0

    def functions_named(self, name: str) -> tuple[tuple[RepoPath, FunctionRange], ...]:
        """Every function or method called ``name`` in any parsed file, in path then line order."""
        found: list[tuple[RepoPath, FunctionRange]] = []
        for path in sorted(self._ast):
            found.extend((path, r) for r in self.function_ranges_of(path) if r.symbol_name == name)
        return tuple(found)

    def is_excluded(self, path: str) -> tuple[bool, str]:
        """Whether ``path`` must not be sliced, and the reason (``""`` when it may be)."""
        if self._never_send(path):
            return True, "policy_never_send"
        file = self._files.get(path)
        if file is None:
            return True, "unknown_file"
        if file.is_vendored:
            return True, "vendored"
        if file.is_generated:
            return True, "generated"
        if file.is_minified:
            return True, "minified"
        return False, ""

    def parsed_of(self, path: str) -> ParsedFile:
        """The parsed file; ``KeyError`` when the scan did not parse it."""
        return self._ast[path]

    def source_of(self, path: RepoPath) -> RawCode:
        """The text of ``path``."""
        return self._ast[path].source

    def symbols_of(self, path: RepoPath) -> SymbolTable:
        """The symbol table of ``path``; an empty table when the scan built none."""
        return self._symbols.get(path, _EMPTY_TABLE)

    def function_ranges_of(self, path: RepoPath) -> tuple[FunctionRange, ...]:
        """Every named function and method of ``path`` with exact ranges, in source order."""
        cached = self._ranges.get(path)
        if cached is None:
            parsed = self._ast[path]
            try:
                spec = REGISTRY.get(parsed.language)
            except UnknownLanguageError:
                spec = None
            cached = function_ranges(parsed, spec)
            self._ranges[path] = cached
        return cached

    def enclosing_function(self, location: Location) -> FunctionRange | None:
        """The innermost function or method whose full range contains the lines of ``location``."""
        best: FunctionRange | None = None
        for candidate in self.function_ranges_of(location.path):
            if not (
                candidate.full.start_line <= location.start_line
                and location.end_line <= candidate.full.end_line
            ):
                continue
            if best is None or (
                candidate.full.start_line >= best.full.start_line
                and candidate.full.end_line <= best.full.end_line
            ):
                best = candidate
        return best

    def definition_of(
        self, symbol_name: str, from_path: RepoPath
    ) -> tuple[RepoPath, FunctionRange] | None:
        """Where the function ``symbol_name`` used in ``from_path`` is defined, if it is known.

        The file itself is searched first; otherwise the import that binds the name is followed
        to an internal module whose path ends with the module's path. The answer is a best
        effort by name (see the call graph's own caveat) and ``None`` when it is not unique.
        """
        local = [r for r in self.function_ranges_of(from_path) if r.symbol_name == symbol_name]
        if len(local) == 1:
            return from_path, local[0]
        if local:
            return None
        for ref in self.symbols_of(from_path).imports:
            if ref.bound != symbol_name or ref.origin != "internal":
                continue
            suffix = _module_suffix(ref.module)
            matches = [
                path
                for path in self._files
                if suffix and path in self._ast and _is_module(path, suffix)
            ]
            found = [
                (path, r)
                for path in sorted(matches)
                for r in self.function_ranges_of(path)
                if r.symbol_name == (ref.imported or symbol_name)
            ]
            if len(found) == 1:
                return found[0]
        return None


_SCRIPT_EXTENSIONS: Final = (".d.ts", ".tsx", ".ts", ".jsx", ".js", ".mjs", ".cjs", ".mts", ".cts")


def _module_suffix(module: str) -> str:
    """The path tail a module name stands for, without extension.

    A Python module (``a.b``, ``..pkg``) becomes ``a/b`` or ``pkg``. A script module that is a
    path (``./util``, ``../lib/util.js``) loses its leading dots and slashes and its extension, so
    both kinds can be compared with the path of a file.
    """
    if "/" not in module:
        return module.lstrip(".").replace(".", "/")
    tail = module.lstrip("./")
    for extension in _SCRIPT_EXTENSIONS:
        if tail.endswith(extension):
            return tail[: -len(extension)]
    return tail


def _is_module(path: str, module_path: str) -> bool:
    """Whether ``path`` (with its extension) is the file of the module ``module_path``."""
    stem = path.rsplit(".", 1)[0]
    return stem == module_path or stem.endswith("/" + module_path)
