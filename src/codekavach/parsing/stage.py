"""``ParseStage``: from the ``files`` artefact to ``ast``, ``symbols`` and ``callgraph`` (E07-04).

Owning epic: E07.

For every source file whose language has a grammar and a spec the stage parses it, builds its
symbol table, classifies its imports and extracts its calls; then it joins the files into one
call graph. Category ``PARSE`` degrades: a file that cannot be parsed is skipped with a machine
reason and the scan carries on, because an unparseable vendored bundle must not stop an audit.
Every skip is recorded in ``SymbolsArtefact.skipped`` and as an item failure, so the coverage
appendix can state what was not analysed (``docs/research/INSIGHTS.md`` section 5.2).

Skip reasons: ``no_language_spec`` (a language with no analyser yet, listed but not an item
failure), ``grammar_unavailable`` (the grammar does not load), ``unreadable``,
``too_large`` (over ``parsing.max_source_bytes``), ``parse_timeout`` (over
``parsing.timeout_seconds``) and ``too_many_errors`` (more than ``MIN_TOLERATED_ERRORS`` plus one
per ``LINES_PER_TOLERATED_ERROR`` lines of syntax errors, which means the grammar does not
describe the file and its symbols would be fiction).

**The ``ast`` artefact is transient** (``transient_provides``): it never reaches the on-disk
store, because a tree-sitter tree cannot be serialised and the source would sit next to it in the
clear. It is a :class:`LazyAst`: a mapping that parses a file the first time it is asked for it,
keeping only a few in memory. Nothing is held for 5 000 files at once, and a warm re-scan that is
served from the memo does not parse anything.

**The per-file memo** (E04-22) stores one :class:`FileFacts` per file under the key
``(sha256, language, grammar version, pack version, parser module version, path, resolver
fingerprint, parsing limits)``. The path is in the key because the result contains locations; the
resolver fingerprint is in it because an import's origin depends on the rest of the project (a new
top-level package turns a ``third_party`` import ``internal``), not only on this file's bytes. A
pack bump, a parser-module bump or a limit change therefore invalidates every entry.
"""

import hashlib
import time
from collections import OrderedDict
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import ClassVar, Final

from codekavach.config.models.parsing import ParsingSettings
from codekavach.core.log import get_logger
from codekavach.core.models import DataClassification, KavachModel, Language
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.memo import memo_key
from codekavach.core.pipeline.stage import StageCategory
from codekavach.ingest.models import SourceFile
from codekavach.parsing.callgraph import CallFacts, build_call_graph_from_facts, extract_call_facts
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.loader import grammar_available, grammar_version, pack_version
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.parser import ParseUnavailableError, SourceTooLargeError, parse
from codekavach.parsing.spec import REGISTRY
from codekavach.parsing.symbols import SymbolsArtefact, SymbolTable, build_symbol_table

PARSER_MODULE_VERSION: Final = "1"
MEMO_NAMESPACE: Final = "parse.facts.v1"
MIN_TOLERATED_ERRORS: Final = 10
LINES_PER_TOLERATED_ERROR: Final = 10
LAZY_AST_CACHE_SIZE: Final = 32
PROGRESS_MIN_SECONDS: Final = 0.25
PROGRESS_MIN_FILES: Final = 250
CONFIG_FILES: Final = ("tsconfig.json", "jsconfig.json", "package.json", "go.mod")
MAX_CONFIG_BYTES: Final = 256 * 1024
SUPPORTED: Final = (
    Language.PYTHON,
    Language.JAVASCRIPT,
    Language.TYPESCRIPT,
    Language.JAVA,
    Language.GO,
)
NO_SPEC: Final = "no_language_spec"

_log = get_logger("codekavach.parsing.stage")


class FileFacts(KavachModel):
    """Everything one file contributes, as stored in the memo. Client data."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    symbols: SymbolTable
    calls: CallFacts
    skipped: str | None = None


class _Skip(Exception):  # noqa: N818 - control flow inside this module only
    """A file the stage cannot analyse; ``reason`` is a machine code."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _read(root: Path, file: SourceFile) -> str:
    try:
        data = (root / file.path).read_bytes()
    except OSError as error:
        raise _Skip("unreadable") from error
    try:
        return data.decode(file.encoding or "utf-8", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _parse_file(root: Path, file: SourceFile, settings: ParsingSettings) -> ParsedFile:
    text = _read(root, file)
    try:
        return parse(file.path, file.language, text, settings=settings)
    except SourceTooLargeError as error:
        raise _Skip("too_large") from error
    except ParseUnavailableError as error:
        raise _Skip("grammar_unavailable") from error


def _too_many_errors(parsed: ParsedFile, file: SourceFile) -> bool:
    return parsed.error_count > MIN_TOLERATED_ERRORS + file.line_count // LINES_PER_TOLERATED_ERROR


def _analyse(
    root: Path, file: SourceFile, settings: ParsingSettings, resolver: DefaultImportResolver
) -> FileFacts:
    """Parse one file and derive its facts; raises :class:`_Skip` when it cannot be analysed."""
    parsed = _parse_file(root, file, settings)
    if parsed.timed_out:
        raise _Skip("parse_timeout")
    if _too_many_errors(parsed, file):
        return FileFacts(
            symbols=SymbolTable(scopes=(), symbols=()), calls=CallFacts(), skipped="too_many_errors"
        )
    table = build_symbol_table(parsed, REGISTRY.get(file.language))
    table = attach_imports(table, parsed, resolver, project_root=root)
    return FileFacts(symbols=table, calls=extract_call_facts(parsed, table))


class LazyAst(Mapping[str, ParsedFile]):
    """A read-only mapping from path to :class:`ParsedFile` that parses on first access.

    At most ``LAZY_AST_CACHE_SIZE`` files are kept. Parsing happens again if an evicted file is
    asked for, with the same result. Raises ``KeyError`` for a path the stage did not analyse and
    for a file that can no longer be read or parsed.
    """

    def __init__(
        self, root: Path, files: Mapping[str, SourceFile], settings: ParsingSettings
    ) -> None:
        self._root = root
        self._files = dict(files)
        self._settings = settings
        self._cache: OrderedDict[str, ParsedFile] = OrderedDict()

    def __getitem__(self, path: str) -> ParsedFile:
        cached = self._cache.get(path)
        if cached is not None:
            self._cache.move_to_end(path)
            return cached
        file = self._files.get(path)
        if file is None:
            raise KeyError(path)
        try:
            parsed = _parse_file(self._root, file, self._settings)
        except _Skip as skip:
            raise KeyError(path) from skip
        self._cache[path] = parsed
        if len(self._cache) > LAZY_AST_CACHE_SIZE:
            self._cache.popitem(last=False)
        return parsed

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._files))

    def __len__(self) -> int:
        return len(self._files)


def _internal_names(files: list[SourceFile]) -> frozenset[str]:
    """Top-level names the scanned Python, Java and Go files define: directory and module names.

    A package that sits below ``project_root`` (a monorepo service) is not found by looking at
    the root alone; treating every directory that holds Python as the project's own is the safe
    direction, since a wrongly internal name is only renamed.
    """
    names: set[str] = set()
    for file in files:
        if file.language is Language.PYTHON:
            parts = file.path.split("/")
            names.update(parts[:-1])
            names.add(parts[-1].removesuffix(".pyi").removesuffix(".py"))
        elif file.language in (Language.JAVA, Language.GO):
            names.update(file.path.split("/")[:-1])
    names.discard("")
    return frozenset(names)


def _resolver_fingerprint(root: Path, internal_names: frozenset[str]) -> str:
    """A digest of everything outside a file's own bytes that decides its imports' origins."""
    digest = hashlib.sha256()
    for name in sorted(internal_names):
        digest.update(name.encode("utf-8", errors="replace") + b"\0")
    for name in CONFIG_FILES:
        digest.update(name.encode("ascii") + b"\0")
        try:
            path = root / name
            if path.stat().st_size <= MAX_CONFIG_BYTES:
                digest.update(path.read_bytes())
        except OSError:
            digest.update(b"-")
    return digest.hexdigest()


def _unanalysable(file: SourceFile) -> str | None:
    """Why no analysis is attempted for ``file`` at all, or ``None`` when one should be."""
    if file.language not in SUPPORTED or REGISTRY.get(file.language) is None:
        return NO_SPEC
    if not grammar_available(file.language):
        return "grammar_unavailable"
    return None


class _Throttle:
    def __init__(self) -> None:
        self._time = time.monotonic()
        self._count = 0

    def ready(self, done: int) -> bool:
        now = time.monotonic()
        if now - self._time < PROGRESS_MIN_SECONDS or done - self._count < PROGRESS_MIN_FILES:
            return False
        self._time, self._count = now, done
        return True


class ParseStage:
    """Parses every analysable file and publishes ``ast``, ``symbols`` and ``callgraph``."""

    name = "parse"
    version = "1"
    requires = frozenset({keys.FILES})
    provides = frozenset({keys.AST, keys.SYMBOLS, keys.CALL_GRAPH})
    transient_provides = frozenset({keys.AST})
    category = StageCategory.PARSE

    def run(self, ctx: RunContext) -> None:
        """Write ``symbols`` and ``callgraph`` (persisted) and ``ast`` (in memory only)."""
        files = sorted(ctx.artefacts.get_list(keys.FILES, SourceFile), key=lambda f: f.path)
        root = ctx.source_root
        settings = ctx.config.parsing
        names = _internal_names(files)
        fingerprint = _resolver_fingerprint(root, names)
        resolvers = {lang: DefaultImportResolver(lang, internal_names=names) for lang in SUPPORTED}
        # Read once: asking the installed-package metadata costs about 2 ms, and a scan has
        # thousands of files. It sits in the key with the limits, so a pack bump or a changed
        # limit invalidates every entry.
        limits = (
            f"{pack_version()}|{settings.timeout_seconds}|"
            f"{settings.max_source_bytes}|{settings.max_node_count}"
        )
        throttle = _Throttle()
        tables: dict[str, SymbolTable] = {}
        facts: list[tuple[str, Language, CallFacts]] = []
        skipped: dict[str, str] = {}
        analysed: dict[str, SourceFile] = {}

        for done, file in enumerate(files, start=1):
            ctx.check_cancelled()
            if throttle.ready(done):
                ctx.emit_progress(done, len(files), "files")
            if file.language is Language.UNKNOWN:
                continue  # no grammar is named for it; the languages artefact says so
            reason = _unanalysable(file)
            if reason is None:
                reason = self._one(
                    ctx,
                    file,
                    root,
                    settings,
                    resolvers[file.language],
                    fingerprint,
                    limits,
                    tables,
                    facts,
                )
            if reason is None:
                analysed[file.path] = file
                continue
            skipped[file.path] = reason
            if reason != NO_SPEC:
                ctx.fail_item(f"file:{file.sha256[:16]}", reason)
        ctx.emit_progress(len(files), len(files), "files")
        if any(reason != NO_SPEC for reason in skipped.values()):
            ctx.warn("files_skipped")

        graph = build_call_graph_from_facts(facts)
        ctx.artefacts.put(keys.SYMBOLS, SymbolsArtefact(tables=tables, skipped=skipped))
        ctx.artefacts.put(keys.CALL_GRAPH, graph)
        ctx.artefacts.put(keys.AST, LazyAst(root, analysed, settings), persist=False)

    @staticmethod
    def _one(  # noqa: PLR0917 - the run's shared state, passed explicitly
        ctx: RunContext,
        file: SourceFile,
        root: Path,
        settings: ParsingSettings,
        resolver: DefaultImportResolver,
        fingerprint: str,
        limits: str,
        tables: dict[str, SymbolTable],
        facts: list[tuple[str, Language, CallFacts]],
    ) -> str | None:
        """Analyse one file. Returns ``None`` on success, else the skip reason."""
        key = memo_key(
            file.sha256,
            file.language.value,
            grammar_version(file.language),
            PARSER_MODULE_VERSION,
            file.path,
            fingerprint,
            limits,
        )
        try:
            result = ctx.memo.get_or_compute(
                MEMO_NAMESPACE, key, lambda: _analyse(root, file, settings, resolver), FileFacts
            )
        except _Skip as skip:
            return skip.reason
        if result.skipped is not None:
            return result.skipped
        tables[file.path] = result.symbols
        facts.append((file.path, file.language, result.calls))
        return None
