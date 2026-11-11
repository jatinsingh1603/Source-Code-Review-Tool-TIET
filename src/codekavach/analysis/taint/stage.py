"""``AnalyseTaintStage``: from ``files`` and ``symbols`` to a part of ``candidates.raw`` (E17-02).

Owning epic: E17. For every Python, JavaScript and TypeScript file the stage lowers each function
(E17-01), propagates taint from the catalogue sources to the catalogue sinks and publishes one
candidate per flow, with a ``TaintPath`` in execution order, as this stage's part of the
multi-provider ``candidates.raw`` key. Category ``ANALYSE`` degrades: a function that raises is
recorded as ``taint_error`` and one that exceeds its time budget as ``taint_timeout``, and the
rest of the file is still analysed, so one pathological function never fails the stage. A language
without a lowering is skipped and logged once.

Candidates carry ``engine="codekavach-taint"`` and ``rule_id="taint.<source kind>.<sink kind>"``
(for example ``taint.http_param.sql``); the CWE and severity come from the sink class in
``catalogue.py``. A flow through an unmodelled call carries ``taint.uncertain=true``; a path cut to
the step cap carries ``taint.path_trimmed=true``; a sink recognised only by method name carries
``taint.sink_match=method`` and a lower confidence.

``engines.native.taint = false`` makes the stage publish an empty part and analyse nothing.
``taint.explain`` writes the explain dump under the scan state directory only (``explain.py``).
"""

from collections.abc import Mapping
from pathlib import Path
from typing import Final

from codekavach.analysis.rules.loader import load_packs
from codekavach.analysis.rules.pack import Catalogue, RulePack
from codekavach.analysis.taint.cache import lower_cached
from codekavach.analysis.taint.catalogue import Binding
from codekavach.analysis.taint.explain import Trace, write_dump
from codekavach.analysis.taint.ir import IRFunction, IRModule
from codekavach.analysis.taint.lowering import LoweringUnavailable, get_lowering
from codekavach.analysis.taint.path import PathResult, build_path_result, cap_per_sink
from codekavach.analysis.taint.propagate import (
    Budget,
    BudgetExceededError,
    FlowWitness,
    propagate_bound,
)
from codekavach.core.log import get_logger
from codekavach.core.models import (
    Candidate,
    Confidence,
    Language,
    Location,
)
from codekavach.core.models.enums import CandidateKind
from codekavach.core.models.fingerprint import FingerprintParts, fingerprint_batch, snippet_hash
from codekavach.core.models.text import split_lines
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.base import ArtefactMissingError
from codekavach.ingest.models import SourceFile
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.parser import parse
from codekavach.parsing.spec import REGISTRY
from codekavach.parsing.symbols import SymbolsArtefact, SymbolTable, build_symbol_table

TAINT_ENGINE: Final = "codekavach-taint"
TAINT_ERROR: Final = "taint_error"
TAINT_TIMEOUT: Final = "taint_timeout"
LANGUAGES: Final = frozenset({Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT})
_log = get_logger("codekavach.analysis.taint.stage")


def _parsed(
    file: SourceFile, ast: Mapping[str, ParsedFile] | None, root: Path, ctx: RunContext
) -> ParsedFile:
    if ast is not None:
        try:
            return ast[file.path]
        except KeyError:
            pass  # the parse stage skipped it; try once ourselves, with the same limits
    text = (root / file.path).read_bytes().decode(file.encoding or "utf-8", errors="replace")
    return parse(file.path, file.language, text, settings=ctx.config.parsing)


def _own_table(parsed: ParsedFile, ctx: RunContext) -> SymbolTable:
    """A symbol table with imports, for a file the parse stage left out."""
    table = build_symbol_table(parsed, REGISTRY.get(parsed.language))
    resolver = DefaultImportResolver(parsed.language)
    return attach_imports(table, parsed, resolver, project_root=ctx.source_root)


def rule_id_of(flow: FlowWitness) -> str:
    """``taint.<source kind>.<sink kind>``."""
    return f"taint.{flow.label}.{flow.sink.kind}"


def _confidence(flow: FlowWitness) -> Confidence:
    weakened = int(flow.uncertain) + int(not flow.sink.exact)
    return (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)[weakened]


def _message(flow: FlowWitness) -> str:
    return f"Data from a {flow.label} source reaches a {flow.sink.kind} sink ({flow.sink_callee})"


def candidate_properties(flow: FlowWitness, result: PathResult) -> tuple[tuple[str, str], ...]:
    """The engine-specific properties of the candidate of ``flow``."""
    properties = [("taint.sink", flow.sink.entry.id), ("taint.source", flow.source_id)]
    if flow.uncertain:
        properties.append(("taint.uncertain", "true"))
    if result.trimmed:
        properties.append(("taint.path_trimmed", "true"))
    if not flow.sink.exact:
        properties.append(("taint.sink_match", "method"))
    if flow.guards:
        properties.append(("taint.guards", ",".join(str(line) for line in flow.guards)[:400]))
    if result.path.is_sanitised:
        properties.append(("taint.sanitised", "inadequate"))
    return tuple(properties)


def candidates_for(  # noqa: PLR0917 - the arguments are the facts of one file and function
    flows: list[FlowWitness],
    function: IRFunction,
    parsed_lines: list[str],
    language: Language,
    path: str,
    max_steps: int,
) -> list[Candidate]:
    """One candidate per flow whose path is valid; the flows are already capped per sink."""
    built: list[tuple[FlowWitness, PathResult]] = []
    for flow in flows:
        result = build_path_result(flow, function, max_steps)
        if result is not None:
            built.append((flow, result))
    parts = [
        FingerprintParts(
            engine=TAINT_ENGINE,
            rule_id=rule_id_of(flow),
            path=path,
            symbol=result.path.sink.location.symbol,
            snippet_hash=snippet_hash(
                parsed_lines[flow.sink_location.start_line - 1 : flow.sink_location.end_line]
            ),
            start_line=flow.sink_location.start_line,
        )
        for flow, result in built
    ]
    found: list[Candidate] = []
    for (flow, result), fingerprint in zip(built, fingerprint_batch(parts), strict=True):
        weakness = flow.sink.weakness
        sink_location: Location = result.path.sink.location
        found.append(
            Candidate.create(
                rule_id=rule_id_of(flow),
                engine=TAINT_ENGINE,
                cwe=weakness.cwe,
                locations=(sink_location,),
                taint_path=result.path,
                engine_severity=weakness.severity,
                engine_confidence=_confidence(flow),
                fingerprint=fingerprint,
                kind=CandidateKind.VULNERABILITY,
                language=language,
                message=_message(flow),
                properties=candidate_properties(flow, result),
            )
        )
    return found


class AnalyseTaintStage:
    """Intraprocedural taint analysis of Python, JavaScript and TypeScript (E17-02)."""

    name = "analyse-taint"
    version = "1"
    requires = frozenset({keys.FILES, keys.SYMBOLS})
    optional_requires = frozenset({keys.AST, keys.CALL_GRAPH})
    provides = frozenset({keys.CANDIDATES_RAW})
    category = StageCategory.ANALYSE

    def __init__(self, packs: tuple[RulePack, ...] | list[RulePack] | None = None) -> None:
        self._packs = packs

    def run(self, ctx: RunContext) -> None:
        """Publish this stage's part of ``candidates.raw``."""
        if not ctx.config.engines.native.taint:
            _log.info("native_taint_disabled")
            ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, [])
            return
        catalogues = self._catalogues(ctx)
        files = sorted(
            (f for f in ctx.artefacts.get_list(keys.FILES, SourceFile) if f.language in LANGUAGES),
            key=lambda f: f.path,
        )
        symbols = ctx.artefacts.get(keys.SYMBOLS, SymbolsArtefact)
        ast = self._ast(ctx)
        candidates: list[Candidate] = []
        unavailable: set[Language] = set()
        for done, file in enumerate(files, start=1):
            ctx.check_cancelled()
            if file.path in symbols.skipped:
                continue
            try:
                candidates.extend(
                    self._file(ctx, file, ast, symbols.tables.get(file.path), catalogues)
                )
            except LoweringUnavailable:
                unavailable.add(file.language)
            except Exception:  # noqa: BLE001 - a broken file must not lose the others
                _log.warning("taint_file_failed", file=file.sha256[:16])
                ctx.fail_item(f"file:{file.sha256[:16]}", TAINT_ERROR)
            if done % 100 == 0:
                ctx.emit_progress(done, len(files), "files")
        for language in sorted(unavailable, key=lambda item: item.value):
            _log.info("taint_language_unavailable", language=language.value)
        ctx.emit_progress(len(files), len(files), "files")
        ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, candidates)

    def _catalogues(self, ctx: RunContext) -> tuple[Catalogue, ...]:
        packs = self._packs if self._packs is not None else load_packs(ctx.config)
        return tuple(catalogue for pack in packs for catalogue in pack.catalogues)

    def _file(
        self,
        ctx: RunContext,
        file: SourceFile,
        ast: Mapping[str, ParsedFile] | None,
        table: SymbolTable | None,
        catalogues: tuple[Catalogue, ...],
    ) -> list[Candidate]:
        settings = ctx.config.taint
        lowering = get_lowering(file.language, settings)
        parsed = _parsed(file, ast, ctx.source_root, ctx)
        module = lower_cached(
            ctx.memo,
            file.sha256,
            parsed,
            table if table is not None else _own_table(parsed, ctx),
            lowering,
            settings,
        )
        lines = split_lines(parsed.source.expose())
        binding = Binding(catalogues, module.aliases, file.language.value)
        found: list[Candidate] = []
        for index, function in enumerate(module.functions):
            found.extend(self._function(ctx, file, module, function, index, binding, lines))
        return found

    @staticmethod
    def _function(  # noqa: PLR0917 - one call site; a bundle type would only rename the list
        ctx: RunContext,
        file: SourceFile,
        module: IRModule,
        function: IRFunction,
        index: int,
        binding: Binding,
        lines: list[str],
    ) -> list[Candidate]:
        settings = ctx.config.taint
        item = f"file:{file.sha256[:16]}:fn{index}"
        if not function.is_analysed:
            _log.info("taint_function_skipped", reason=function.skipped_reason)
            return []
        trace = Trace()
        try:
            flows = propagate_bound(
                function,
                binding,
                budget=Budget.of(settings.timeout_seconds),
                settings=settings,
                observe=trace.record if settings.explain else None,
            )
            flows = cap_per_sink(flows, settings.max_paths_per_sink)
            if settings.explain and ctx.state_dir is not None:
                write_dump(ctx.state_dir, file.sha256, function, flows, trace)
            return candidates_for(
                flows, function, lines, file.language, module.path, settings.max_path_steps
            )
        except BudgetExceededError:
            ctx.fail_item(item, TAINT_TIMEOUT)
        except Exception:  # noqa: BLE001 - one pathological function must not fail the stage
            _log.warning("taint_function_failed", file=file.sha256[:16], index=index)
            ctx.fail_item(item, TAINT_ERROR)
        return []

    @staticmethod
    def _ast(ctx: RunContext) -> Mapping[str, ParsedFile] | None:
        if not ctx.artefacts.has(keys.AST):
            return None
        try:
            value = ctx.artefacts.get_object(keys.AST)
        except ArtefactMissingError:
            return None
        return value if isinstance(value, Mapping) else None
