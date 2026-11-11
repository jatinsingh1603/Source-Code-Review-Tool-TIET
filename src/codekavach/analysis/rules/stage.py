"""``AnalyseRulesStage``: from ``files`` and ``symbols`` to a part of ``candidates.raw`` (E13-01).

Owning epic: E13. MVP; extended by E16, which adds the rule language and pack loader behind the same
generator protocol and keeps this stage's name and contract.

For every Python and JavaScript file the stage runs the registered generators over one traversal of
the syntax tree and publishes the candidates as this stage's part of ``candidates.raw`` (a
multi-provider key: other analysers add their own parts). Category ``ANALYSE`` degrades: a file
that cannot be read or parsed is skipped with a machine code and recorded as an item failure, and
the scan carries on, so the coverage appendix can say what was not analysed.

The ``ast`` artefact is optional. When the parse stage ran, its lazy mapping supplies the tree;
otherwise the stage parses the file itself. Item failure codes: ``unreadable``, ``too_large``,
``grammar_unavailable``, ``matcher_failed``.
"""

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import ClassVar, Final

from codekavach.analysis.rules.base import CandidateGenerator, GeneratorRegistry
from codekavach.analysis.rules.builtin import default_registry
from codekavach.analysis.rules.compile import grammar_version
from codekavach.analysis.rules.engine import NodeMatcher, run_matchers
from codekavach.analysis.rules.loader import load_packs
from codekavach.analysis.rules.matcher import MATCHER_VERSION, Matcher, RuleMatch
from codekavach.analysis.rules.pack import RulePack
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, Language, Location
from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import CandidateKind
from codekavach.core.models.fingerprint import FingerprintParts, fingerprint_batch, snippet_hash
from codekavach.core.models.text import split_lines
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.memo import memo_key
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.base import ArtefactMissingError
from codekavach.ingest.models import SourceFile
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.parser import ParseUnavailableError, SourceTooLargeError, parse
from codekavach.parsing.symbols import SymbolsArtefact, SymbolTable

MATCHER_FAILED: Final = "matcher_failed"
RULES_ENGINE: Final = "codekavach-rules"
MEMO_NAMESPACE: Final = "rules.matches.v1"
MIN_RULE_SECONDS: Final = 0.25
MAX_RULE_SECONDS: Final = 10.0
_log = get_logger("codekavach.analysis.rules.stage")


class _SkipFileError(Exception):
    """A file this stage cannot analyse; ``code`` is the item failure code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _parse_myself(root: Path, file: SourceFile, ctx: RunContext) -> ParsedFile:
    try:
        text = (root / file.path).read_bytes().decode(file.encoding or "utf-8", errors="replace")
    except (OSError, LookupError) as error:
        raise _SkipFileError("unreadable") from error
    try:
        return parse(file.path, file.language, text, settings=ctx.config.parsing)
    except SourceTooLargeError as error:
        raise _SkipFileError("too_large") from error
    except ParseUnavailableError as error:
        raise _SkipFileError("grammar_unavailable") from error


def _parsed(
    file: SourceFile, ast: Mapping[str, ParsedFile] | None, root: Path, ctx: RunContext
) -> ParsedFile:
    if ast is not None:
        try:
            return ast[file.path]
        except KeyError:
            pass  # the parse stage skipped it; try once ourselves, with the same limits
    return _parse_myself(root, file, ctx)


class MatchRecord(KavachModel):
    """One rule match without its path, as kept in the memo. Client data (it holds positions)."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    rule_id: str
    start_line: int
    end_line: int
    start_col: int | None = None
    end_col: int | None = None
    symbol: str | None = None
    snippet_hash: str
    taint_unavailable: bool = False


class _Uncacheable(Exception):  # noqa: N818 - control flow inside this module only
    """Carries a result that must not be memoised, because a rule failed or timed out."""

    def __init__(self, records: list[MatchRecord], failures: list[tuple[str, str]]) -> None:
        self.records = records
        self.failures = failures
        super().__init__("uncacheable")


class _Packs:
    """The loaded packs, the matcher built from them, and the key that identifies them."""

    def __init__(self, packs: Sequence[RulePack], timeout_seconds: float) -> None:
        self.packs = tuple(packs)
        rule_count = sum(len(pack.rules) for pack in packs)
        budget = timeout_seconds / rule_count if rule_count else MAX_RULE_SECONDS
        self.matcher, self.rules = Matcher.for_packs(
            packs, rule_seconds=max(MIN_RULE_SECONDS, min(budget, MAX_RULE_SECONDS))
        )
        self.checksums = ",".join(f"{pack.id}={pack.checksum[:16]}" for pack in packs)
        self.version = {
            rule.id: f"{pack.id}@{pack.version}" for pack in packs for rule in pack.rules
        }
        self.by_id = {rule.id: rule for rule in self.rules}
        self.languages = {name for rule in self.rules for name in rule.languages}


def _records(
    packs: _Packs, parsed: ParsedFile, path: str
) -> tuple[list[MatchRecord], list[tuple[str, str]]]:
    index = parsed.line_index
    if index is None or parsed.tree is None:
        return [], []
    result = packs.matcher.match_detailed(parsed, packs.rules)
    lines = split_lines(parsed.source.expose())
    records: list[MatchRecord] = []
    for match in result.matches:
        location = _match_location(parsed, match, path)
        records.append(
            MatchRecord(
                rule_id=match.rule.id,
                start_line=location.start_line,
                end_line=location.end_line,
                start_col=location.start_col,
                end_col=location.end_col,
                symbol=location.symbol,
                snippet_hash=snippet_hash(lines[location.start_line - 1 : location.end_line]),
                taint_unavailable=match.taint_unavailable,
            )
        )
    return records, [(failure.rule_id, failure.code) for failure in result.failures]


def _match_location(parsed: ParsedFile, match: RuleMatch, path: str) -> Location:
    from codekavach.analysis.rules.syntax import (  # noqa: PLC0415
        FUNCTION_TYPES,
        enclosing_function,
        function_name,
    )

    assert parsed.line_index is not None  # noqa: S101 - checked by the caller
    symbol: str | None = None
    if parsed.tree is not None:
        node = parsed.tree.root_node.descendant_for_byte_range(match.start_byte, match.end_byte)
        while node is not None and (
            node.start_byte != match.start_byte or node.end_byte != match.end_byte
        ):
            node = node.parent
        if node is not None:
            function = node if node.type in FUNCTION_TYPES else enclosing_function(node)
            name = function_name(function) if function is not None else None
            symbol = name if name and len(name) <= 512 else None
    return parsed.line_index.location(path, match.start_byte, match.end_byte, symbol)


def _candidates(
    packs: _Packs, records: Sequence[MatchRecord], path: str, language: Language
) -> list[Candidate]:
    """Candidates for one file's records; numbering of identical statements is per file."""
    parts = [
        FingerprintParts(
            engine=RULES_ENGINE,
            rule_id=record.rule_id,
            path=path,
            symbol=record.symbol,
            snippet_hash=record.snippet_hash,
            start_line=record.start_line,
        )
        for record in records
    ]
    fingerprints = fingerprint_batch(parts)
    found: list[Candidate] = []
    for record, fingerprint in zip(records, fingerprints, strict=True):
        rule = packs.by_id[record.rule_id]
        properties = [("pack", packs.version[rule.id])]
        if record.taint_unavailable:
            properties.append(("rule.taint", "unavailable"))
        found.append(
            Candidate.create(
                rule_id=rule.id,
                engine=RULES_ENGINE,
                engine_version=packs.version[rule.id],
                cwe=rule.metadata.cwe,
                locations=(
                    Location(
                        path=path,
                        start_line=record.start_line,
                        end_line=record.end_line,
                        start_col=record.start_col,
                        end_col=record.end_col,
                        symbol=record.symbol,
                    ),
                ),
                engine_severity=rule.severity,
                engine_confidence=rule.confidence,
                fingerprint=fingerprint,
                kind=CandidateKind.VULNERABILITY,
                language=language,
                message=rule.message,
                properties=tuple(properties),
            )
        )
    return found


class AnalyseRulesStage:
    """Runs the DSL rule packs and the thin-slice code matchers over Python and JavaScript files.

    The packs come from ``engines.native.rules`` and friends (E16-01). The code matchers stay
    until the shipped packs of E16-03 reproduce their findings; both feed ``candidates.raw``.
    """

    name = "analyse-rules"
    version = "2"
    requires = frozenset({keys.FILES, keys.SYMBOLS})
    optional_requires = frozenset({keys.AST, keys.CALL_GRAPH})
    provides = frozenset({keys.CANDIDATES_RAW})
    category = StageCategory.ANALYSE

    def __init__(
        self,
        registry: GeneratorRegistry | None = None,
        packs: Sequence[RulePack] | None = None,
    ) -> None:
        self._registry = registry if registry is not None else default_registry()
        self._packs = packs

    def run(self, ctx: RunContext) -> None:
        """Publish this stage's part of ``candidates.raw``."""
        files = sorted(ctx.artefacts.get_list(keys.FILES, SourceFile), key=lambda f: f.path)
        symbols = ctx.artefacts.get(keys.SYMBOLS, SymbolsArtefact)
        ast = self._ast(ctx)
        packs = self._load(ctx)
        analysable = [
            f
            for f in files
            if self._registry.for_language(f.language)
            or (packs is not None and f.language.value in packs.languages)
        ]
        candidates: list[Candidate] = []
        for done, file in enumerate(analysable, start=1):
            ctx.check_cancelled()
            if file.path in symbols.skipped:
                continue  # the parse stage judged the file not worth analysing; it said why
            try:
                candidates.extend(self._file(ctx, file, ast, symbols, packs))
            except _SkipFileError as skip:
                ctx.fail_item(f"file:{file.sha256[:16]}", skip.code)
            except Exception:  # noqa: BLE001 - one broken matcher must not lose the other files
                _log.warning("matcher_failed", file=file.sha256[:16])
                ctx.fail_item(f"file:{file.sha256[:16]}", MATCHER_FAILED)
            if done % 100 == 0:
                ctx.emit_progress(done, len(analysable), "files")
        ctx.emit_progress(len(analysable), len(analysable), "files")
        ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, candidates)

    def _load(self, ctx: RunContext) -> _Packs | None:
        if not ctx.config.engines.native.rules:
            return None
        packs = self._packs if self._packs is not None else load_packs(ctx.config)
        if not packs:
            return None
        return _Packs(packs, float(ctx.config.engines.timeout_seconds))

    def _file(
        self,
        ctx: RunContext,
        file: SourceFile,
        ast: Mapping[str, ParsedFile] | None,
        symbols: SymbolsArtefact,
        packs: _Packs | None,
    ) -> list[Candidate]:
        parsed_once: list[ParsedFile] = []

        def parsed() -> ParsedFile:
            if not parsed_once:
                parsed_once.append(_parsed(file, ast, ctx.source_root, ctx))
            return parsed_once[0]

        found: list[Candidate] = []
        if self._registry.for_language(file.language):
            found.extend(self._generate(file.language, parsed(), symbols.tables.get(file.path)))
        if packs is not None and file.language.value in packs.languages:
            found.extend(self._rules(ctx, file, packs, parsed))
        return found

    @staticmethod
    def _rules(
        ctx: RunContext, file: SourceFile, packs: _Packs, parsed: Callable[[], ParsedFile]
    ) -> list[Candidate]:
        failures: list[tuple[str, str]] = []

        def compute() -> list[MatchRecord]:
            records, failed = _records(packs, parsed(), file.path)
            if failed:
                raise _Uncacheable(records, failed)
            return records

        key = memo_key(
            file.sha256,
            file.language.value,
            grammar_version(file.language),
            packs.checksums,
            MATCHER_VERSION,
        )
        try:
            records = ctx.memo.get_or_compute_list(MEMO_NAMESPACE, key, compute, MatchRecord)
        except _Uncacheable as partial:
            records, failures = partial.records, partial.failures
        for rule_id, code in failures:
            ctx.fail_item(rule_id, code)
        return _candidates(packs, records, file.path, file.language)

    @staticmethod
    def _ast(ctx: RunContext) -> Mapping[str, ParsedFile] | None:
        if not ctx.artefacts.has(keys.AST):
            return None
        try:
            value = ctx.artefacts.get_object(keys.AST)
        except ArtefactMissingError:
            return None
        return value if isinstance(value, Mapping) else None

    def _generate(
        self, language: Language, parsed: ParsedFile, table: SymbolTable | None
    ) -> list[Candidate]:
        generators: tuple[CandidateGenerator, ...] = self._registry.for_language(language)
        nodes = tuple(item for item in generators if isinstance(item, NodeMatcher))
        found = run_matchers(nodes, parsed, table)
        for generator in generators:
            if not isinstance(generator, NodeMatcher):
                found.extend(generator.generate(parsed, table))
        return found
