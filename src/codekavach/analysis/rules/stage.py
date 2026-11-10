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

from collections.abc import Mapping
from pathlib import Path
from typing import Final

from codekavach.analysis.rules.base import CandidateGenerator, GeneratorRegistry
from codekavach.analysis.rules.builtin import default_registry
from codekavach.analysis.rules.engine import NodeMatcher, run_matchers
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, Language
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.base import ArtefactMissingError
from codekavach.ingest.models import SourceFile
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.parser import ParseUnavailableError, SourceTooLargeError, parse
from codekavach.parsing.symbols import SymbolsArtefact, SymbolTable

MATCHER_FAILED: Final = "matcher_failed"
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


class AnalyseRulesStage:
    """Runs the native matchers over every Python and JavaScript file."""

    name = "analyse-rules"
    version = "1"
    requires = frozenset({keys.FILES, keys.SYMBOLS})
    optional_requires = frozenset({keys.AST, keys.CALL_GRAPH})
    provides = frozenset({keys.CANDIDATES_RAW})
    category = StageCategory.ANALYSE

    def __init__(self, registry: GeneratorRegistry | None = None) -> None:
        self._registry = registry if registry is not None else default_registry()

    def run(self, ctx: RunContext) -> None:
        """Publish this stage's part of ``candidates.raw``."""
        files = sorted(ctx.artefacts.get_list(keys.FILES, SourceFile), key=lambda f: f.path)
        symbols = ctx.artefacts.get(keys.SYMBOLS, SymbolsArtefact)
        ast = self._ast(ctx)
        analysable = [f for f in files if self._registry.for_language(f.language)]
        candidates: list[Candidate] = []
        for done, file in enumerate(analysable, start=1):
            ctx.check_cancelled()
            if file.path in symbols.skipped:
                continue  # the parse stage judged the file not worth analysing; it said why
            try:
                parsed = _parsed(file, ast, ctx.source_root, ctx)
                candidates.extend(
                    self._generate(file.language, parsed, symbols.tables.get(file.path))
                )
            except _SkipFileError as skip:
                ctx.fail_item(f"file:{file.sha256[:16]}", skip.code)
            except Exception:  # noqa: BLE001 - one broken matcher must not lose the other files
                _log.warning("matcher_failed", file=file.sha256[:16])
                ctx.fail_item(f"file:{file.sha256[:16]}", MATCHER_FAILED)
            if done % 100 == 0:
                ctx.emit_progress(done, len(analysable), "files")
        ctx.emit_progress(len(analysable), len(analysable), "files")
        ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, candidates)

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
