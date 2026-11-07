"""The matcher runtime: one traversal per file, dispatch by node type, candidates with fingerprints.

Owning epic: E13. MVP; extended by E16, whose rule engine replaces the dispatch table.

A :class:`NodeMatcher` names the tree-sitter node types it wants and yields a :class:`Hit` for each
node that is a weakness. :func:`run_matchers` walks the tree once, hands every node to the matchers
registered for its type and turns the hits into :class:`Candidate` objects, so adding a matcher
costs a dictionary entry and not another pass over the file. Output order is the order of the
traversal, which is source order, so two runs over the same bytes give the same list.

The fingerprint of a candidate is ``ckfp1`` (E02-10) over the engine, the rule, the path, the
enclosing function and the flagged statement, with identical statements numbered in line order.
"""

from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.syntax import FUNCTION_TYPES, enclosing_function, function_name
from codekavach.core.models import Candidate, Confidence, Language, Location, Severity
from codekavach.core.models.enums import CandidateKind
from codekavach.core.models.fingerprint import FingerprintParts, fingerprint_batch, snippet_hash
from codekavach.core.models.text import split_lines
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable

ENGINE: Final = "codekavach.rules"
ENGINE_VERSION: Final = "1"
LANGUAGE_PREFIX: Final = {Language.PYTHON: "py", Language.JAVASCRIPT: "js"}
SUPPORTED_LANGUAGES: Final = frozenset(LANGUAGE_PREFIX)


@dataclass(frozen=True, slots=True)
class Rule:
    """What a matcher reports: the slug (``sql-injection``), the CWE, the severity and the text.

    The message states the weakness in general terms and never quotes the code, so it is safe to
    keep next to the candidate. ``engine_severity`` stays local and out of any prompt (E13-02).
    """

    slug: str
    cwe: int
    severity: Severity
    message: str
    confidence: Confidence = Confidence.MEDIUM

    def rule_id(self, language: Language) -> str:
        """``py.sql-injection`` for Python, ``js.sql-injection`` for JavaScript."""
        return f"{LANGUAGE_PREFIX[language]}.{self.slug}"


@dataclass(frozen=True, slots=True)
class Hit:
    """A node a matcher found weak. ``node`` is the span the candidate points at."""

    rule: Rule
    node: Node


@dataclass(slots=True)
class FileContext:
    """What a matcher may ask about the file it is looking at."""

    parsed: ParsedFile
    language: Language
    root: Node
    symbols: SymbolTable | None = None
    _lines: list[str] | None = field(default=None, repr=False)

    @property
    def path(self) -> str:
        """The repository-relative path of the file."""
        return self.parsed.path

    @property
    def lines(self) -> list[str]:
        """The source split into lines, computed on first use."""
        if self._lines is None:
            self._lines = split_lines(self.parsed.source.expose())
        return self._lines


class NodeMatcher(ABC):
    """A candidate generator that looks at nodes of given types in a Python or JavaScript tree."""

    languages: frozenset[Language] = SUPPORTED_LANGUAGES
    node_types: ClassVar[frozenset[str]]

    @abstractmethod
    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a :class:`Hit` when ``node`` (one of ``node_types``) is a weakness."""

    def generate(self, parsed: ParsedFile, symbols: SymbolTable | None) -> Sequence[Candidate]:
        """The candidates of this matcher alone (the stage uses :func:`run_matchers` for all)."""
        return run_matchers((self,), parsed, symbols)


def _dispatch(matchers: Sequence[NodeMatcher], language: Language) -> dict[str, list[NodeMatcher]]:
    table: dict[str, list[NodeMatcher]] = defaultdict(list)
    for matcher in matchers:
        if language in matcher.languages:
            for node_type in matcher.node_types:
                table[node_type].append(matcher)
    return table


def _collect(root: Node, table: dict[str, list[NodeMatcher]], ctx: FileContext) -> list[Hit]:
    hits: list[Hit] = []
    stack = [root]
    while stack:
        node = stack.pop()
        for matcher in table.get(node.type, ()):
            hits.extend(matcher.visit(node, ctx))
        stack.extend(reversed(node.named_children))
    return hits


def _location(ctx: FileContext, node: Node) -> Location:
    index = ctx.parsed.line_index
    if index is None:
        raise ValueError("a parsed file needs its line index to report a location")
    function = node if node.type in FUNCTION_TYPES else enclosing_function(node)
    name = function_name(function) if function is not None else None
    symbol = name if name and len(name) <= 512 else None
    return index.location(ctx.path, node.start_byte, node.end_byte, symbol)


def _build(hits: Sequence[Hit], ctx: FileContext) -> list[Candidate]:
    locations = [_location(ctx, hit.node) for hit in hits]
    parts = [
        FingerprintParts(
            engine=ENGINE,
            rule_id=hit.rule.rule_id(ctx.language),
            path=location.path,
            symbol=location.symbol,
            snippet_hash=snippet_hash(ctx.lines[location.start_line - 1 : location.end_line]),
            start_line=location.start_line,
        )
        for hit, location in zip(hits, locations, strict=True)
    ]
    fingerprints = fingerprint_batch(parts)
    return [
        Candidate.create(
            rule_id=hit.rule.rule_id(ctx.language),
            engine=ENGINE,
            engine_version=ENGINE_VERSION,
            cwe=(hit.rule.cwe,),
            locations=(location,),
            engine_severity=hit.rule.severity,
            engine_confidence=hit.rule.confidence,
            fingerprint=fingerprint,
            kind=CandidateKind.VULNERABILITY,
            language=ctx.language,
            message=hit.rule.message,
            properties=(("matcher", hit.rule.slug),),
        )
        for hit, location, fingerprint in zip(hits, locations, fingerprints, strict=True)
    ]


def run_matchers(
    matchers: Sequence[NodeMatcher], parsed: ParsedFile, symbols: SymbolTable | None
) -> list[Candidate]:
    """Run every matcher that handles ``parsed.language`` over one traversal of its tree."""
    if parsed.tree is None or parsed.language not in SUPPORTED_LANGUAGES:
        return []
    table = _dispatch(matchers, parsed.language)
    if not table:
        return []
    root = parsed.tree.root_node
    ctx = FileContext(parsed=parsed, language=parsed.language, root=root, symbols=symbols)
    return _build(_collect(root, table, ctx), ctx)
