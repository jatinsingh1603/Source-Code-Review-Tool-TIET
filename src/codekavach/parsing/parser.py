"""Error-tolerant, bounded tree-sitter parsing (E07-01, E07-02).

Owning epic: E07.

``parse`` is the single entry point every later stage calls. It normalises the text (Unicode
hidden-character substitution, this module's own ``normalise_source``), enforces the size, time
and node-count guards of ``[parsing]``, counts ``ERROR``/``MISSING`` nodes instead of raising on
them, and converts every span it reports through one ``LineIndex`` built from the *normalised*
text, because that is the byte stream tree-sitter actually walked. A parse that cannot run at all
because no grammar is installed is reported as ``ParseUnavailableError``, not an error: a missing
grammar is a fact about the environment, not a defect in the file being scanned, and a future
``ParseStage`` (E07-04) turns that into a skipped file rather than a failed scan.

**Extraction.** Identifiers, string content, comments and (for Python) docstrings are found by
one combined compiled query (``codekavach.parsing.queries.load_combined_query``, over E07-02's
separate, separately readable ``.scm`` files), not by walking the tree again and not by one
``QueryCursor.captures`` call per kind: that call has a real fixed cost of its own, and a file
whose query has no matching name for a language (``docstrings`` has one only for Python)
contributes nothing for it rather than erroring. One further, optional, duck-typed spec hook,
``literal_context``, is not expressible as a query capture: it needs each string's position in
its call, assignment or concatenation, not just its node type; it is not part of the
``LanguageSpec`` protocol itself, because most languages need no such hook at all.

**Timeout mechanism.** ``tree_sitter.Parser.timeout_micros`` is deprecated in the pinned
tree-sitter release in favour of a ``progress_callback`` passed to ``parse()``, but that
replacement only takes effect when parsing through a chunked read callback, and cancelling a
chunked parse mid-way segfaults the interpreter in this release (reproduced while building this
module; not something a ``try``/``except`` can recover from). ``timeout_micros`` with a plain
``bytes`` argument is the only cancellation path that is both correct and does not crash the
process, so this module uses it and narrowly silences its one ``DeprecationWarning``. Revisit
this once a tree-sitter release fixes the chunked-parse crash.
"""

import warnings

from tree_sitter import Node as TSNode
from tree_sitter import Parser as TSParser
from tree_sitter import QueryCursor
from tree_sitter import Tree as TSTree

from codekavach.config.models.parsing import ParsingSettings
from codekavach.core.log import get_logger
from codekavach.core.models import Language, Location, RawCode
from codekavach.parsing.literals import LiteralContext, classify_literal
from codekavach.parsing.loader import grammar_available, load_language
from codekavach.parsing.models import TIMED_OUT, LiteralSpan, ParsedFile
from codekavach.parsing.normalise import normalise_source
from codekavach.parsing.positions import LineIndex
from codekavach.parsing.queries import load_combined_query
from codekavach.parsing.spec import REGISTRY, LanguageSpec, UnknownLanguageError

_log = get_logger("codekavach.parsing")

MICROS_PER_SECOND = 1_000_000


class ParseUnavailableError(Exception):
    """``language`` has no installed grammar; not a defect in the file being parsed."""

    def __init__(self, language: Language) -> None:
        self.language = language
        super().__init__(f"no tree-sitter grammar is available for {language.value!r}")


class SourceTooLargeError(Exception):
    """The source exceeds ``parsing.max_source_bytes``."""

    def __init__(self, path: str, size: int, limit: int) -> None:
        self.path = path
        self.size = size
        self.limit = limit
        super().__init__(f"{path}: {size} bytes exceeds the {limit}-byte parsing limit")


def _walk_errors(tree: TSTree, max_node_count: int) -> tuple[int, bool]:
    """One cursor-based walk: the ``ERROR``/``MISSING`` count and whether the node cap was hit.

    Uses ``Tree.walk()`` rather than recursing through ``Node.children``: the cursor moves over
    the existing tree instead of allocating a fresh list of child ``Node`` wrappers at every
    step, which matters here because this walk runs once per file of a scan.
    """
    cursor = tree.walk()
    error_count = 0
    node_count = 0
    reached_root = False
    while not reached_root:
        node = cursor.node
        assert node is not None  # noqa: S101 - a cursor from Tree.walk() always has one
        node_count += 1
        if node_count > max_node_count:
            return error_count, True
        if node.is_error or node.is_missing:
            error_count += 1
        if cursor.goto_first_child():
            continue
        if cursor.goto_next_sibling():
            continue
        retracing = True
        while retracing:
            if not cursor.goto_parent():
                retracing = False
                reached_root = True
            elif cursor.goto_next_sibling():
                retracing = False
    return error_count, False


# The query files combined into one compiled query per language, and the capture name each
# contributes. Running one QueryCursor.captures() call instead of one per kind matters because
# the call has a real fixed cost of its own, and this runs once per file of a scan.
_EXTRACTION_QUERY_NAMES = ("identifiers", "strings", "comments", "docstrings")


def _query_captures(language: Language, tree: TSTree) -> dict[str, list[TSNode]]:
    """Every node captured by this language's combined query, grouped by capture name.

    A capture name whose query file does not exist for ``language`` (``"docstrings"`` has one
    only for Python) is simply absent from the result, not an error.
    """
    query = load_combined_query(language, _EXTRACTION_QUERY_NAMES)
    return QueryCursor(query).captures(tree.root_node)


def _node_text(node: TSNode) -> str:
    return (node.text or b"").decode("utf-8", errors="replace")


def _build_identifiers(
    locations: list[Location], nodes: list[TSNode]
) -> tuple[tuple[Location, str], ...]:
    return tuple(zip(locations, (_node_text(node) for node in nodes), strict=True))


def _build_comments(locations: list[Location]) -> tuple[Location, ...]:
    return tuple(sorted(locations, key=lambda loc: loc.sort_key()))


def _build_literals(
    locations: list[Location], nodes: list[TSNode], spec: LanguageSpec | None
) -> tuple[LiteralSpan, ...]:
    literal_context = getattr(spec, "literal_context", None)
    spans = []
    for node, location in zip(nodes, locations, strict=True):
        context: LiteralContext | None = literal_context(node) if literal_context else None
        text = _node_text(node)
        spans.append(
            LiteralSpan(location=location, kind=classify_literal(text, context), raw_text=text)
        )
    return tuple(spans)


def _extract(
    language: Language, tree: TSTree, path: str, line_index: LineIndex
) -> tuple[tuple[tuple[Location, str], ...], tuple[LiteralSpan, ...], tuple[Location, ...]]:
    """Identifiers, string literals and comments, from one combined query plus one optional hook."""
    try:
        spec: LanguageSpec | None = REGISTRY.get(language)
    except UnknownLanguageError:
        spec = None

    captures = _query_captures(language, tree)
    identifier_nodes = sorted(captures.get("identifier", []), key=lambda node: node.start_byte)
    string_nodes = captures.get("string_content", [])
    comment_nodes = captures.get("comment", [])
    docstring_nodes = captures.get("docstring", [])

    if docstring_nodes:
        docstring_ranges = {(node.start_byte, node.end_byte) for node in docstring_nodes}
        string_nodes = [
            node
            for node in string_nodes
            if node.parent is None
            or (node.parent.start_byte, node.parent.end_byte) not in docstring_ranges
        ]
        comment_nodes = comment_nodes + docstring_nodes
    string_nodes = sorted(string_nodes, key=lambda node: node.start_byte)
    comment_nodes = sorted(comment_nodes, key=lambda node: node.start_byte)

    # One locations() call for every span of every kind: path validation (and whatever other
    # per-call cost model_construct has) happens once per parse, not three times.
    all_nodes = identifier_nodes + string_nodes + comment_nodes
    all_locations = line_index.locations(
        path, [(node.start_byte, node.end_byte) for node in all_nodes]
    )
    identifier_locations = all_locations[: len(identifier_nodes)]
    string_locations = all_locations[
        len(identifier_nodes) : len(identifier_nodes) + len(string_nodes)
    ]
    comment_locations = all_locations[len(identifier_nodes) + len(string_nodes) :]

    identifiers = _build_identifiers(identifier_locations, identifier_nodes)
    literals = _build_literals(string_locations, string_nodes, spec)
    comments = _build_comments(comment_locations)
    return identifiers, literals, comments


def parse(
    path: str, language: Language, text: str, *, settings: ParsingSettings | None = None
) -> ParsedFile:
    """Parse ``text`` (the content of ``path``) as ``language``, within the ``[parsing]`` guards.

    Raises:
        ParseUnavailableError: no pinned grammar for ``language`` is installed.
        SourceTooLargeError: ``text`` is larger than ``parsing.max_source_bytes``.
    """
    limits = settings or ParsingSettings()
    if not grammar_available(language):
        raise ParseUnavailableError(language)
    original_size = len(text.encode("utf-8"))
    if original_size > limits.max_source_bytes:
        raise SourceTooLargeError(path, original_size, limits.max_source_bytes)

    normalised_text, hidden_chars = normalise_source(text, path)
    data = normalised_text.encode("utf-8")

    grammar = load_language(language)
    ts_parser = TSParser(grammar)
    # See the module docstring: the deprecation is expected and the replacement is unsafe.
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        # The type stub marks this read-only; it is a settable, if deprecated, attribute at
        # runtime (verified while building this module).
        ts_parser.timeout_micros = int(  # type: ignore[misc]
            limits.timeout_seconds * MICROS_PER_SECOND
        )
    # This pinned release raises ValueError("Parsing failed") on expiry instead of the
    # documented None return; both paths are treated as a timeout, any other ValueError
    # propagates.
    try:
        tree = ts_parser.parse(data)
    except ValueError as error:
        if str(error) != "Parsing failed":
            raise
        tree = None
    if tree is None:
        _log.debug("parse_timed_out", path=path, language=language.value)
        return ParsedFile(
            path=path,
            language=language,
            source=RawCode(text),
            error_count=TIMED_OUT,
            hidden_chars=hidden_chars,
        )

    error_count, cap_hit = _walk_errors(tree, limits.max_node_count)
    if cap_hit:
        _log.debug("parse_node_cap_exceeded", path=path, language=language.value)
        return ParsedFile(
            path=path,
            language=language,
            source=RawCode(text),
            error_count=TIMED_OUT,
            hidden_chars=hidden_chars,
        )

    line_index = LineIndex.build(normalised_text)
    identifiers, literals, comments = _extract(language, tree, path, line_index)
    return ParsedFile(
        path=path,
        language=language,
        source=RawCode(text),
        error_count=error_count,
        hidden_chars=hidden_chars,
        identifier_locations=identifiers,
        literal_spans=literals,
        comment_locations=comments,
    )
