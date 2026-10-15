"""Error-tolerant, bounded tree-sitter parsing (E07-01).

Owning epic: E07.

``parse`` is the single entry point every later stage calls. It normalises the text (Unicode
hidden-character substitution, this module's own ``normalise_source``), enforces the size, time
and node-count guards of ``[parsing]``, counts ``ERROR``/``MISSING`` nodes instead of raising on
them, and converts every span it reports through one ``LineIndex`` built from the *normalised*
text, because that is the byte stream tree-sitter actually walked. A parse that cannot run at all
because no grammar is installed is reported as ``ParseUnavailableError``, not an error: a missing
grammar is a fact about the environment, not a defect in the file being scanned, and a future
``ParseStage`` (E07-04) turns that into a skipped file rather than a failed scan.

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
from tree_sitter import Tree as TSTree

from codekavach.config.models.parsing import ParsingSettings
from codekavach.core.log import get_logger
from codekavach.core.models import Language, Location, RawCode
from codekavach.parsing.loader import grammar_available, load_language
from codekavach.parsing.models import TIMED_OUT, LiteralSpan, ParsedFile
from codekavach.parsing.normalise import normalise_source
from codekavach.parsing.positions import LineIndex
from codekavach.parsing.spec import REGISTRY, NodeKind, UnknownLanguageError

_log = get_logger("codekavach.parsing")

MICROS_PER_SECOND = 1_000_000
# The three NodeKinds ParsedFile exposes; a registered spec need not classify any others for
# this issue to use them.
_EXTRACTED_KINDS = (NodeKind.IDENTIFIER, NodeKind.STRING, NodeKind.COMMENT)


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


def _type_to_kind(language: Language) -> dict[str, NodeKind]:
    """Reverse ``node_kinds()`` of the registered spec, or ``{}`` when none is registered."""
    try:
        spec = REGISTRY.get(language)
    except UnknownLanguageError:
        return {}
    mapping = spec.node_kinds()
    return {
        type_name: kind for kind in _EXTRACTED_KINDS for type_name in mapping.get(kind, frozenset())
    }


def _walk(
    tree: TSTree, max_node_count: int, type_to_kind: dict[str, NodeKind]
) -> tuple[int, bool, dict[NodeKind, list[TSNode]]]:
    """One cursor-based walk: error/missing count, whether the node cap was hit, kind buckets.

    Uses ``Tree.walk()`` rather than recursing through ``Node.children``: the cursor moves over
    the existing tree instead of allocating a fresh list of child ``Node`` wrappers at every
    step, which matters here because this walk runs once per file of a scan.
    """
    cursor = tree.walk()
    error_count = 0
    node_count = 0
    buckets: dict[NodeKind, list[TSNode]] = {}
    reached_root = False
    while not reached_root:
        node = cursor.node
        assert node is not None  # noqa: S101 - a cursor from Tree.walk() always has one
        node_count += 1
        if node_count > max_node_count:
            return error_count, True, buckets
        if node.is_error or node.is_missing:
            error_count += 1
        kind = type_to_kind.get(node.type)
        if kind is not None:
            buckets.setdefault(kind, []).append(node)
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
    return error_count, False, buckets


def _locations(nodes: list[TSNode], path: str, line_index: LineIndex) -> tuple[Location, ...]:
    return tuple(line_index.location(path, node.start_byte, node.end_byte) for node in nodes)


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

    line_index = LineIndex.build(normalised_text)
    type_to_kind = _type_to_kind(language)
    error_count, cap_hit, buckets = _walk(tree, limits.max_node_count, type_to_kind)
    if cap_hit:
        _log.debug("parse_node_cap_exceeded", path=path, language=language.value)
        return ParsedFile(
            path=path,
            language=language,
            source=RawCode(text),
            error_count=TIMED_OUT,
            hidden_chars=hidden_chars,
        )

    identifier_locations = _locations(buckets.get(NodeKind.IDENTIFIER, []), path, line_index)
    comment_locations = _locations(buckets.get(NodeKind.COMMENT, []), path, line_index)
    literal_spans = tuple(
        LiteralSpan(
            location=line_index.location(path, node.start_byte, node.end_byte),
            kind="natural",
            raw_text=(node.text or b"").decode("utf-8", errors="replace"),
        )
        for node in buckets.get(NodeKind.STRING, [])
    )
    return ParsedFile(
        path=path,
        language=language,
        source=RawCode(text),
        error_count=error_count,
        hidden_chars=hidden_chars,
        identifier_locations=identifier_locations,
        literal_spans=literal_spans,
        comment_locations=comment_locations,
    )
