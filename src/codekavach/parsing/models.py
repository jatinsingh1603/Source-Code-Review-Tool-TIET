"""``ParsedFile``, the output of ``codekavach.parsing.parse`` (E07-01).

Owning epic: E07.

``ParsedFile`` is a plain class, not a ``KavachModel``: a later epic's scope resolver and call
graph (E07-03, E07-04) need the underlying ``tree_sitter.Tree``, which wraps native memory and
cannot be validated, hashed or JSON-serialised the way a Pydantic model is. This module ships
only the shape this issue is responsible for: the file's identity, its raw source, how many
parse errors it had, which characters were hidden, and the three kinds of span every language
can report through the ``LanguageSpec`` protocol (``identifiers``, ``string_literals``,
``comments``); a later epic that needs the tree itself extends this module, not this issue.

``identifiers()`` pairs each ``Location`` with its text (E07-02): the pseudonymiser renames
exactly these occurrences and needs the text to decide how (``docs/ARCHITECTURE.md`` section
6.2 step 4), and re-reading it from the source by location is exactly the kind of per-node
string slicing ``LineIndex`` exists to avoid doing repeatedly.
"""

from dataclasses import dataclass, field
from typing import ClassVar, Literal

from codekavach.core.models import DataClassification, Language, Location, RawCode
from codekavach.parsing.normalise import EMPTY_HIDDEN_CHAR_REPORT, HiddenCharReport

# The timeout sentinel: a parse that exceeded parsing.timeout_seconds reports this error_count,
# distinct from a non-negative count of genuine ERROR/MISSING nodes.
TIMED_OUT = -1

LiteralKind = Literal["sql", "url", "path", "format", "regex", "natural"]


@dataclass(frozen=True, slots=True)
class LiteralSpan:
    """One string literal found while parsing, with a coarse content guess.

    ``kind`` defaults to ``"natural"`` here: classifying a literal's content as SQL, a URL, a
    path, a format string or a regular expression is a content heuristic, not a parsing concern,
    and is a later epic's job (the rule engine, E16, or the secret/PII detectors, E08).
    """

    location: Location
    kind: LiteralKind
    raw_text: str


@dataclass(frozen=True, slots=True)
class ParsedFile:
    """The result of parsing one file: client data, so ``DATA_CLASSIFICATION`` is ``RAW``.

    ``error_count`` is a non-negative count of ``ERROR`` and ``MISSING`` nodes, or the sentinel
    ``TIMED_OUT`` (``-1``) when the parse exceeded ``parsing.timeout_seconds``. ``identifiers``,
    ``string_literals`` and ``comments`` are empty whenever no ``LanguageSpec`` is registered for
    ``language``: this issue ships the walk that fills them from a spec's ``node_kinds()``, not
    any language's actual node-kind mapping (E07-02, E07-05).
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    path: str
    language: Language
    source: RawCode
    error_count: int
    hidden_chars: HiddenCharReport = field(default=EMPTY_HIDDEN_CHAR_REPORT)
    identifier_locations: tuple[tuple[Location, str], ...] = field(default=())
    literal_spans: tuple[LiteralSpan, ...] = field(default=())
    comment_locations: tuple[Location, ...] = field(default=())

    def identifiers(self) -> tuple[tuple[Location, str], ...]:
        """Every ``(location, text)`` identifier occurrence found while parsing, in source order."""
        return self.identifier_locations

    def string_literals(self) -> tuple[LiteralSpan, ...]:
        """Every string literal span found while parsing, in source order."""
        return self.literal_spans

    def comments(self) -> tuple[Location, ...]:
        """Every comment location found while parsing, in source order."""
        return self.comment_locations

    @property
    def timed_out(self) -> bool:
        """True when the parse hit ``parsing.timeout_seconds`` (the ``error_count`` sentinel)."""
        return self.error_count == TIMED_OUT
