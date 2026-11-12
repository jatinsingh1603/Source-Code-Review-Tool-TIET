"""The renamer contract and the part of renaming that no language changes.

Owning epic: E09. Issue E09-04. Normative layout: docs/ARCHITECTURE.md section 3.

``Renamer`` is the protocol of the M1 interface contract: a ``language`` and
``rename(source, plan)``. ``BaseRenamer`` composes plan building, validation and application, so a
language supplies only the rules that differ: what a name looks like after renaming
(``identifier_edits``), what its parse tells beyond the classification (``facts``) and which
strings name a binding (``is_name_string``).

**One token per name.** Every internal occurrence of a name gets the same token (the kind of the
strongest binding of that name in the file), so a definition and every use agree whatever the
scope, and shadowing is kept as it was. The tokens come from the E09-01 generator, so they depend
on the scan salt and the set of names only (I5).

**One plan.** Identifier, literal and comment edits are collected from the original, merged and
validated by ``RenamePlan.build``, and applied once (``apply.apply_plan``).

**Strings that name a binding.** A string equal to an internal name that the classifier marked as
dynamic (``getattr(x, "name")``) or as a serialisation field is rewritten to the token, so the
code stays consistent; a string equal to a name the classifier kept in clear is not shaped, so
the pair stays consistent in clear. Both are counted.

**Fail closed (I4).** A file that does not parse cleanly, a decision that does not sit on the
name it claims, a token that collides with a public name, an unknown symbol kind or an invalid
plan raises ``PseudonymError``; no text is produced.
"""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Final, Protocol

from tree_sitter import Node

from codekavach.core.models import Language, PrivacyLevel, RawCode
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.apply import apply_plan
from codekavach.privacy.pseudonymise.classify import (
    NAME_ONLY_RULES,
    ClassificationDecision,
    ClassificationNote,
    ClassificationResult,
    IdentifierClass,
    Rule,
)
from codekavach.privacy.pseudonymise.comments import blank_comments
from codekavach.privacy.pseudonymise.generator import (
    SYMBOL_KINDS,
    PseudonymGenerator,
    PseudonymKind,
)
from codekavach.privacy.pseudonymise.literals import shape
from codekavach.privacy.pseudonymise.plan import (
    EditReason,
    RenameEdit,
    RenamePlan,
    edits_around_placeholders,
)

if TYPE_CHECKING:
    from codekavach.parsing.models import ParsedFile

BLANK_MARKER: Final = "x"
_NAME_NOTES: Final = frozenset(
    {ClassificationNote.DYNAMIC_NAME, ClassificationNote.SERIALISATION_FIELD}
)
# The strongest binding of a name decides its token kind; a class beats a function beats a value.
_KIND_ORDER: Final = (
    "class",
    "function",
    "method",
    "constant",
    "field",
    "parameter",
    "variable",
    "import",
    "module",
)
_RANK: Final = {kind: rank for rank, kind in enumerate(_KIND_ORDER)}
_TOKEN_LIKE: Final = re.compile(r"^#?[A-Za-z_$][\w$]*$")


def _is_public_specifier(content: str, allowlist: PublicAllowlist) -> bool:
    """Whether the text of an import string names a package that the bundled data lists.

    A relative path is never public; ``@scope/name/sub`` is judged by ``@scope/name``.
    """
    parts = content.split("/")
    if not parts[0] or parts[0].startswith("."):
        return False
    top = "/".join(parts[:2]) if parts[0].startswith("@") else parts[0]
    return top in allowlist.package_names()


class UnsupportedLanguageError(PseudonymError):
    """No renamer is registered for a language."""


class Renamer(Protocol):
    """The M1 interface contract: a language and a function from a plan to text."""

    @property
    def language(self) -> Language:
        """The language this renamer rewrites."""
        ...

    def rename(self, source: RawCode, plan: RenamePlan) -> str:
        """The text of ``source`` with ``plan`` applied; raises ``PseudonymError`` if invalid."""
        ...


@dataclass(frozen=True, slots=True)
class RenameReport:
    """What one plan does, as counts only; never a name or a piece of text."""

    identifiers_renamed: int = 0
    shorthand_expanded: int = 0
    literals_shaped: int = 0
    name_strings_rewritten: int = 0
    comments_blanked: int = 0
    kept_identifier: int = 0


@dataclass(frozen=True, slots=True)
class SourceFacts:
    """What the parse tells that the classification does not: byte offsets of special nodes."""

    shorthand_starts: frozenset[int] = field(default=frozenset())
    specifier_starts: frozenset[int] = field(
        default=frozenset()
    )  # start of the text, not the quote
    # Go struct tags: (start of the tag text, name of the field the tag belongs to).
    tag_fields: tuple[tuple[int, str], ...] = ()
    # C and C++ macro bodies: the start of each ``preproc_arg`` token.
    macro_starts: frozenset[int] = field(default=frozenset())


class ByteOffsets:
    """1-based (line, code-point column) positions to UTF-8 byte offsets, for one text."""

    __slots__ = ("_ascii", "_lines", "_starts", "all_ascii", "starts")

    def __init__(self, text: str) -> None:
        self.all_ascii = text.isascii()
        self._lines = text.split("\n")
        self._starts: list[int] = []
        self._ascii: list[bool] = []
        offset = 0
        for line in self._lines:
            self._starts.append(offset)
            is_ascii = line.isascii()
            self._ascii.append(is_ascii)
            offset += (len(line) if is_ascii else len(line.encode("utf-8"))) + 1
        self.starts = self._starts

    def at(self, line: int, column: int | None) -> int:
        """The byte offset of a position; raises ``PseudonymError`` for one outside the text."""
        if column is None or line < 1 or line > len(self._lines) or column < 1:
            raise PseudonymError("a span has no position inside the text")
        text = self._lines[line - 1]
        if column - 1 > len(text):
            raise PseudonymError("a span lies beyond the end of its line")
        if self._ascii[line - 1]:
            return self._starts[line - 1] + column - 1
        return self._starts[line - 1] + len(text[: column - 1].encode("utf-8"))


def _kind_of(kind: str) -> PseudonymKind:
    try:
        return SYMBOL_KINDS[kind]
    except KeyError:
        raise PseudonymError("a symbol has a kind the pseudonym generator does not know") from None


def name_tokens(
    classification: ClassificationResult,
    generator: PseudonymGenerator,
    canonical: Callable[[str], str] = str,
) -> dict[str, str]:
    """The token of every internal name of a file; one token per name.

    The names of a kind are numbered together (``prepare``), so the numbers depend on the salt and
    the set of names, not on the order of the code (I5). ``canonical`` maps the spellings of one
    name to a single key (Ruby's ``@conn``, ``:conn`` and ``conn``), so they share a token.

    Raises:
        PseudonymError: a symbol kind is unknown, or a token equals a name that stays in clear.
    """
    strongest: dict[str, str] = {}
    spellings: dict[str, set[str]] = {}
    public: set[str] = set()
    for decision in classification.decisions:
        if decision.classification is IdentifierClass.PUBLIC:
            public.add(decision.name)
            continue
        key = canonical(decision.name)
        spellings.setdefault(key, set()).add(decision.name)
        current = strongest.get(key)
        if current is None or _RANK.get(decision.kind, 99) < _RANK.get(current, 99):
            strongest[key] = decision.kind
    by_kind: dict[PseudonymKind, list[str]] = {}
    for name, kind in strongest.items():
        by_kind.setdefault(_kind_of(kind), []).append(name)
    for kind, names in by_kind.items():
        generator.prepare(kind, names)
    made = {key: generator.token(_kind_of(kind), key) for key, kind in strongest.items()}
    if public.intersection(made.values()):
        raise PseudonymError("a pseudonym equals a name that stays in clear")
    return {name: made[key] for key, names in spellings.items() for name in names}


class BaseRenamer:
    """Plan building and application shared by every language; subclasses add the differences."""

    language: ClassVar[Language]

    # --- what a language may change -------------------------------------------------------

    def facts(self, parsed: "ParsedFile") -> SourceFacts:
        """Byte offsets of the nodes whose rewrite differs from a plain rename."""
        return SourceFacts()

    @staticmethod
    def canonical_name(name: str) -> str:
        """The key under which the spellings of one name share a token (default: the name)."""
        return name

    def identifier_edits(
        self, name: str, token: str, start: int, end: int, facts: SourceFacts
    ) -> list[RenameEdit]:
        """The edit that renames the occurrence at ``start:end`` to ``token``."""
        return [RenameEdit(start, end, token, EditReason.IDENTIFIER)]

    def is_name_string(self, node: Node | None) -> bool:
        """Whether a string, by where it sits, names a binding (``__all__``, an annotation)."""
        return False

    def is_public_specifier(self, content: str, allowlist: PublicAllowlist) -> bool:
        """Whether the text of an import string names a package that stays in clear."""
        return _is_public_specifier(content, allowlist)

    def literal_edits(
        self, original: str, start: int, end: int, tokens: dict[str, str], facts: SourceFacts
    ) -> list[RenameEdit] | None:
        """The edits a language makes for a string by its place (a Go struct tag), or ``None``.

        ``None`` leaves the string to the common path. An empty list keeps the string as written.
        """
        return None

    # --- the contract ---------------------------------------------------------------------

    def rename(self, source: RawCode, plan: RenamePlan) -> str:
        """Apply ``plan`` to ``source``."""
        return apply_plan(source, plan)

    def plan(
        self,
        parsed: "ParsedFile",
        classification: ClassificationResult,
        generator: PseudonymGenerator,
        *,
        allowlist: PublicAllowlist,
        level: PrivacyLevel = PrivacyLevel.L3,
    ) -> RenamePlan:
        """The validated plan for ``parsed``; see ``plan_with_report`` for the counts."""
        return self.plan_with_report(
            parsed, classification, generator, allowlist=allowlist, level=level
        )[0]

    def plan_with_report(
        self,
        parsed: "ParsedFile",
        classification: ClassificationResult,
        generator: PseudonymGenerator,
        *,
        allowlist: PublicAllowlist,
        level: PrivacyLevel = PrivacyLevel.L3,
    ) -> tuple[RenamePlan, RenameReport]:
        """The validated plan for ``parsed`` and what it does, as counts.

        Raises:
            PseudonymError: the file has syntax errors, the classification does not fit the
                text, a literal cannot be shaped, or the plan is invalid. No text is produced.
        """
        if parsed.language is not self.language:
            raise PseudonymError("the file is not in the language of this renamer")
        if parsed.error_count != 0 or parsed.tree is None:
            raise PseudonymError("a file with syntax errors is not renamed")
        text = parsed.source.expose()
        data = text.encode("utf-8")
        offsets = ByteOffsets(text)
        tokens = name_tokens(classification, generator, self.canonical_name)
        facts = self.facts(parsed)
        string_names = {
            d.name
            for d in classification.decisions
            if d.classification is IdentifierClass.INTERNAL and d.notes & _NAME_NOTES
        }
        identifiers, shorthand, kept = self._identifier_edits(
            classification.decisions, tokens, facts, data, offsets
        )
        literals, shaped, name_strings = self._literal_edits(
            parsed,
            classification=classification,
            generator=generator,
            allowlist=allowlist,
            level=level,
            tokens=tokens,
            string_names=string_names,
            facts=facts,
            data=data,
            offsets=offsets,
        )
        comments = self._comment_edits(parsed, text, data, offsets)
        plan = RenamePlan.build(identifiers, literals, comments, source=data)
        report = RenameReport(
            identifiers_renamed=len(identifiers),
            shorthand_expanded=shorthand,
            literals_shaped=shaped,
            name_strings_rewritten=name_strings,
            comments_blanked=len(parsed.comments()),
            kept_identifier=classification.counts.kept_identifier + kept,
        )
        return plan, report

    # --- collection -----------------------------------------------------------------------

    def _identifier_edits(
        self,
        decisions: Iterable[ClassificationDecision],
        tokens: dict[str, str],
        facts: SourceFacts,
        data: bytes,
        offsets: ByteOffsets,
    ) -> tuple[list[RenameEdit], int, int]:
        decisions = tuple(decisions)
        public_parameters = {
            d.name
            for d in decisions
            if d.kind == "parameter"
            and d.classification is IdentifierClass.PUBLIC
            and d.rule in NAME_ONLY_RULES
        }
        edits: list[RenameEdit] = []
        shorthand = kept = 0
        encoded: dict[str, bytes] = {}
        line_starts = offsets.starts
        known_lines = len(line_starts)
        for decision in decisions:
            if decision.classification is not IdentifierClass.INTERNAL:
                continue
            name = decision.name
            if decision.rule is Rule.KEYWORD_OF_INTERNAL and name in public_parameters:
                kept += 1  # the parameter it binds stays in clear, so the keyword must too
                continue
            where = decision.location
            name_bytes = encoded.get(name)
            if name_bytes is None:
                name_bytes = encoded[name] = name.encode("utf-8")
            column = where.start_col
            if offsets.all_ascii and column is not None and 1 <= where.start_line <= known_lines:
                start = line_starts[where.start_line - 1] + column - 1
            else:
                start = offsets.at(where.start_line, column)
            end = start + len(name_bytes)
            if data[start:end] != name_bytes:
                raise PseudonymError("an identifier does not sit where the classification says")
            made = self.identifier_edits(name, tokens[name], start, end, facts)
            shorthand += sum(1 for edit in made if edit.reason is EditReason.SHORTHAND_KEY)
            edits.extend(made)
        return edits, shorthand, kept

    def _literal_edits(
        self,
        parsed: "ParsedFile",
        *,
        classification: ClassificationResult,
        generator: PseudonymGenerator,
        allowlist: PublicAllowlist,
        level: PrivacyLevel,
        tokens: dict[str, str],
        string_names: set[str],
        facts: SourceFacts,
        data: bytes,
        offsets: ByteOffsets,
    ) -> tuple[list[RenameEdit], int, int]:
        edits: list[RenameEdit] = []
        shaped_count = name_strings = 0
        root = parsed.tree.root_node if parsed.tree is not None else None
        for span in parsed.string_literals():
            where = span.location
            start = offsets.at(where.start_line, where.start_col)
            end = offsets.at(where.end_line, where.end_col)
            original = span.raw_text
            if data[start:end] != original.encode("utf-8"):
                raise PseudonymError("a string literal does not sit where the parse says")
            if original in classification.kept_dynamic:
                continue  # the pair stays in clear and consistent, and is counted as kept
            special = self.literal_edits(original, start, end, tokens, facts)
            if special is not None:
                edits.extend(special)
                name_strings += len(special)
                continue
            if start in facts.specifier_starts and self.is_public_specifier(original, allowlist):
                continue  # ``require('express')``: a listed package is recognisable by name
            token = tokens.get(original)
            if token is not None and (
                original in string_names
                or (
                    root is not None
                    and self.is_name_string(root.descendant_for_byte_range(start, end))
                )
            ):
                edits.append(RenameEdit(start, end, token, EditReason.NAME_STRING))
                name_strings += 1
                continue
            new = shape(span, generator=generator, allowlist=allowlist, level=level)
            if new != original:
                edits.extend(edits_around_placeholders(start, original, new, EditReason.LITERAL))
                shaped_count += 1
        return edits, shaped_count, name_strings

    @staticmethod
    def _comment_edits(
        parsed: "ParsedFile", text: str, data: bytes, offsets: ByteOffsets
    ) -> list[RenameEdit]:
        spans = parsed.comments()
        if not spans:
            return []
        blanked = blank_comments(text, spans, marker=BLANK_MARKER).encode("utf-8")
        if len(blanked) != len(data):
            raise PseudonymError("blanking changed the length of the text")
        edits: list[RenameEdit] = []
        for where in spans:
            start = offsets.at(where.start_line, where.start_col)
            end = offsets.at(where.end_line, where.end_col)
            old, new = data[start:end].decode("utf-8"), blanked[start:end].decode("utf-8")
            if old != new:
                edits.extend(edits_around_placeholders(start, old, new, EditReason.COMMENT))
        return edits
