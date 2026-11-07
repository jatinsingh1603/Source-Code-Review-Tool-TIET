"""From a slice and its redaction to the payload the provider may see (E09-05).

Owning epic: E09.

``Pseudonymiser.apply`` is the one place where the pieces of E09 meet. The order is fixed: lay out
the slice (``layout_of``), check that the redaction kept the layout, classify the identifiers,
build and apply one rename plan, put the fixed lines (header, labels, elision markers, stub
summaries) back, verify that the result parses to the node-type sequence of its input, build the
line map, run the survival self-check, and only then build the ``SanitisedPayload``.

The text that the redactor works on is ``layout_of(slice_, level).text``. The renamer blanks
comments, which are most of the fixed lines; they are put back afterwards from the layout, which
holds no client data.

Levels. L1 replaces only values: the redacted text is the payload and nothing is classified or
renamed. L2 and L3 take the full path. L4 sends no code and is delivered by epic E27, so it
raises ``NotImplementedError``; L0 sends nothing, so it raises ``PseudonymError``.

Failure. Any exception from a step is raised as ``PseudonymError`` with the type of the failure
and no text, and no partial payload is ever returned (invariant I4). There is no path that
returns the original text.
"""

import re
from collections import Counter
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from codekavach.core.models import (
    CodeSlice,
    PrivacyLevel,
    RawCode,
    SanitisedPayload,
    SanitisedText,
    SegmentRole,
)
from codekavach.core.models.payload import find_placeholders
from codekavach.core.models.text import split_lines
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.imports import DefaultImportResolver, attach_imports
from codekavach.parsing.symbols import build_symbol_table
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.classify import ConservativeCounts, classify_all
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator, PseudonymKind
from codekavach.privacy.pseudonymise.linemap import (
    LayoutLine,
    LineKind,
    PayloadLayout,
    layout_of,
    map_layout,
)
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.pseudonymise.plan import EditReason, file_labels
from codekavach.privacy.pseudonymise.renamers.base import RenameReport
from codekavach.privacy.pseudonymise.renamers.registry import RenamerRegistry, default_registry
from codekavach.privacy.pseudonymise.validate import check_against, signature_of
from codekavach.privacy.redact.redactor import RedactionResult
from codekavach.privacy.slicing.elide import comment_prefix

PSEUDONYMISE_VERSION: Final = "e09.1"
"""The version of the transformation. A change here invalidates cached verdicts, because a
cached answer refers to the payload that a given version produced."""

_MIN_SURVIVOR_LENGTH: Final = 4
_WORD: Final = re.compile(r"[\w$]+")
_IDENTIFIER: Final = re.compile(r"#?[\w$]+")


@dataclass(frozen=True, slots=True)
class PayloadProvenance:
    """What was kept and what was conservative in one payload; counts and public names only.

    Held by the caller and not part of ``SanitisedPayload``, whose fields are fixed. Every field
    is safe to record: no original identifier of the client appears in it.
    """

    pseudonymise_version: str
    level: PrivacyLevel
    allowlist_version: str | None
    grammar_version: str | None
    kept_public_names: tuple[str, ...] = ()
    conservative: ConservativeCounts = field(default_factory=ConservativeCounts)
    report: RenameReport = field(default_factory=RenameReport)


@dataclass(frozen=True, slots=True, repr=False)
class PseudonymisationResult:
    """The payload, the mappings to persist, and the provenance."""

    payload: SanitisedPayload
    batch: MappingBatch
    provenance: PayloadProvenance

    def __repr__(self) -> str:
        return f"PseudonymisationResult({self.provenance.level.value})"


class Pseudonymiser:
    """Builds the payload of one candidate; it holds settings, never a salt or a text."""

    def __init__(
        self,
        *,
        allowlist_extra: Collection[str] = (),
        project_root: Path | None = None,
        registry: RenamerRegistry | None = None,
    ) -> None:
        self._extra = tuple(allowlist_extra)
        self._root = project_root if project_root is not None else Path()
        self._registry = registry if registry is not None else default_registry()

    @staticmethod
    def layout(slice_: CodeSlice, level: PrivacyLevel) -> PayloadLayout:
        """The layout of ``slice_``: its ``text`` is what the redactor must be given."""
        return layout_of(slice_, level)

    def apply(
        self,
        slice_: CodeSlice,
        redaction: RedactionResult,
        *,
        salt: ScanSalt,
        level: PrivacyLevel,
        scan_id: str,
    ) -> tuple[SanitisedPayload, MappingBatch]:
        """The payload and the mapping batch of ``slice_``; see ``process`` for the provenance."""
        result = self.process(slice_, redaction, salt=salt, level=level, scan_id=scan_id)
        return result.payload, result.batch

    def process(
        self,
        slice_: CodeSlice,
        redaction: RedactionResult,
        *,
        salt: ScanSalt,
        level: PrivacyLevel,
        scan_id: str,
    ) -> PseudonymisationResult:
        """The payload, the mapping batch and the provenance of ``slice_``.

        ``redaction`` is the redaction of ``Pseudonymiser.layout(slice_, level).text``.

        Raises:
            PseudonymError: any step failed; the message names the step and no text.
            NotImplementedError: the level is L4, which epic E27 delivers.
        """
        if level is PrivacyLevel.L0:
            raise PseudonymError("nothing is sent at L0, so there is no payload")
        if level is PrivacyLevel.L4:
            raise NotImplementedError(
                "L4 sends abstract facts and no code; it is delivered by epic E27 (issue E27-01)"
            )
        try:
            return self._process(slice_, redaction, salt, level, scan_id)
        except PseudonymError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed: every failure aborts the candidate
            raise PseudonymError(f"pseudonymisation failed ({type(exc).__name__})") from None

    # --- the steps -------------------------------------------------------------------------

    def _process(
        self,
        slice_: CodeSlice,
        redaction: RedactionResult,
        salt: ScanSalt,
        level: PrivacyLevel,
        scan_id: str,
    ) -> PseudonymisationResult:
        layout = layout_of(slice_, level)
        _check_redaction(layout, redaction)
        if level is PrivacyLevel.L1:
            line_map = map_layout(layout, redaction.text)
            payload = SanitisedPayload.build(
                candidate_id=slice_.candidate_id,
                slice_id=slice_.id,
                text=SanitisedText(redaction.text),
                level=level,
                line_map=line_map,
            )
            provenance = PayloadProvenance(PSEUDONYMISE_VERSION, level, None, None)
            return PseudonymisationResult(payload, MappingBatch(scan_id), provenance)
        return self._full(slice_, redaction, layout, salt=salt, level=level, scan_id=scan_id)

    def _full(
        self,
        slice_: CodeSlice,
        redaction: RedactionResult,
        layout: PayloadLayout,
        *,
        salt: ScanSalt,
        level: PrivacyLevel,
        scan_id: str,
    ) -> PseudonymisationResult:
        language = slice_.language
        spec = REGISTRY.get(language)
        renamer = self._registry.get(language)
        parsed = parse("payload", language, redaction.text)
        table = attach_imports(
            build_symbol_table(parsed, spec),
            parsed,
            DefaultImportResolver(language),
            project_root=self._root,
        )
        allowlist = PublicAllowlist.bundled(language, extra=self._extra)
        classification = classify_all(parsed, table, allowlist=allowlist)
        generator = PseudonymGenerator(salt)
        labels = file_labels(generator, (segment.path for segment in slice_.segments))
        plan, report = renamer.plan_with_report(
            parsed, classification, generator, allowlist=allowlist, level=level
        )
        renamed = renamer.rename(RawCode(redaction.text), plan)
        text = _restore_fixed_lines(layout, redaction.text, renamed, labels)
        expanded = [e.start_byte for e in plan.edits if e.reason is EditReason.SHORTHAND_KEY]
        if parsed.tree is None:
            raise PseudonymError("the redacted text has no syntax tree")
        check_against(signature_of(parsed.tree.root_node, expanded=expanded), text, spec)
        if Counter(find_placeholders(text)) != Counter(find_placeholders(redaction.text)):
            raise PseudonymError("pseudonymisation changed the placeholders of the text")
        line_map = map_layout(layout, text)
        assignments = generator.assignments()
        kept = classification.kept_public_names()
        _check_survival(text, assignments, frozenset(kept))
        primary = next(s for s in slice_.segments if s.role is SegmentRole.PRIMARY)
        batch = MappingBatch(
            scan_id,
            tuple(
                MappingEntry(token, original, kind, primary.path)
                for kind, original, token in assignments
            ),
        )
        payload = SanitisedPayload.build(
            candidate_id=slice_.candidate_id,
            slice_id=slice_.id,
            text=SanitisedText(text),
            level=level,
            pseudonym_count=len(assignments),
            line_map=line_map,
        )
        provenance = PayloadProvenance(
            pseudonymise_version=PSEUDONYMISE_VERSION,
            level=level,
            allowlist_version=allowlist.version(),
            grammar_version=spec.grammar_version,
            kept_public_names=kept,
            conservative=classification.counts,
            report=report,
        )
        return PseudonymisationResult(payload, batch, provenance)


def _check_redaction(layout: PayloadLayout, redaction: RedactionResult) -> None:
    """The redaction must have the line structure and the fixed lines of the layout."""
    lines = split_lines(redaction.text)
    if len(lines) != len(layout.lines):
        raise PseudonymError(
            f"the redaction has {len(lines)} lines and the layout {len(layout.lines)}"
        )
    for expected, actual in zip(layout.lines, lines, strict=True):
        if expected.kind not in (LineKind.SEGMENT, LineKind.STUB) and expected.text != actual:
            raise PseudonymError("the redaction changed a fixed line of the layout")


def _restore_fixed_lines(
    layout: PayloadLayout, redacted: str, renamed: str, labels: dict[str, str]
) -> str:
    """``renamed`` with the lines that the renamer blanked put back from the layout."""
    prefix = comment_prefix(layout.language)
    before = split_lines(redacted)
    lines = split_lines(renamed)
    if len(lines) != len(layout.lines):
        raise PseudonymError("renaming changed the number of lines")
    for number, line in enumerate(layout.lines):
        lines[number] = _fixed_line(line, before[number], labels, prefix, lines[number])
    return "\n".join(lines) + "\n"


def _fixed_line(
    line: LayoutLine, redacted: str, labels: dict[str, str], prefix: str, renamed: str
) -> str:
    if line.kind is LineKind.LABEL and line.path is not None:
        return f"{prefix} {labels[line.path]}"
    if line.kind in (LineKind.HEADER, LineKind.ELISION, LineKind.SEPARATOR):
        return line.text
    if line.kind is LineKind.STUB and redacted.lstrip().startswith(prefix):
        return redacted  # a summary line of ours; a stub holds no comment from the source
    return renamed


def _check_survival(
    text: str,
    assignments: Sequence[tuple[PseudonymKind, str, str]],
    kept: frozenset[str],
) -> None:
    """Raise if an original name of four characters or more is still in ``text``.

    This repeats a part of the egress guard on purpose (E12-02, the authoritative control): a
    renamer bug then fails here, close to its cause, and does not rely on a later stage. A name
    that stays in clear by design is allowed: a public name, and a shorthand key that the renamer
    wrote as ``key: token`` with its own token.
    """
    words = set(_WORD.findall(text))
    for _, original, token in assignments:
        if len(original) < _MIN_SURVIVOR_LENGTH or original in kept:
            continue
        if _IDENTIFIER.fullmatch(original):
            name = original.removeprefix("#")
            if name not in words:
                continue
            follow = re.compile(rf"\s*:\s*{re.escape(token)}(?![\w$])")
            for found in re.finditer(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text):
                if not follow.match(text, found.end()):
                    raise PseudonymError("an original name survives in the payload")
        elif original in text:
            raise PseudonymError("an original name survives in the payload")
