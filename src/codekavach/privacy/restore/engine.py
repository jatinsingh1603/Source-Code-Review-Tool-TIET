"""The restore engine: de-pseudonymise a model verdict and anchor it to real file lines (E10-02).

Owning epic: E10 (issue E10-02). Invariant I3: ``codekavach.privacy.restore`` is one of the two
packages that may hold a ``MappingRecord``; the engine reads originals through ``Vault.lookup_many``
for the duration of one ``restore`` call, never logs them and never keeps them afterwards.

Model output is untrusted text. A token is accepted in the forms a model actually writes it
(different case, backticks, quotes, parentheses, a call suffix, a possessive or plural ``s``, a
space or hyphen for the underscore, a markdown emphasis wrapper), and a token with a different
number is never corrected to a near match: ``fn_11`` when only ``fn_1`` exists is unknown, because
attributing a claim to the wrong function is worse than dropping it. Every unknown reference drops
the sentence that holds it; every cited line is resolved through the payload's line map, and the
file line that comes out is authoritative, never the model's guess. A verdict whose first sentence
(its primary assertion) cannot be anchored is dropped as a whole, and its candidate keeps the
deterministic evidence (invariant I4). Restored text is checked for leftover tokens and
placeholders and a failed check raises ``RestoreError``.

Known limit: the check is over the restored text, so an original identifier that happens to match
the token grammar (``file_1`` in a client repository) makes that verdict fail closed.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final

from codekavach.core.models.enums import Confidence, PlaceholderKind
from codekavach.core.models.location import Location
from codekavach.core.models.payload import (
    PLACEHOLDER_PATTERN,
    SanitisedPayload,
    parse_placeholder,
)
from codekavach.core.models.slice import CodeSlice
from codekavach.core.models.verdict import LLMVerdict
from codekavach.privacy.restore.errors import RestoreError
from codekavach.privacy.restore.models import (
    DroppedClaim,
    DroppedSection,
    RestoredContext,
    RestoredVerdict,
    RestoreStats,
)
from codekavach.privacy.vault.store import Vault

_NAME_BODY: Final = (
    r"(?P<kind>fn|cls|var|param|field|mod|const|file)"
    r"[_ -](?P<number>[0-9]+)"
    r"(?P<role>_[a-z]+(?:_[a-z]+)*)?"
)
_NAME: Final = rf"(?i:{_NAME_BODY})"
_POSSESSIVE: Final = r"(?P<possessive>(?i:'s|s))?"
# A token may follow a non-word character, or a markdown emphasis marker that follows one.
_START: Final = r"(?:(?<![A-Za-z0-9_])|(?<=[^A-Za-z0-9_][_*]))"
# A placeholder wrapped in backticks loses them: the phrase that replaces it is plain prose.
_SCAN: Final = re.compile(
    rf"(?P<tick>`)?(?P<placeholder>{PLACEHOLDER_PATTERN})(?(tick)`)"
    rf"|{_START}{_NAME}{_POSSESSIVE}(?![A-Za-z0-9])"
)
_NAME_ONLY: Final = re.compile(_NAME)
_SENTENCE_BREAK: Final = re.compile(r"((?<=[.!?])\s+|\n+)")
_ACRONYMS: Final = frozenset({"api", "aws", "gcp", "jwt", "npm", "pypi", "sql", "ssh", "url"})


def _name_key(kind: str, number: str, role: str | None) -> str:
    """The vault key of a token: lower case, underscore separator, digits exactly as written."""
    return f"{kind.lower()}_{number}" + (role.lower() if role else "")


def _token_key(match: "re.Match[str]") -> str:
    return _name_key(match.group("kind"), match.group("number"), match.group("role"))


def _lookup_key(match: "re.Match[str]") -> str | None:
    """The key to look up for one match, or None for a placeholder that needs no lookup."""
    placeholder = match.group("placeholder")
    if placeholder is None:
        return _token_key(match)
    kind, _subtype, _index = parse_placeholder(placeholder)
    return placeholder if kind is PlaceholderKind.TERM else None


def _words(subtype: str) -> str:
    return " ".join(word.upper() if word in _ACRONYMS else word for word in subtype.split("_"))


def _secret_phrase(subtype: str) -> str:
    """A human phrase for a secret placeholder; the value is never in the payload to restore."""
    return f"the hardcoded {_words(subtype)}"


def _personal_data_phrase(subtype: str) -> str:
    return f"the {_words(subtype)}"


def check_restored_text(text: str) -> None:
    """Raise ``RestoreError`` when restored text still holds a pseudonym or a placeholder.

    Raises:
        RestoreError: a token or a placeholder survived restoration. The text is not quoted.
    """
    if _SCAN.search(text) is not None:
        raise RestoreError("restored text still holds a pseudonym or a placeholder")


def _sentences(text: str) -> list[tuple[str, str]]:
    """Split prose into ``(sentence, separator)`` pairs, so that kept text keeps its layout."""
    parts = _SENTENCE_BREAK.split(text)
    sentences = parts[0::2]
    separators = [*parts[1::2], ""]
    return list(zip(sentences, separators, strict=True))


@dataclass(slots=True, repr=False)
class _Scope:
    """The state of one ``restore`` call. It holds the originals it looked up: never shown."""

    found: Mapping[str, str]
    claims: list[DroppedClaim] = field(default_factory=list)
    unknown: int = 0
    unmappable: int = 0
    pseudonyms: int = 0
    secret: int = 0
    pii: int = 0
    term: int = 0

    def __repr__(self) -> str:
        return f"_Scope({len(self.claims)} claims)"


class RestoreEngine:
    """Turns a ``LLMVerdict`` in pseudonym space into a ``RestoredVerdict``.

    ``scan_id`` scopes every lookup to one scan, which is what a per-scan salt needs (the same
    pseudonym may stand for other originals in another scan). Without it the newest record of a
    name wins, as ``Vault.lookup`` does.
    """

    def __init__(self, vault: Vault, *, scan_id: str | None = None) -> None:
        self._vault = vault
        self._scan_id = scan_id

    def __repr__(self) -> str:
        return "RestoreEngine(<vault>)"

    def resolve_symbol(self, pseudonym: str) -> str | None:
        """The real name behind one pseudonym, or ``None`` when it is not a known token.

        This lets the context resolver turn a model's request for ``fn_12`` into a symbol. The
        number is matched exactly; no near match is ever tried.
        """
        match = _NAME_ONLY.fullmatch(pseudonym.strip())
        if match is None:
            return None
        key = _token_key(match)
        return self._lookup([key]).get(key)

    def restore(
        self, verdict: LLMVerdict, payload: SanitisedPayload, slice_: CodeSlice
    ) -> RestoredVerdict:
        """Restore one verdict. One vault query is issued for all its distinct tokens.

        Raises:
            RestoreError: the payload and the slice describe different candidates or slices, or
                restored text fails the leftover check.
        """
        if payload.candidate_id != slice_.candidate_id:
            raise RestoreError("the payload and the slice describe different candidates")
        if payload.slice_id is not None and payload.slice_id != slice_.id:
            raise RestoreError("the payload and the slice describe different slices")
        found = self._lookup(_keys_of(verdict))
        scope = _Scope(found=found)
        reasoning, primary_dropped = self._prose("reasoning", verdict.reasoning, scope)
        impact, _ = self._prose("impact", verdict.impact, scope)
        remediation, _ = self._prose("remediation", verdict.remediation, scope)
        needs = self._needs(verdict, scope)
        locations = self._locations(verdict.cited_lines, payload, slice_, scope)
        stats = RestoreStats(
            pseudonyms=scope.pseudonyms,
            secret_placeholders=scope.secret,
            pii_placeholders=scope.pii,
            term_placeholders=scope.term,
            unknown_pseudonyms=scope.unknown,
            unmappable_lines=scope.unmappable,
        )
        claims = tuple(scope.claims)
        if primary_dropped or (verdict.is_vulnerable is None and not needs):
            return RestoredVerdict(
                candidate_id=payload.candidate_id,
                verdict_dropped=True,
                is_vulnerable=None,
                confidence=Confidence.LOW,
                dropped_claims=claims,
                restore_stats=stats,
            )
        for text in (
            reasoning,
            impact,
            remediation,
            *(part for item in needs for part in (item.symbol, item.reason)),
        ):
            check_restored_text(text)
        return RestoredVerdict(
            candidate_id=payload.candidate_id,
            verdict_dropped=False,
            is_vulnerable=verdict.is_vulnerable,
            confidence=verdict.confidence,
            cwe=verdict.cwe,
            reasoning=reasoning,
            impact=impact,
            remediation=remediation,
            needs_context=tuple(needs),
            cited_locations=tuple(locations),
            dropped_claims=claims,
            restore_stats=stats,
        )

    def _lookup(self, keys: Iterable[str]) -> dict[str, str]:
        """One vault query for the distinct keys; no query at all when there are none."""
        distinct = list(dict.fromkeys(keys))
        if not distinct:
            return {}
        return self._vault.lookup_many(distinct, scan_id=self._scan_id)

    def _prose(self, section: DroppedSection, text: str, scope: _Scope) -> tuple[str, bool]:
        """Restore a free-text field sentence by sentence; report whether its first one dropped."""
        kept: list[str] = []
        primary_seen = False
        primary_dropped = False
        for sentence, separator in _sentences(text):
            if not sentence.strip():
                continue
            restored = self._unit(sentence, section, scope)
            if not primary_seen:
                primary_seen = True
                primary_dropped = restored is None
            if restored is not None:
                kept.append(restored + separator)
        return "".join(kept).strip(), primary_dropped

    def _needs(self, verdict: LLMVerdict, scope: _Scope) -> list[RestoredContext]:
        needs: list[RestoredContext] = []
        for item in verdict.needs_context:
            symbol = self._unit(item.symbol, "needs_context", scope)
            reason = self._unit(item.reason, "needs_context", scope)
            if symbol is None or reason is None:
                continue
            needs.append(RestoredContext(kind=item.kind, symbol=symbol, reason=reason))
        return needs

    def _unit(self, text: str, section: DroppedSection, scope: _Scope) -> str | None:
        """Restore one unit of text, or return None and record its claims when it is unanchored."""
        unknown = [
            match
            for match in _SCAN.finditer(text)
            if (key := _lookup_key(match)) is not None and key not in scope.found
        ]
        if unknown:
            scope.unknown += len(unknown)
            scope.claims.extend(
                DroppedClaim(section=section, reason="unknown_pseudonym") for _ in unknown
            )
            return None
        return _SCAN.sub(lambda match: self._replace(match, scope), text)

    @staticmethod
    def _replace(match: "re.Match[str]", scope: _Scope) -> str:
        placeholder = match.group("placeholder")
        if placeholder is not None:
            kind, subtype, _index = parse_placeholder(placeholder)
            if kind is PlaceholderKind.TERM:
                scope.term += 1
                return scope.found[placeholder]
            if kind is PlaceholderKind.SECRET:
                scope.secret += 1
                return _secret_phrase(subtype)
            scope.pii += 1
            return _personal_data_phrase(subtype)
        scope.pseudonyms += 1
        suffix = match.group("possessive") or ""
        return scope.found[_token_key(match)] + suffix

    def _locations(
        self,
        cited: tuple[int, ...],
        payload: SanitisedPayload,
        slice_: CodeSlice,
        scope: _Scope,
    ) -> list[Location]:
        """Map each cited payload line to a real file line; an unmappable one is dropped."""
        locations: list[Location] = []
        for line in cited:
            mapped = payload.map_line(line)
            segment = None
            if mapped is not None and 0 <= mapped[0] < len(slice_.segments):
                segment = slice_.segments[mapped[0]]
            if mapped is None or segment is None or not segment.region.contains_line(mapped[1]):
                scope.unmappable += 1
                scope.claims.append(DroppedClaim(section="cited_lines", reason="unmappable_line"))
                continue
            file_line = mapped[1]
            locations.append(Location(path=segment.path, start_line=file_line, end_line=file_line))
        return locations


def _keys_of(verdict: LLMVerdict) -> list[str]:
    """Every distinct lookup key of the verdict's free text, in first-seen order."""
    texts = [
        verdict.reasoning,
        verdict.impact,
        verdict.remediation,
        *(part for item in verdict.needs_context for part in (item.symbol, item.reason)),
    ]
    keys: list[str] = []
    for text in texts:
        for match in _SCAN.finditer(text):
            key = _lookup_key(match)
            if key is not None:
                keys.append(key)
    return list(dict.fromkeys(keys))
