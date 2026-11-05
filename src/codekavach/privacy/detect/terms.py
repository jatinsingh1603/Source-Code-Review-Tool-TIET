"""The domain-term detector and the Aho-Corasick automaton behind it.

Owning epic: E08.

``DomainTermDetector`` finds the business vocabulary in ``settings.privacy.domain_terms`` (the
effective list: E03-21 has already merged ``domain_terms_file`` into it, so this module never
opens a file) and emits every hit as ``TypedSpan(kind=TERM, subtype="domain")``. The subtype is
the constant ``domain``, never the term: the subtype is part of the payload and the term is the
thing being hidden.

**What it does, and what it does not.** It removes the listed vocabulary *verbatim*. It does not
stop a reader inferring the domain from structure (call graphs, data shapes, the shape of the
remaining names); the leakage harness measures that (metric M4), and anything the policy engine
was never told is sensitive cannot be protected by a dictionary
(``docs/research/INSIGHTS.md`` section 4.4).

**Matching.** Terms and text are normalised the same way: case-folded, with ``-``, ``_``, ``.``
and whitespace removed, so ``festival-bonus``, ``festival bonus``, ``festival_bonus`` and the
camel-case ``festivalBonus`` are one string, ``festivalbonus``. Removing the separators is what
lets one automaton match the term in ``festivalBonusRate``, in ``calculate_festival_bonus`` and
in the string ``"festival bonus"`` without knowing which of the three it is looking at; a hit is
a plain substring of the normalised text. The span covers the matched run in the original text,
from its first to its last matched character, and not the whole identifier, so the pseudonymiser
(E09) renames what is left. A term shorter than four characters after normalisation is ignored
(invariant I6: no value under four characters is treated as hideable text).

**Automaton.** ``AhoCorasick`` is built once per scan from the normalised terms, and matches in
time linear in the text whatever the size of the dictionary. A parallel array maps each
automaton state to the indices of the terms that end there, so :meth:`DomainTermDetector.stats`
can count distinct terms without a span holding any text. The class is public so that the egress
guard (E12-02) reuses it rather than building a second one.

A term inside an identifier is redacted here and the identifier is renamed by E09 afterwards.
The order is fixed by ``docs/ARCHITECTURE.md`` section 6.2 (redact at step 3, pseudonymise at
step 4), so E09 treats an already-substituted placeholder as an opaque token; see
``privacy.detect.mask.mask_placeholders``.

This module performs no network operation and logs no term.
"""

import re
from bisect import bisect_right
from collections import deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Final, Self

from codekavach.config.models.root import Settings
from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode, RepoPath
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.offsets import ByteOffsets
from codekavach.privacy.detect.registry import DetectorRegistry

DETECTOR_ID: Final = "term.domain"
SUBTYPE: Final = "domain"
MIN_TERM_LENGTH: Final = 4
_SEPARATORS: Final = " \t\n\r\f\v-_."
_DELETE: Final = {ord(char): None for char in _SEPARATORS}
_RUN: Final = re.compile(r"[^ \t\n\r\f\v\-_.]+")


def fold(text: str) -> str:
    """``text`` case-folded with the separator characters removed (the matching form)."""
    return _lower(text).translate(_DELETE)


def _lower(text: str) -> str:
    """Lower-case ``text`` without changing its length, so indices keep their meaning."""
    lowered = text.lower()
    if len(lowered) == len(text):
        return lowered
    return "".join(char.lower() if len(char.lower()) == 1 else char for char in text)


class AhoCorasick:
    """A multi-pattern string matcher: linear in the text, whatever the number of patterns."""

    __slots__ = ("_fail", "_goto", "_lengths", "_out")
    __ck_never_persist__ = True

    def __init__(self, patterns: Sequence[str]) -> None:
        goto: list[dict[str, int]] = [{}]
        own: list[list[int]] = [[]]
        for index, pattern in enumerate(patterns):
            if not pattern:
                raise ValueError("an empty pattern would match everywhere")
            node = 0
            for char in pattern:
                following = goto[node].get(char)
                if following is None:
                    goto.append({})
                    own.append([])
                    following = len(goto) - 1
                    goto[node][char] = following
                node = following
            own[node].append(index)
        fail = [0] * len(goto)
        out: list[tuple[int, ...]] = [() for _ in goto]
        queue: deque[int] = deque()
        for child in goto[0].values():
            out[child] = tuple(own[child])
            queue.append(child)
        while queue:
            node = queue.popleft()
            for char, child in goto[node].items():
                queue.append(child)
                state = fail[node]
                while state and char not in goto[state]:
                    state = fail[state]
                target = goto[state].get(char, 0)
                fail[child] = target
                out[child] = (*own[child], *out[target])
        self._goto = goto
        self._fail = fail
        self._out = out
        self._lengths = tuple(len(pattern) for pattern in patterns)

    def __repr__(self) -> str:
        return f"AhoCorasick(patterns={len(self._lengths)}, states={len(self._goto)})"

    def __len__(self) -> int:
        return len(self._lengths)

    def finditer(self, text: str) -> Iterator[tuple[int, int, int]]:
        """Every occurrence as ``(start, end, pattern_index)``, ``end`` exclusive.

        Overlapping and nested occurrences are all reported, in order of ``end``.
        """
        goto, fail, out, lengths = self._goto, self._fail, self._out, self._lengths
        state = 0
        for position, char in enumerate(text, 1):
            while state and char not in goto[state]:
                state = fail[state]
            state = goto[state].get(char, 0)
            found = out[state]
            if found:
                for index in found:
                    yield position - lengths[index], position, index


@dataclass(frozen=True)
class TermStats:
    """How many distinct terms matched and how many hits there were: numbers, never a term."""

    distinct_terms: int
    hits: int


class DomainTermDetector:
    """The ``term.domain`` detector: the effective term list, matched verbatim.

    ``terms`` is ``settings.privacy.domain_terms`` (see :meth:`from_settings`). The detector
    keeps running counts across the texts it has seen, for the privacy attestation.
    """

    id = DETECTOR_ID
    kinds = frozenset({PlaceholderKind.TERM})
    __ck_never_persist__ = True

    def __init__(self, terms: Iterable[str]) -> None:
        folded = dict.fromkeys(fold(term) for term in terms)
        self._automaton = AhoCorasick([form for form in folded if len(form) >= MIN_TERM_LENGTH])
        self._matched: set[int] = set()
        self._hits = 0

    @classmethod
    def from_settings(cls, settings: Settings) -> Self:
        """The detector for ``settings.privacy.domain_terms``."""
        return cls(settings.privacy.domain_terms)

    def __repr__(self) -> str:
        return f"DomainTermDetector(terms={len(self._automaton)})"

    def stats(self) -> TermStats:
        """The number of distinct terms matched so far and the total number of hits."""
        return TermStats(distinct_terms=len(self._matched), hits=self._hits)

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> list[TypedSpan]:
        """A ``TERM`` span for every occurrence of a listed term in ``text``."""
        if not len(self._automaton):
            return []
        raw = text.expose()
        lowered = _lower(raw)
        hits = list(self._automaton.finditer(lowered.translate(_DELETE)))
        if not hits:
            return []
        runs = [(match.start(), match.end()) for match in _RUN.finditer(lowered)]
        compact_starts: list[int] = []
        total = 0
        for start, end in runs:
            compact_starts.append(total)
            total += end - start
        offsets = ByteOffsets(raw)
        found: dict[tuple[int, int], None] = {}
        for first, last, index in hits:
            self._matched.add(index)
            begin = _original(first, runs, compact_starts)
            finish = _original(last - 1, runs, compact_starts) + 1
            found[(begin, finish)] = None
        self._hits += len(found)
        return [
            TypedSpan(
                kind=PlaceholderKind.TERM,
                subtype=SUBTYPE,
                start_byte=offsets.at(begin),
                end_byte=offsets.at(finish),
                confidence=Confidence.HIGH,
                detector=self.id,
            )
            for begin, finish in found
        ]


def _original(compact_index: int, runs: list[tuple[int, int]], starts: list[int]) -> int:
    """The index in the original text of the character at ``compact_index`` of the folded text."""
    run = bisect_right(starts, compact_index) - 1
    return runs[run][0] + compact_index - starts[run]


def register_term_detector(registry: DetectorRegistry, settings: Settings) -> DetectorRegistry:
    """Add the domain-term detector for ``settings`` to ``registry`` and return it."""
    registry.register(DomainTermDetector.from_settings(settings))
    return registry
