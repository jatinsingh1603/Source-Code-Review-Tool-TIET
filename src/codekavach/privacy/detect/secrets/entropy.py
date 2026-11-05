"""The ``secret.entropy`` detector: charset-aware Shannon entropy for the long tail.

Owning epic: E08.

Provider prefixes (``patterns.py``) find credentials with a documented shape. This detector is
the fallback for the rest, and it is the one that produces false positives, so every hit is
``LOW`` confidence and passes the filter list (``filters.py``).

**Charset-aware.** Shannon entropy in bits per character means something different per alphabet:
random hexadecimal tops out near 4.0 bits, base64 near 6.0, base58 near 5.86. One threshold would
either miss hex secrets or flood on base64 prose. The literal's alphabet is found first, over the
whole literal, narrowest first, and the first alphabet whose minimum length the literal meets
decides:

=============  ==========  =========
alphabet       min length  threshold
=============  ==========  =========
hex            32          3.2
base58         25          4.2
alphanumeric   16          3.8
base64url      20          4.5
base64         20          4.5
=============  ==========  =========

Worked: ``deadbeef`` repeated to 32 characters has 5 distinct symbols and an entropy of about
2.16 bits, under 3.2, so it is not reported; a random 32-character hex string has about 3.7 and
is.

Candidates are quoted literals and the values of ``key = value`` / ``key: value`` lines (``.env``,
YAML, INI), one token with no spaces, 16 to 512 characters. The span covers the value, not the
quotes. This module performs no network operation.
"""

import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode, RepoPath
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.offsets import ByteOffsets
from codekavach.privacy.detect.safe_regex import safe_compile
from codekavach.privacy.detect.secrets.filters import (
    REPEAT_THRESHOLD,
    FilterContext,
    Verdict,
    first_match,
)
from codekavach.privacy.detect.secrets.stats import ScanSecretStats

DETECTOR_ID: Final = "secret.entropy"
SUBTYPE: Final = "high_entropy_string"
_MAX_LITERAL: Final = 512


@dataclass(frozen=True)
class Alphabet:
    """One alphabet with its minimum length and entropy threshold (bits per character)."""

    name: str
    charset: re.Pattern[str]
    min_length: int
    threshold: float


ALPHABETS: Final[tuple[Alphabet, ...]] = (
    Alphabet("hex", safe_compile(r"[0-9a-fA-F]+"), 32, 3.2),
    Alphabet("base58", safe_compile(r"[1-9A-HJ-NP-Za-km-z]+"), 25, 4.2),
    Alphabet("alphanumeric", safe_compile(r"[A-Za-z0-9]+"), 16, 3.8),
    Alphabet("base64url", safe_compile(r"[A-Za-z0-9_\-]+"), 20, 4.5),
    Alphabet("base64", safe_compile(r"[A-Za-z0-9+/]+={0,2}"), 20, 4.5),
)


def shannon_entropy(value: str) -> float:
    """Shannon entropy of ``value`` in bits per character (0.0 for an empty string)."""
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in Counter(value).values())


def classify(value: str) -> Alphabet | None:
    """The alphabet that decides ``value``: narrowest charset first, minimum length met."""
    for alphabet in ALPHABETS:
        if len(value) >= alphabet.min_length and alphabet.charset.fullmatch(value):
            return alphabet
    return None


def exceeds_threshold(alphabet: Alphabet, bits: float) -> bool:
    """The decision for a literal of ``alphabet`` with ``bits`` of entropy per character.

    A pure function of the alphabet and the entropy, monotone in ``bits``.
    """
    return bits >= alphabet.threshold


def is_high_entropy(value: str) -> bool:
    """True when ``value`` has the length and entropy of a secret for its alphabet."""
    alphabet = classify(value)
    return alphabet is not None and exceeds_threshold(alphabet, shannon_entropy(value))


_VALUE_CHARS = r"[A-Za-z0-9+/=_\-]"
_QUOTED: Final = safe_compile(rf"""(?P<q>["'`])(?P<v>{_VALUE_CHARS}{{16,{_MAX_LITERAL}}})(?P=q)""")
_LINE_VALUE: Final = safe_compile(
    rf"""(?m)^[ \t]*(?:export[ \t]+)?(?P<name>[\w.\-"']{{1,64}})[ \t]*[:=][ \t]*"""
    rf"""(?P<v>{_VALUE_CHARS}{{16,{_MAX_LITERAL}}})[ \t]*\r?$"""
)
_NAME_BEFORE: Final = safe_compile(r"""([A-Za-z_][\w.\-]{0,63})["']?\s*(?::=|=>|[:=])\s*["'`]?$""")


def _line_of(raw: str, start: int, end: int) -> str:
    line_start = raw.rfind("\n", 0, start) + 1
    line_end = raw.find("\n", end)
    return raw[line_start : len(raw) if line_end == -1 else line_end]


def _field_before(raw: str, start: int) -> str | None:
    line_start = raw.rfind("\n", 0, start) + 1
    found = _NAME_BEFORE.search(raw[max(line_start, start - 96) : start])
    return found.group(1) if found else None


class EntropyDetector:
    """The ``secret.entropy`` detector.

    ``stats`` (optional) counts values across the scan for the repetition filter; without it the
    count is within the one text. ``disabled_filters`` names filters to switch off.
    """

    id = DETECTOR_ID
    kinds = frozenset({PlaceholderKind.SECRET})

    def __init__(
        self,
        stats: ScanSecretStats | None = None,
        *,
        disabled_filters: Iterable[str] = (),
    ) -> None:
        self._stats = stats
        self._disabled = frozenset(disabled_filters)
        first_match("", FilterContext(path=""), self._disabled)  # rejects unknown names early

    def _candidates(self, raw: str) -> list[tuple[int, int]]:
        found = [match.span("v") for match in _QUOTED.finditer(raw)]
        found.extend(match.span("v") for match in _LINE_VALUE.finditer(raw))
        return found

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> list[TypedSpan]:
        """Spans of high-entropy literals that no filter drops."""
        raw = text.expose()
        entropic = [
            (start, end) for start, end in self._candidates(raw) if is_high_entropy(raw[start:end])
        ]
        if not entropic:
            return []
        totals: dict[str, int] = dict(Counter(raw[start:end] for start, end in entropic))
        if self._stats is not None:
            # Every occurrence is observed before any is judged, so the first of 25 copies is
            # downgraded too, not only the 21st.
            for value, occurrences in list(totals.items()):
                for _ in range(occurrences):
                    totals[value] = self._stats.observe(value)
        offsets = ByteOffsets(raw)
        spans: list[TypedSpan] = []
        for start, end in entropic:
            value = raw[start:end]
            context = FilterContext(
                path=path,
                line=_line_of(raw, start, end),
                field=_field_before(raw, start),
                occurrences=totals[value],
            )
            rule = first_match(value, context, self._disabled)
            if rule is not None and rule.verdict is Verdict.DROP:
                continue
            spans.append(
                TypedSpan(
                    kind=PlaceholderKind.SECRET,
                    subtype=SUBTYPE,
                    start_byte=offsets.at(start),
                    end_byte=offsets.at(end),
                    confidence=Confidence.LOW,
                    detector=self.id,
                    downgraded=rule is not None,
                )
            )
        return spans


__all__ = ["ALPHABETS", "REPEAT_THRESHOLD", "EntropyDetector", "classify", "is_high_entropy"]
