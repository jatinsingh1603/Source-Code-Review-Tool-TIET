"""Cheap facts about a text, and the conditions under which a detector cannot match (E12-02b).

Owning epic: E08. MVP; extended by E12 (the egress scanners run the detectors again).

A detector is a regular-expression pass over the whole text. Most texts hold no email address, no
credential-looking name and no card number, and the pass then costs time and finds nothing. A
detector may therefore offer ``may_match(facts)``: ``False`` means *its patterns cannot match this
text*, so the pass is skipped; ``True`` means nothing, and the pass runs. The runner builds the
facts once per text, and only a detector that asks reads them.

**A prefilter must never hide a value.** Skipping a pass that would have matched is a leaked
secret, so a condition here is a *necessary* condition read off the detector's own pattern: a
literal the pattern cannot match without, or the pattern itself with its look-around assertions
removed (an assertion only restricts a match, so the rest still occurs wherever the whole does).
The cost of the real pattern is mostly its look-behind, which is tried at every position, while
the core starts at a literal or a digit and fails fast. ``tests/unit/privacy/test_prefilter.py``
compares the spans with and without prefiltering on the detector corpus and on generated texts. A
condition that is not obvious from the pattern does not belong here: leave the detector without a
prefilter. The facts never leave the process and hold the text only for one detection.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from typing import Final

from codekavach.privacy.detect.safe_regex import safe_compile

_NO_FLAGS: Final = 0


class TextFacts:
    """The text of one detection and its lower-cased copy, made when first asked for."""

    __slots__ = ("_lowered", "text")

    def __init__(self, text: str) -> None:
        self.text = text
        self._lowered: str | None = None

    @property
    def lowered(self) -> str:
        """``text.lower()``: the lower case of a sub-word of a name is a substring of it."""
        if self._lowered is None:
            self._lowered = self.text.lower()
        return self._lowered

    def has_any_word(self, words: Iterable[str]) -> bool:
        """True when the lower-cased text contains any of the lower-case ``words``."""
        lowered = self.lowered
        return any(word in lowered for word in words)


@cache
def _compiled(core: str) -> re.Pattern[str]:
    return safe_compile(core, _NO_FLAGS)


@dataclass(frozen=True, slots=True)
class Needs:
    """What a text must contain for a pattern to be able to match; the empty value needs nothing.

    ``chars`` must all occur; ``words`` (lower case) needs one of them in the lower-cased text;
    ``core`` is a regular expression that must match somewhere (the pattern with its look-around
    assertions removed, or a necessary part of it).
    """

    chars: tuple[str, ...] = ()
    words: tuple[str, ...] = ()
    core: str = ""

    def met(self, facts: TextFacts) -> bool:
        """False only when the pattern cannot match ``facts``' text."""
        text = facts.text
        return (
            all(char in text for char in self.chars)
            and (not self.words or facts.has_any_word(self.words))
            and (not self.core or _compiled(self.core).search(text) is not None)
        )


__all__ = ["Needs", "TextFacts"]
