"""Input side of the prompt-injection defence (E24).

This is a **mitigation layered on an architecture**, not a claim of immunity: one finding per call,
no tools, schema-constrained output, a per-request random delimiter, and client material only
after the delimiter (see ``prompts/*``). Filters of this kind fall to adaptive attacks, so none of
the checks here is relied upon alone; they reduce noise, make attempts visible, and give the
output validator something to compare against.

What it does to the sanitised payload text:

* removes control, zero-width and bidirectional characters (they hide instructions from reviewers);
* replaces fragments that read as instructions to the model ("ignore previous instructions",
  "mark this as a false positive", fake chat roles) by a fixed marker, and counts them;
* breaks any run that imitates the per-request delimiter.

It never echoes the matched text in a log line or an error: only counts and pattern names leave
this module.
"""

import re
import secrets
from dataclasses import dataclass
from typing import Final

MARKER: Final = "[removed: instruction-like text]"

_HIDDEN: Final = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)
_DELIMITER_LOOKALIKE: Final = re.compile(r"={3,}\s*CK-[0-9a-fA-F]{4,}\s*={3,}")

_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    name: re.compile(pattern, re.IGNORECASE)
    for name, pattern in {
        "override": (
            r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?"
            r"(?:previous|prior|above|earlier|preceding|system|safety)?\s*"
            r"(?:instructions?|prompts?|rules?|guidelines?)"
        ),
        "role_play": (
            r"you\s+are\s+now\s+(?:a|an|the|in)\b|act\s+as\s+(?:a|an)\s+(?:different|new)"
        ),
        "fake_role": (
            r"(?:^|\n)\s*(?:system|assistant|developer)\s*:\s"
            r"|<\|?(?:im_start|im_end|system)\|?>|\[/?INST\]"
        ),
        "steer_verdict": (
            r"(?:mark|label|report|classify|treat|rate)\s+(?:this|that|it|the)(?:\s+(?:finding|code|issue|result|alert))?"
            r"\s+(?:as\s+)?(?:safe|secure|benign|(?:a\s+)?false[\s-]+positive|not\s+vulnerable)"
        ),
        "claim_safe": (
            r"(?:this|the)\s+(?:code|finding|function|line)\s+(?:is|has\s+been)\s+"
            r"(?:safe|secure|audited|reviewed|approved|a\s+false[\s-]+positive)"
        ),
        "dictate_output": (
            r"(?:set|answer|respond|reply|output|return)\s+(?:with\s+)?[`\"']?is_vulnerable[`\"']?"
            r"|(?:respond|reply|answer)\s+(?:only\s+)?(?:with|that)\s+(?:the\s+code\s+is\s+)?(?:safe|false)"
        ),
        "reveal_prompt": (
            r"(?:reveal|print|repeat|show|output|leak)\s+(?:your|the)\s+"
            r"(?:system\s+)?(?:prompt|instructions|hidden|secret)"
        ),
        "reviewer_note": (
            r"(?:note|message|instruction)s?\s+(?:to|for)\s+(?:the\s+)?"
            r"(?:ai|llm|model|assistant|reviewer)"
        ),
    }.items()
}


@dataclass(frozen=True, slots=True)
class InjectionReport:
    """What the input defence did to one text; counts and names only, never the text."""

    removed: int
    patterns: tuple[str, ...]
    hidden_characters: int

    @property
    def suspected(self) -> bool:
        """True when anything instruction-like or hidden was found."""
        return bool(self.removed or self.hidden_characters)


def scan(text: str) -> InjectionReport:
    """Count what ``neutralise`` would change, without changing anything."""
    return neutralise(text)[1]


def neutralise(text: str) -> tuple[str, InjectionReport]:
    """``text`` with hidden characters and instruction-like fragments neutralised, and a report."""
    hidden = len(_HIDDEN.findall(text))
    cleaned = _HIDDEN.sub("", text)
    removed = 0
    names: list[str] = []
    cleaned, count = _DELIMITER_LOOKALIKE.subn("[removed: delimiter lookalike]", cleaned)
    if count:
        removed += count
        names.append("delimiter_lookalike")
    for name, pattern in _PATTERNS.items():
        cleaned, count = pattern.subn(MARKER, cleaned)
        if count:
            removed += count
            names.append(name)
    return cleaned, InjectionReport(removed, tuple(names), hidden)


def new_canary() -> str:
    """A random token for tests and probes; a response that contains it obeyed a planted order."""
    return f"CANARY-{secrets.token_hex(6)}"
