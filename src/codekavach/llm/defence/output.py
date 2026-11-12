"""Output side of the prompt-injection defence: treat every model answer as untrusted (E24).

``LLMVerdict`` already bounds lengths, removes control characters and rejects unknown keys. This
module adds what a type cannot say:

* **Rejection** (``OutputRejected``) when the answer shows that it obeyed or leaked something: it
  contains a planted canary, the per-request delimiter, or a long run of the prompt's own wording.
  The candidate then keeps its deterministic evidence and gets no model text (fail closed, I4).
* **Sanitising** of what is kept: CWE numbers outside the allow-list are dropped, markdown images,
  active HTML and ``javascript:`` links are removed (they are an exfiltration channel when a
  report is rendered), and context requests whose symbol is not a plain identifier are dropped.
* **No power over findings.** Nothing here, and nothing downstream of a verdict, removes a
  deterministic finding because a model said it is not vulnerable (ARCHITECTURE section 7): a
  ``False`` verdict can only lower the confidence that ranks a finding.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from codekavach.core.models.verdict import ContextRequest, LLMVerdict
from codekavach.llm.defence.cwe import filter_cwes

_IMAGE: Final = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_ACTIVE_HTML: Final = re.compile(
    r"</?(?:script|iframe|img|object|embed|style|link|meta|form|svg|a)\b[^>]*>", re.IGNORECASE
)
_JS_URI: Final = re.compile(r"(?:javascript|data|vbscript):[^\s)\"']*", re.IGNORECASE)
_SYMBOL: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")
_SHINGLE_WORDS: Final = 9


class OutputRejected(ValueError):  # noqa: N818 - a verdict is rejected, not an error in itself
    """The answer must not be used; ``reason`` names the check, never the text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class OutputReport:
    """What the validator changed; counts and names only."""

    cwes_dropped: int = 0
    markup_removed: int = 0
    contexts_dropped: int = 0

    @property
    def clean(self) -> bool:
        """True when the answer needed no change."""
        return not (self.cwes_dropped or self.markup_removed or self.contexts_dropped)


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_`<>:]+", text.lower())


def prompt_shingles(prompt_text: str) -> frozenset[tuple[str, ...]]:
    """The nine-word windows of the prompt's own wording, for the echo check."""
    words = _words(prompt_text)
    return frozenset(
        tuple(words[i : i + _SHINGLE_WORDS]) for i in range(max(len(words) - _SHINGLE_WORDS, 0))
    )


def echoes_prompt(text: str, shingles: frozenset[tuple[str, ...]]) -> bool:
    """True when ``text`` repeats nine consecutive words of the prompt."""
    words = _words(text)
    return any(
        tuple(words[i : i + _SHINGLE_WORDS]) in shingles
        for i in range(max(len(words) - _SHINGLE_WORDS, 0))
    )


def _scrub(text: str) -> tuple[str, int]:
    count = 0
    for pattern in (_IMAGE, _ACTIVE_HTML, _JS_URI):
        text, n = pattern.subn("", text)
        count += n
    return text, count


def _texts(verdict: LLMVerdict) -> Iterable[str]:
    yield verdict.reasoning
    yield verdict.impact
    yield verdict.remediation
    for item in verdict.needs_context:
        yield item.symbol
        yield item.reason


def check_text(
    text: str,
    *,
    canaries: Iterable[str] = (),
    shingles: frozenset[tuple[str, ...]] = frozenset(),
) -> None:
    """Reject ``text`` that leaks a canary, the delimiter or the prompt's wording.

    Raises:
        OutputRejected: one of the checks fired.
    """
    if any(canary and canary in text for canary in canaries):
        raise OutputRejected("canary_in_output")
    if "=====CK-" in text:
        raise OutputRejected("delimiter_in_output")
    if shingles and echoes_prompt(text, shingles):
        raise OutputRejected("prompt_echoed")


def validate_verdict(
    verdict: LLMVerdict,
    *,
    trusted_cwes: tuple[int, ...] = (),
    canaries: Iterable[str] = (),
    shingles: frozenset[tuple[str, ...]] = frozenset(),
) -> tuple[LLMVerdict, OutputReport]:
    """The verdict with unsafe parts removed, and a report; or ``OutputRejected``.

    Raises:
        OutputRejected: the answer leaked a canary, the delimiter or the prompt's wording.
    """
    canary_list = tuple(canaries)
    for text in _texts(verdict):
        check_text(text, canaries=canary_list, shingles=shingles)
    removed = 0
    fields: dict[str, str] = {}
    for name in ("reasoning", "impact", "remediation"):
        fields[name], count = _scrub(getattr(verdict, name))
        removed += count
    contexts = tuple(item for item in verdict.needs_context if _SYMBOL.fullmatch(item.symbol))
    kept: tuple[ContextRequest, ...] = tuple(
        item.model_copy(update={"reason": _scrub(item.reason)[0]}) for item in contexts
    )
    cwe = filter_cwes(verdict.cwe, trusted=trusted_cwes)
    update: dict[str, object] = {**fields, "cwe": cwe, "needs_context": kept}
    if verdict.is_vulnerable is None and not kept:
        raise OutputRejected("context_request_invalid")
    cleaned = verdict.model_copy(update=update)
    report = OutputReport(
        cwes_dropped=len(verdict.cwe) - len(cwe),
        markup_removed=removed,
        contexts_dropped=len(verdict.needs_context) - len(kept),
    )
    return cleaned, report
