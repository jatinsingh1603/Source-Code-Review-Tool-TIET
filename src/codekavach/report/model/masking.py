"""Secret masking for report evidence: no report format ever prints a live secret.

Owning epic: E30 (E30-02). Privacy-critical.

A report is for the client and holds real code, but a credential copied into a PDF that is then
emailed, printed and archived has left every control that protected it. Every evidence line is
therefore passed through two layers before any renderer sees it:

1. the product's own secret detectors (``codekavach.privacy.detect``: pattern, assignment and
   entropy), the same ones that redact payloads before egress; and
2. a local set of conservative patterns (cloud keys, tokens, private keys, credentials in URLs and
   secret-named assignments), which also runs when the detectors cannot be loaded.

A masked value keeps its first two characters, so an auditor can tell which key it was, and the
rest is replaced by ``*`` characters, capped at a fixed width so the length is not disclosed.
Masking fails closed: if the detectors raise, the local patterns still run, and a line the
patterns cannot parse is returned with every quoted string masked.
"""

import re
from collections.abc import Iterable, Sequence
from functools import lru_cache
from typing import Any, Final

from codekavach.core.log import get_logger

_log = get_logger(__name__)

KEEP: Final = 2
MASK_WIDTH: Final = 8
MASK_CHAR: Final = "*"

_NAME_HINTS = (
    r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?key|credential|signing[_-]?key|session[_-]?key|"
    r"encryption[_-]?key|enc[_-]?key|aes[_-]?key|hmac[_-]?key|jwt[_-]?secret|db[_-]?pass)"
)
# A value the pipeline already replaced by a typed placeholder is shown as the placeholder.
_PLACEHOLDER = re.compile(r"<(?:SECRET|PII|TERM)(?::[^<>\s]{1,64})+>|<MASKED>")
# Each pattern captures the secret value in the group named ``v``.
_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?P<v>\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b)"),
    re.compile(r"(?P<v>\bgh[pousr]_[A-Za-z0-9]{30,}\b)"),
    re.compile(r"(?P<v>\bgithub_pat_[A-Za-z0-9_]{40,}\b)"),
    re.compile(r"(?P<v>\bxox[abposr]-[A-Za-z0-9-]{10,}\b)"),
    re.compile(r"(?P<v>\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b)"),
    re.compile(r"(?P<v>\bsk-[A-Za-z0-9_-]{20,}\b)"),
    re.compile(r"(?P<v>\bAIza[0-9A-Za-z_-]{35}\b)"),
    re.compile(r"(?P<v>\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"),
    re.compile(r"(?P<v>-----BEGIN [A-Z ]*PRIVATE KEY-----.*)"),
    re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@'\"]+:(?P<v>[^\s@/'\"]{3,})@"),
    re.compile(
        r"(?i)\b[\w.-]*" + _NAME_HINTS + r"[\w.-]*\s*[\"']?\s*(?::|=|:=|=>)\s*"
        r"(?P<q>[\"'`])(?P<v>[^\"'`\s]{4,})(?P=q)"
    ),
    re.compile(
        r"(?i)\b[\w.-]*" + _NAME_HINTS + r"[\w.-]*\s*(?:=|:)\s*(?P<v>[A-Za-z0-9+/_\-.]{8,})\s*$"
    ),
)


def mask_value(value: str) -> str:
    """``value`` with all but its first two characters replaced by a fixed-width mask."""
    if len(value) <= KEEP:
        return MASK_CHAR * MASK_WIDTH
    return value[:KEEP] + MASK_CHAR * MASK_WIDTH


def _merge(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _pattern_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span("v")
            if end > start:
                spans.append((start, end))
    return spans


@lru_cache(maxsize=1)
def _detectors() -> tuple[Any, Any, Any] | None:
    """The product's secret detectors, the settings and the runner, or None when unavailable."""
    try:
        from codekavach.config import Settings  # noqa: PLC0415 - optional at import time
        from codekavach.privacy.detect.registry import DetectorRegistry  # noqa: PLC0415
        from codekavach.privacy.detect.runner import detect_all  # noqa: PLC0415
        from codekavach.privacy.detect.secrets.builtin import (  # noqa: PLC0415
            register_secret_detectors,
        )

        return register_secret_detectors(DetectorRegistry()), Settings(), detect_all
    except Exception:  # noqa: BLE001 - the local patterns still run
        _log.info("report_masking_detectors_unavailable")
        return None


def _detector_spans(text: str, path: str, language: str) -> list[tuple[int, int]]:
    loaded = _detectors()
    if loaded is None or not text.strip():
        return []
    registry, settings, detect_all = loaded
    try:
        from codekavach.core.models.enums import Language  # noqa: PLC0415
        from codekavach.core.models.text import RawCode  # noqa: PLC0415

        try:
            lang = Language(language)
        except ValueError:
            lang = Language.UNKNOWN
        spans = detect_all(
            RawCode(text),
            path=path or "evidence.txt",
            language=lang,
            settings=settings,
            registry=registry,
        )
    except Exception:  # noqa: BLE001 - fall back to the local patterns
        _log.info("report_masking_detector_failed")
        return []
    data = text.encode("utf-8", errors="surrogatepass")
    result: list[tuple[int, int]] = []
    for span in spans:
        if str(getattr(span.kind, "value", span.kind)).upper() != "SECRET":
            continue
        start = len(data[: span.start_byte].decode("utf-8", errors="ignore"))
        end = len(data[: span.end_byte].decode("utf-8", errors="ignore"))
        if end > start:
            result.append((start, end))
    return result


def mask_lines(
    lines: Sequence[str], *, path: str = "", language: str = "unknown", detectors: bool = True
) -> tuple[tuple[str, ...], int]:
    """``lines`` with every detected secret masked, and the number of values masked.

    Placeholder tokens such as ``<SECRET:aws_access_key>`` that an earlier stage put in place of a
    secret are kept as they are and counted as masked values.

    The detectors run on the joined snippet, so an assignment that spans lines is still seen;
    the local patterns run line by line.
    """
    joined = "\n".join(lines)
    starts: list[int] = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1
    per_line: list[list[tuple[int, int]]] = [[] for _ in lines]
    found = _detector_spans(joined, path, language) if detectors else []
    for start, end in found:
        for index, line_start in enumerate(starts):
            line_end = line_start + len(lines[index])
            lo, hi = max(start, line_start), min(end, line_end)
            if hi > lo:
                per_line[index].append((lo - line_start, hi - line_start))
    masked_total = 0
    out: list[str] = []
    for index, line in enumerate(lines):
        tokens = [m.span() for m in _PLACEHOLDER.finditer(line)]
        masked_total += len(tokens)
        spans = [
            (start, end)
            for start, end in _merge([*per_line[index], *_pattern_spans(line)])
            if not any(start < t_end and t_start < end for t_start, t_end in tokens)
        ]
        if not spans:
            out.append(line)
            continue
        pieces: list[str] = []
        cursor = 0
        for start, end in spans:
            pieces.append(line[cursor:start])
            pieces.append(mask_value(line[start:end]))
            cursor = end
        pieces.append(line[cursor:])
        masked_total += len(spans)
        out.append("".join(pieces))
    return tuple(out), masked_total


def mask_text(text: str) -> str:
    """Free text (a title, a reasoning, a note) with pattern-detected secrets masked."""
    lines, _ = mask_lines(text.split("\n"), detectors=False)
    return "\n".join(lines)
