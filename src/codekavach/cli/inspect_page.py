"""The ``privacy inspect --html`` page: original and payload side by side, written locally.

Owning epic: E13. MVP; extended by E11.

The page shows, per candidate, the original slice with its file line numbers on the left and the
exact payload with its payload line numbers on the right; redactions and renames are marked by
class so a reader can see what changed. It contains client code, so it is written only to the path
the user names, with the permissions of a report file, and no report ever includes or links it.
Like the report it loads nothing remote and escapes every value.
"""

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from markupsafe import Markup, escape

from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.slice import CodeSlice
from codekavach.report.render.html import CSP, environment

if TYPE_CHECKING:
    from codekavach.cli.privacy import Entry

TEMPLATE: Final = "inspect.html.j2"
FILE_MODE: Final = 0o640
_RENAME: Final = re.compile(r"\b(fn|cls|var|param|field|mod|const|file)_[0-9]+\b")
_REDACTION: Final = re.compile(r"<(SECRET|PII|TERM):[a-z][a-z0-9_]{0,47}:[1-9][0-9]{0,5}>")


@dataclass(frozen=True)
class Row:
    """One numbered line; ``html`` is escaped text with marked spans."""

    number: int
    html: Markup


@dataclass(frozen=True)
class Pair:
    """One candidate: where it is, how it was ledgered, and the two columns."""

    candidate_id: str
    location: str
    rule: str
    level: str
    outcome: str
    payload_hash: str
    original: list[Row]
    payload: list[Row]
    redactions: int
    renames: int


def _mark(text: str) -> Markup:
    """``text`` escaped, with redaction tokens and renamed identifiers in marked spans."""
    spans: list[tuple[int, int, str]] = []
    spans += [(m.start(), m.end(), "redacted") for m in _REDACTION.finditer(text)]
    spans += [(m.start(), m.end(), "renamed") for m in _RENAME.finditer(text)]
    pieces: list[Markup | str] = []
    cursor = 0
    for start, end, kind in sorted(spans):
        if start < cursor:
            continue
        pieces.append(escape(text[cursor:start]))
        pieces.append(Markup('<span class="{}">{}</span>').format(kind, text[start:end]))
        cursor = end
    pieces.append(escape(text[cursor:]))
    return Markup("").join(pieces)


def original_rows(slice_: CodeSlice | None) -> list[Row]:
    """The slice's lines with their file line numbers, segments in order."""
    if slice_ is None:
        return []
    rows: list[Row] = []
    for segment in slice_.segments:
        lines = segment.text.expose().split("\n")
        rows += [
            Row(segment.region.start_line + offset, escape(line))
            for offset, line in enumerate(lines)
        ]
    return rows


def payload_rows(payload: SanitisedPayload) -> list[Row]:
    """The payload's lines with their payload line numbers (from 1)."""
    lines = payload.text.expose().split("\n")
    return [Row(number, _mark(line)) for number, line in enumerate(lines, start=1)]


def pair_of(entry: "Entry") -> Pair:
    """The page's view of one entry."""
    candidate = entry.candidate
    location = candidate.locations[0] if candidate else None
    text = entry.payload.text.expose()
    return Pair(
        candidate_id=str(entry.payload.candidate_id),
        location=f"{location.path}:{location.start_line}" if location else "unknown",
        rule=candidate.rule_id if candidate else "unknown",
        level=entry.payload.level.value,
        outcome=entry.outcome or "not recorded",
        payload_hash=entry.payload.payload_hash,
        original=original_rows(entry.slice),
        payload=payload_rows(entry.payload),
        redactions=len(_REDACTION.findall(text)),
        renames=len(_RENAME.findall(text)),
    )


def render_page(entries: Sequence["Entry"], *, scan_id: str, provider_kind: str | None) -> str:
    """The page for ``entries`` as one string."""
    context = {
        "csp": CSP,
        "scan_id": scan_id,
        "pairs": [pair_of(entry) for entry in entries],
        "offline": provider_kind in {"mock", "replay"},
        "provider_kind": provider_kind or "none",
    }
    return environment().get_template(TEMPLATE).render(**context)


def write_page(path: Path, html: str) -> Path:
    """Write ``html`` to ``path`` (parents created), readable by the owner and the group only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8", newline="\n")
    if os.name != "nt":
        path.chmod(FILE_MODE)
    return path
