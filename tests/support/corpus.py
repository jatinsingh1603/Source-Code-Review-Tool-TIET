"""The labelled detector corpus (E08-01): templates, labels and a loader.

A case is two files in ``tests/fixtures/detect/corpus/``:

- ``<name>.txt``, a **template**: ordinary text with markers ``{{secret:aws_access_key}}``,
  ``{{pii:email}}`` or ``{{term:domain:1}}`` (the optional last number picks the n-th synthetic
  value of that subtype). Markers are expanded from ``tests/support/synthetic.py`` when the case
  is loaded, so no secret-shaped string is ever committed as a literal (AGENTS.md section 3).
- ``<name>.labels.json``, the expected spans of the **expanded** text, by UTF-8 byte range:
  ``detected`` is everything the detectors report, overlaps included, and ``expected`` is what
  ``resolve_overlaps`` must leave.

Labels are written by ``expand_labels`` (used by the corpus generator) and checked by a test that
slices each label's range out of the expanded text and compares it with the value it names.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from codekavach.core.models import Confidence, PlaceholderKind
from codekavach.privacy.detect.base import TypedSpan
from tests.support.synthetic import synthetic_value

CORPUS_ROOT: Final = Path(__file__).resolve().parents[1] / "fixtures" / "detect" / "corpus"
DETECTOR_ID: Final = "fake.corpus"
_MARKER: Final = re.compile(r"\{\{(secret|pii|term):([a-z0-9_]+)(?::(\d+))?\}\}")
_KINDS: Final = {
    "secret": PlaceholderKind.SECRET,
    "pii": PlaceholderKind.PII,
    "term": PlaceholderKind.TERM,
}


@dataclass(frozen=True)
class CorpusCase:
    """One expanded corpus case."""

    name: str
    text: str
    detected: tuple[TypedSpan, ...]
    expected: tuple[TypedSpan, ...]


def expand(template: str) -> str:
    """Replace every marker of ``template`` with its synthetic value."""

    def value(match: re.Match[str]) -> str:
        return synthetic_value(match.group(1), match.group(2), int(match.group(3) or 0))

    return _MARKER.sub(value, template)


def span_from_label(label: dict[str, Any]) -> TypedSpan:
    """Build a :class:`TypedSpan` from one entry of a labels file."""
    return TypedSpan(
        kind=PlaceholderKind(label["kind"]),
        subtype=label["subtype"],
        start_byte=label["start_byte"],
        end_byte=label["end_byte"],
        confidence=Confidence(label["confidence"]),
        detector=DETECTOR_ID,
    )


def case_names() -> list[str]:
    """The names of every case in the corpus, sorted."""
    return sorted(
        path.name.removesuffix(".labels.json") for path in CORPUS_ROOT.glob("*.labels.json")
    )


def load_case(name: str) -> CorpusCase:
    """Load and expand the case ``name``."""
    text = expand((CORPUS_ROOT / f"{name}.txt").read_text(encoding="utf-8"))
    labels = json.loads((CORPUS_ROOT / f"{name}.labels.json").read_text(encoding="utf-8"))
    return CorpusCase(
        name=name,
        text=text,
        detected=tuple(span_from_label(label) for label in labels["detected"]),
        expected=tuple(span_from_label(label) for label in labels["expected"]),
    )


def byte_range(text: str, needle: str, nth: int = 0) -> tuple[int, int]:
    """The UTF-8 byte range of the ``nth`` occurrence of ``needle`` in ``text``."""
    index = -1
    for _ in range(nth + 1):
        index = text.index(needle, index + 1)
    start = len(text[:index].encode("utf-8"))
    return start, start + len(needle.encode("utf-8"))
