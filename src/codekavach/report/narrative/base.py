"""Narrative blocks and the aggregated facts they are written from.

Owning epic: E30 (E30-03).

Every sentence of the deterministic narrative is composed from ``AggregatedFacts`` (counts and
public labels) and from the finding views; nothing is invented and no model is involved, so the
same scan always gives the same prose. ``provenance`` records where a block came from so a reader
can tell template prose from model prose if a model-assisted mode is added.
"""

from collections import Counter
from collections.abc import Sequence
from typing import ClassVar, Literal

from pydantic import Field

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.report.model.finding_view import FindingView
from codekavach.report.model.library import cwe_name

TEMPLATE_VERSION = "v1"
SEVERITIES = ("critical", "high", "medium", "low", "info")


class NarrativeBlock(KavachModel):
    """One paragraph or list of the narrative."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    id: str
    heading: str
    paragraphs: tuple[str, ...] = ()
    bullets: tuple[str, ...] = ()
    provenance: Literal["template", "llm"] = "template"
    facts_used: tuple[str, ...] = ()
    template_version: str | None = TEMPLATE_VERSION

    @property
    def text(self) -> str:
        """Paragraphs and bullets as plain text."""
        parts = list(self.paragraphs) + [f"- {item}" for item in self.bullets]
        return "\n\n".join(parts)


class RoadmapItem(KavachModel):
    """One prioritised remediation action."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    priority: str
    lane: str
    window: str
    theme: str
    action: str
    effort: str
    severity: str
    report_ids: tuple[str, ...] = ()


class AggregatedFacts(KavachModel):
    """Counts and public labels only: no code, no paths, no identifiers."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    total: int = Field(ge=0)
    by_severity: tuple[tuple[str, int], ...]
    top_cwes: tuple[tuple[str, int], ...] = ()
    top_owasp: tuple[tuple[str, int], ...] = ()
    languages: tuple[str, ...] = ()
    files_analysed: int = 0
    lines_analysed: int = 0
    reviewed_by_model: int = 0
    confirmed_by_model: int = 0
    taint_confirmed: int = 0
    privacy_level: str = "L3"
    posture: str = "Low"

    def count(self, severity: str) -> int:
        """The number of findings of ``severity``."""
        return dict(self.by_severity).get(severity, 0)

    def as_prompt_lines(self) -> tuple[str, ...]:
        """The facts as short lines, for a model-assisted summary."""
        lines = [f"total findings: {self.total}"]
        lines.extend(f"{name}: {count}" for name, count in self.by_severity)
        lines.extend(f"weakness {name}: {count}" for name, count in self.top_cwes)
        lines.extend(f"owasp {name}: {count}" for name, count in self.top_owasp)
        lines.append(f"languages: {', '.join(self.languages) or 'n/a'}")
        lines.append(f"posture: {self.posture}")
        return tuple(lines)

    @classmethod
    def from_views(
        cls,
        views: Sequence[FindingView],
        *,
        languages: Sequence[str] = (),
        files_analysed: int = 0,
        lines_analysed: int = 0,
        privacy_level: str = "L3",
    ) -> "AggregatedFacts":
        """The facts of ``views``."""
        severities = Counter(view.severity for view in views)
        cwes: Counter[str] = Counter()
        owasp: Counter[str] = Counter()
        for view in views:
            if view.cwe:
                cwes[f"CWE-{view.cwe[0]} {cwe_name(view.cwe[0])}"] += 1
            for item in view.owasp[:1]:
                owasp[f"{item.clause} {item.title or ''}".strip()] += 1
        reviewed = [view for view in views if view.verdict is not None]
        return cls(
            total=len(views),
            by_severity=tuple((name, severities.get(name, 0)) for name in SEVERITIES),
            top_cwes=tuple(cwes.most_common(5)),
            top_owasp=tuple(owasp.most_common(5)),
            languages=tuple(languages),
            files_analysed=files_analysed,
            lines_analysed=lines_analysed,
            reviewed_by_model=len(reviewed),
            confirmed_by_model=sum(1 for v in reviewed if v.verdict and v.verdict.is_vulnerable),
            taint_confirmed=sum(1 for view in views if view.flow),
            privacy_level=privacy_level,
            posture=posture(severities),
        )


def posture(severities: Counter[str] | dict[str, int]) -> str:
    """The overall risk posture: the highest severity present, as a rating word."""
    for name, label in (
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Moderate"),
        ("low", "Low"),
    ):
        if severities.get(name, 0):
            return label
    return "Minimal"
