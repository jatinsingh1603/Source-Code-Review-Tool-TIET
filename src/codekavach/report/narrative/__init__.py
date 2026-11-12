"""Narratives: executive summary, concentration statement and remediation roadmap.

Owning epic: E30. Normative layout: docs/ARCHITECTURE.md section 3.

The default and only shipped mode is ``template``: every sentence is composed from aggregated
facts and finding views, with no model call, so a report is reproducible and can be produced
air-gapped.
"""

from codekavach.report.narrative.base import AggregatedFacts, NarrativeBlock, RoadmapItem
from codekavach.report.narrative.executive import executive_summary
from codekavach.report.narrative.roadmap import build_roadmap

__all__ = [
    "AggregatedFacts",
    "NarrativeBlock",
    "RoadmapItem",
    "build_roadmap",
    "executive_summary",
]
