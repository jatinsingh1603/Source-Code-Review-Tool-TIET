"""The prioritised remediation roadmap.

Owning epic: E30 (E30-03).

Findings are grouped by lane (derived from severity) and, within a lane, by weakness class, so one
roadmap line fixes a class of problem rather than one line of code. Lanes are ordered by priority
and, within a lane, by severity, then by the number of findings the action closes, then by effort.
"""

from collections import defaultdict
from collections.abc import Sequence

from codekavach.report.model.finding_view import FindingView
from codekavach.report.model.library import lookup
from codekavach.report.narrative.base import RoadmapItem

_EFFORT_ORDER = {"low": 0, "medium": 1, "high": 2}


def build_roadmap(views: Sequence[FindingView]) -> tuple[RoadmapItem, ...]:
    """One action per lane and weakness class, most urgent first."""
    groups: dict[tuple[str, str], list[FindingView]] = defaultdict(list)
    for view in views:
        if view.status in {"fixed", "false_positive"}:
            continue
        key = (view.priority, f"CWE-{view.cwe[0]}" if view.cwe else view.rule_id or view.title)
        groups[key].append(view)
    items: list[RoadmapItem] = []
    for (priority, _), members in groups.items():
        first = members[0]
        entry = lookup(first.cwe)
        theme = entry.name if entry.cwe else first.title.rstrip(".")
        items.append(
            RoadmapItem(
                priority=priority,
                lane=first.lane,
                window=first.lane_window,
                theme=theme,
                action=entry.short_term if entry.cwe else first.remediation_short_term,
                effort=entry.effort,
                severity=max(members, key=lambda v: v.severity_rank).severity,
                report_ids=tuple(view.report_id for view in members),
            )
        )
    items.sort(
        key=lambda item: (
            item.priority,
            -len(item.report_ids),
            _EFFORT_ORDER.get(item.effort, 1),
            item.theme,
        )
    )
    return tuple(items)
