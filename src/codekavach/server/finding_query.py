"""The findings list: filters, baseline state, merged engines, SLA and paging.

Owning epic: E32.

``FindingFilters`` holds every filter of the findings page. The indexed columns (severity,
status, CWE, primary engine, path, text) are filtered in SQL; the filters that read the stored
finding JSON (language, any reporting engine, LLM verdict, privacy level, OWASP category) and the
baseline state are applied afterwards, then the list is paged. ``list_findings`` returns the page
and the total, so ``GET /findings`` and the saved-view counts share one implementation.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.server.db.models import FindingRow, ScanRow
from codekavach.server.insights import (
    also_reported_by,
    baseline_states,
    merged_engines,
    review_level,
    sla,
    sla_policy,
    verdict_word,
)
from codekavach.server.results import finding_summary

MAX_LIMIT = 1000
VERDICTS = frozenset({"vulnerable", "not_vulnerable", "uncertain", "unreviewed"})
BASELINE_STATES = frozenset({"new", "unchanged", "fixed"})


def _split(value: str | None) -> list[str]:
    return [item.strip().lower() for item in (value or "").split(",") if item.strip()]


@dataclass
class FindingFilters:
    """Every filter of the findings list (all optional; lists are comma separated)."""

    severity: str | None = None
    status: str | None = None
    cwe: str | None = None
    q: str | None = None
    engine: str | None = None
    path: str | None = None
    language: str | None = None
    verdict: str | None = None
    level: str | None = None
    owasp: str | None = None
    assignee: str | None = None
    baseline_state: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> "FindingFilters":
        """Filters from a saved view (unknown keys are ignored)."""
        known = {name for name in cls.__dataclass_fields__ if name != "extra"}
        chosen: dict[str, Any] = {
            key: (str(value) if value is not None else None)
            for key, value in values.items()
            if key in known
        }
        return cls(**chosen)

    def as_dict(self) -> dict[str, str]:
        """The filters that are set."""
        return {
            name: value
            for name in self.__dataclass_fields__
            if name != "extra" and (value := getattr(self, name))
        }


def latest_scan_ids(session: Session) -> list[str]:
    """The latest completed scan of every project."""
    latest: dict[str, str] = {}
    for row in session.scalars(
        select(ScanRow).where(ScanRow.status == "completed").order_by(ScanRow.finished_at)
    ):
        latest[row.project_id] = row.id
    return list(latest.values())


def _sql(scan_ids: Sequence[str], filters: FindingFilters, me: str | None) -> Any:
    query = select(FindingRow).where(FindingRow.scan_id.in_(list(scan_ids)))
    if filters.severity:
        query = query.where(FindingRow.severity.in_(_split(filters.severity)))
    if filters.status:
        query = query.where(FindingRow.status.in_(_split(filters.status)))
    if filters.cwe:
        number = re.sub(r"(?i)^cwe-", "", filters.cwe.strip())
        query = query.where(FindingRow.cwe.contains(f"CWE-{number}"))
    if filters.path:
        query = query.where(FindingRow.path.contains(filters.path))
    if filters.assignee:
        who = me if filters.assignee == "me" else filters.assignee
        query = query.where(FindingRow.assignee == who)
    if filters.q:
        pattern = f"%{filters.q.lower()}%"
        query = query.where(
            FindingRow.title.ilike(pattern)
            | FindingRow.path.ilike(pattern)
            | FindingRow.rule_id.ilike(pattern)
            | FindingRow.cwe.ilike(pattern)
            | FindingRow.id.ilike(pattern)
        )
    return query.order_by(FindingRow.severity_rank.desc(), FindingRow.path, FindingRow.line)


def _owasp_ids(data: dict[str, Any]) -> list[str]:
    return [str(ref.get("id") or "").lower() for ref in data.get("owasp") or []]


def _matches(item: dict[str, Any], data: dict[str, Any], filters: FindingFilters) -> bool:
    checks = [
        not filters.language or str(data.get("language") or "").lower() in _split(filters.language),
        not filters.engine
        or bool(set(_split(filters.engine)) & {str(e["engine"]).lower() for e in item["engines"]}),
        not filters.verdict or item["verdict"] in _split(filters.verdict),
        not filters.level or str(item["privacy_level"] or "").lower() in _split(filters.level),
        not filters.owasp
        or any(i.startswith(want) for want in _split(filters.owasp) for i in _owasp_ids(data)),
        not filters.baseline_state or item["baseline_state"] in _split(filters.baseline_state),
    ]
    return all(checks)


def enrich(
    row: FindingRow,
    *,
    folded: dict[str, list[str]],
    states: dict[str, str],
    has_baseline: bool,
    policy: dict[str, int | None],
    scan_level: str | None,
) -> dict[str, Any]:
    """The list JSON of a finding with the derived fields."""
    data = row.data or {}
    item = finding_summary(row)
    item["engines"] = merged_engines(row, folded)
    item["merged_from"] = len(item["engines"])
    item["verdict"] = verdict_word(data)
    item["privacy_level"] = review_level(data) or scan_level
    item["language"] = data.get("language")
    item["baseline_state"] = states.get(row.id, "new" if has_baseline else None)
    item.update(sla(row, policy))
    return item


def list_findings(
    session: Session,
    scan_ids: Sequence[str],
    filters: FindingFilters,
    *,
    settings: dict[str, Any],
    offset: int = 0,
    limit: int | None = None,
    baseline: str | None = None,
    me: str | None = None,
) -> dict[str, Any]:
    """``{items, total, offset, limit, baseline_scan_id}`` for ``scan_ids`` under ``filters``."""
    scans = {row.id: row for row in session.scalars(select(ScanRow).where(
        ScanRow.id.in_(list(scan_ids))))}  # fmt: skip
    policy = sla_policy(settings)
    items: list[dict[str, Any]] = []
    baseline_ids: dict[str, str | None] = {}
    fixed_ids: list[str] = []
    for scan_id, scan in scans.items():
        base_id, states, fixed = baseline_states(session, scan, baseline)
        baseline_ids[scan_id] = base_id
        fixed_ids.extend(fixed)
        folded = also_reported_by(scan)
        rows = session.scalars(_sql([scan_id], filters, me))
        for row in rows:
            item = enrich(row, folded=folded, states=states, has_baseline=base_id is not None,
                          policy=policy, scan_level=scan.privacy_level)  # fmt: skip
            if _matches(item, row.data or {}, filters):
                items.append(item)
    if filters.baseline_state and "fixed" in _split(filters.baseline_state) and fixed_ids:
        for row in session.scalars(select(FindingRow).where(FindingRow.id.in_(fixed_ids))):
            item = enrich(row, folded={}, states={row.id: "fixed"}, has_baseline=True,
                          policy=policy, scan_level=None)  # fmt: skip
            item["baseline_state"] = "fixed"
            if _matches(item, row.data or {}, filters):
                items.append(item)
    items.sort(key=lambda item: (-_rank(item["severity"]), item["path"], item["line"]))
    total = len(items)
    start = max(0, offset)
    size = MAX_LIMIT if limit is None else max(1, min(limit, MAX_LIMIT))
    single = next(iter(baseline_ids.values()), None) if len(baseline_ids) == 1 else None
    return {
        "items": items[start : start + size],
        "total": total,
        "offset": start,
        "limit": size,
        "baseline_scan_id": single,
    }


def _rank(severity: str) -> int:
    from codekavach.server.results import SEVERITY_RANK  # noqa: PLC0415

    return SEVERITY_RANK.get(severity, 0)
