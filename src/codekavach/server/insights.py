"""Derived figures the dashboard shows beside the stored results: baseline, SLA, engines, runs.

Owning epic: E32.

Everything here is computed from data the server already holds: the finding rows and their
triage history, the stored scan record (``scan.json``) and the scan's artefacts. Nothing is
estimated or invented; when the source of a figure is absent the figure is ``None``.

* ``baseline_states`` compares the fingerprints of a scan with those of a baseline scan through
  ``codekavach.analysis.aggregate.delta.compute_delta`` (new, unchanged, fixed).
* ``also_reported_by`` reads the ``aggregate.also_reported_by`` property the correlation step
  put on each kept candidate, so a finding lists every engine that reported it.
* ``sla`` adds a due date from the severity policy in the server settings (``sla_days``).
* ``llm_runs`` lists the model runs of a finding (one per review, with its ledger entry).
"""

import contextlib
import json
import re
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.core.log import get_logger
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import FindingEvent, FindingRow, ScanRow, utcnow
from codekavach.server.results import ScanPaths

_log = get_logger("codekavach.server.insights")

DEFAULT_SLA_DAYS: Final[dict[str, int | None]] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": None,
}
CLOSED_STATUSES: Final = frozenset({"fixed", "false_positive", "accepted_risk"})
ALSO_REPORTED_FILE: Final = "also_reported_by.json"
_SCENARIO: Final = re.compile(r"Attack scenario:\s*(.+?)(?:\n\n|$)", re.DOTALL)
_EXAMPLE: Final = re.compile(r"Secure example:\s*```([a-z0-9]*)\n(.*?)\n```", re.DOTALL)


# --- baseline -------------------------------------------------------------------------------


def previous_scan(session: Session, row: ScanRow) -> ScanRow | None:
    """The completed scan of the same project that finished before ``row`` started."""
    query = (
        select(ScanRow)
        .where(
            ScanRow.project_id == row.project_id,
            ScanRow.status == "completed",
            ScanRow.id != row.id,
        )
        .order_by(ScanRow.finished_at.desc())
    )
    cutoff = as_utc(row.started_at or row.created_at)
    for candidate in session.scalars(query):
        finished = as_utc(candidate.finished_at)
        if cutoff is None or finished is None or finished <= cutoff:
            return candidate
    return None


def fingerprints(session: Session, scan_id: str) -> dict[str, str]:
    """Fingerprint to finding id for one scan."""
    rows = session.execute(
        select(FindingRow.fingerprint, FindingRow.id).where(FindingRow.scan_id == scan_id)
    )
    return {str(fp): str(fid) for fp, fid in rows if fp}


def baseline_states(
    session: Session, scan: ScanRow, baseline_id: str | None
) -> tuple[str | None, dict[str, str], list[str]]:
    """``(baseline scan id, finding id -> new|unchanged, fixed finding ids of the baseline)``.

    ``baseline_id`` names the scan to compare with; ``None`` picks the previous completed scan
    of the project. Without a baseline every state is absent.
    """
    from codekavach.analysis.aggregate.delta import compute_delta  # noqa: PLC0415

    base = session.get(ScanRow, baseline_id) if baseline_id else previous_scan(session, scan)
    if base is None or base.id == scan.id:
        return None, {}, []
    before = fingerprints(session, base.id)
    after = fingerprints(session, scan.id)
    delta = compute_delta(before, after)
    states = {after[fp]: "new" for fp in delta.new}
    states.update({after[fp]: "unchanged" for fp in delta.unchanged})
    return base.id, states, [before[fp] for fp in delta.fixed]


# --- merged engines -------------------------------------------------------------------------


def also_reported_by(scan: ScanRow) -> dict[str, list[str]]:
    """Candidate id to the ``engine:rule`` pairs folded into it by correlation (cached)."""
    if not scan.workspace or not scan.core_scan_id:
        return {}
    paths = ScanPaths(Path(scan.workspace))
    cache = paths.workspace / ALSO_REPORTED_FILE
    if cache.is_file():
        try:
            loaded = json.loads(cache.read_text(encoding="utf-8"))
            return {str(k): [str(v) for v in values] for k, values in loaded.items()}
        except (OSError, ValueError, AttributeError):
            pass
    found: dict[str, list[str]] = {}
    try:
        from codekavach.core.models import Candidate  # noqa: PLC0415
        from codekavach.core.pipeline import keys  # noqa: PLC0415
        from codekavach.core.store.artefacts import OnDiskArtefactStore  # noqa: PLC0415
        from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

        store = OnDiskArtefactStore.open_existing(StateLayout(paths.state_dir), scan.core_scan_id)
        if store.has(keys.CANDIDATES):
            for candidate in store.get_list(keys.CANDIDATES, Candidate):
                for key, value in candidate.properties:
                    if key == "aggregate.also_reported_by" and value:
                        found[str(candidate.id)] = [item for item in str(value).split(",") if item]
    except Exception as error:  # noqa: BLE001 - the list is enrichment, not a failure
        _log.info("server_candidates_unreadable", error_type=type(error).__name__)
        return {}
    with contextlib.suppress(OSError):
        cache.write_text(json.dumps(found), encoding="utf-8")
    return found


def merged_engines(row: FindingRow, folded: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Every engine that reported the finding: its own engines first, then the folded ones."""
    data = row.data or {}
    seen: dict[str, dict[str, Any]] = {}
    for ref in (data.get("provenance") or {}).get("engines") or []:
        engine = str(ref.get("engine") or "")
        if engine and engine not in seen:
            seen[engine] = {"engine": engine, "rule_id": ref.get("rule_id"), "merged": False}
    for candidate in (data.get("provenance") or {}).get("candidate_ids") or []:
        for pair in folded.get(str(candidate), []):
            engine, _, rule = pair.partition(":")
            if engine and engine not in seen:
                seen[engine] = {"engine": engine, "rule_id": rule or None, "merged": True}
    return list(seen.values())


# --- SLA ------------------------------------------------------------------------------------


def sla_policy(settings: dict[str, Any]) -> dict[str, int | None]:
    """The severity to days policy: the server setting over the defaults."""
    stored = settings.get("sla_days") or {}
    policy = dict(DEFAULT_SLA_DAYS)
    if isinstance(stored, dict):
        for key, value in stored.items():
            if key in policy and (value is None or (isinstance(value, int) and value > 0)):
                policy[key] = value
    return policy


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return as_utc(value)
    if isinstance(value, str) and value:
        try:
            return as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def sla(
    row: FindingRow, policy: dict[str, int | None], now: datetime | None = None
) -> dict[str, Any]:
    """``{sla_days, due_at, sla_state}`` of a finding; ``sla_state`` is ``None`` once closed."""
    days = policy.get(row.severity)
    first_seen = _parse_time((row.data or {}).get("created_at"))
    if days is None or first_seen is None:
        return {"sla_days": days, "due_at": None, "sla_state": None}
    due = first_seen + timedelta(days=days)
    state: str | None = None
    if row.status not in CLOSED_STATUSES:
        current = now or utcnow()
        if current > due:
            state = "overdue"
        elif due - current <= timedelta(days=max(1, days // 5)):
            state = "due_soon"
        else:
            state = "on_track"
    return {"sla_days": days, "due_at": due, "sla_state": state}


# --- LLM runs -------------------------------------------------------------------------------


def verdict_word(data: dict[str, Any]) -> str:
    """``vulnerable``, ``not_vulnerable``, ``uncertain`` or ``unreviewed`` (last review)."""
    reviews = (data.get("provenance") or {}).get("llm_reviews") or []
    if not reviews:
        return "unreviewed"
    value = reviews[-1].get("is_vulnerable")
    return {True: "vulnerable", False: "not_vulnerable"}.get(value, "uncertain")


def review_level(data: dict[str, Any]) -> str | None:
    """The privacy level the last review's payload was prepared at."""
    reviews = (data.get("provenance") or {}).get("llm_reviews") or []
    return str(reviews[-1].get("level")) if reviews and reviews[-1].get("level") else None


def llm_runs(data: dict[str, Any], ledger: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per model run: the reviews the finding records, plus ledger calls not in them."""
    reviews = (data.get("provenance") or {}).get("llm_reviews") or []
    runs: list[dict[str, Any]] = []
    seen: set[int] = set()
    for review in reviews:
        seq = review.get("ledger_seq")
        if isinstance(seq, int):
            seen.add(seq)
        value = review.get("is_vulnerable")
        runs.append(
            {
                "source": "review",
                "task": review.get("task"),
                "provider": review.get("provider"),
                "model": review.get("model"),
                "level": review.get("level"),
                "verdict": {True: "vulnerable", False: "not_vulnerable"}.get(value, "uncertain"),
                "is_vulnerable": value,
                "confidence": review.get("confidence"),
                "ledger_seq": seq,
            }
        )
    for entry in ledger:
        if entry.get("seq") in seen:
            continue
        runs.append(
            {
                "source": "ledger",
                "task": entry.get("task"),
                "provider": entry.get("provider"),
                "model": entry.get("model"),
                "level": entry.get("level"),
                "verdict": None,
                "is_vulnerable": None,
                "confidence": None,
                "ledger_seq": entry.get("seq"),
                "outcome": entry.get("outcome"),
            }
        )
    return runs


def consensus(runs: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """How the reviewed runs voted (``None`` without a review)."""
    votes = [run for run in runs if run.get("source") == "review"]
    if not votes:
        return None
    yes = sum(1 for run in votes if run.get("is_vulnerable") is True)
    no = sum(1 for run in votes if run.get("is_vulnerable") is False)
    decided = yes + no
    return {
        "samples": len(votes),
        "votes_vulnerable": yes,
        "votes_safe": no,
        "abstained": len(votes) - decided,
        "agreement": round(max(yes, no) / decided, 3) if decided else 0.0,
    }


def exploit_scenario(impact_text: str | None) -> str | None:
    """The ``Attack scenario`` part the explain task wrote into the impact, if it ran."""
    if not impact_text:
        return None
    match = _SCENARIO.search(impact_text)
    return match.group(1).strip() if match else None


def remediation_example(text: str | None) -> dict[str, str] | None:
    """The secure example the remediate task wrote, if it ran: ``{language, code}``."""
    if not text:
        return None
    match = _EXAMPLE.search(text)
    return {"language": match.group(1), "code": match.group(2)} if match else None


# --- MTTR -----------------------------------------------------------------------------------


def remediation_times(
    session: Session, project_id: str | None = None
) -> list[tuple[datetime, float]]:
    """``(fixed_at, days to fix)`` for every finding whose status was changed to fixed.

    With ``project_id``, only the findings of that project's scans count.
    """
    events = session.execute(
        select(FindingEvent.finding_id, FindingEvent.at)
        .where(FindingEvent.to_status == "fixed", FindingEvent.action == "status")
        .order_by(FindingEvent.at)
    ).all()
    first_fix: dict[str, datetime] = {}
    for finding_id, at in events:
        moment = as_utc(at)
        if moment is not None:
            first_fix.setdefault(str(finding_id), moment)
    if not first_fix:
        return []
    query = select(FindingRow).where(FindingRow.id.in_(list(first_fix)))
    if project_id is not None:
        query = query.join(ScanRow, ScanRow.id == FindingRow.scan_id).where(
            ScanRow.project_id == project_id
        )
    rows = session.scalars(query)
    result = []
    for row in rows:
        seen = _parse_time((row.data or {}).get("created_at"))
        fixed = first_fix.get(row.id)
        if seen is not None and fixed is not None and fixed >= seen:
            result.append((fixed, (fixed - seen).total_seconds() / 86400.0))
    return result


def mttr(session: Session, window_days: int = 30, project_id: str | None = None) -> dict[str, Any]:
    """Mean days to remediate: overall, this window, and the change from the window before."""
    times = remediation_times(session, project_id)
    if not times:
        return {"mttr_days": None, "mttr_delta_days": None, "mttr_samples": 0}
    now = utcnow()
    recent = [days for at, days in times if at >= now - timedelta(days=window_days)]
    earlier = [
        days
        for at, days in times
        if now - timedelta(days=2 * window_days) <= at < now - timedelta(days=window_days)
    ]
    overall = sum(days for _at, days in times) / len(times)
    delta = None
    if recent and earlier:
        delta = round(sum(recent) / len(recent) - sum(earlier) / len(earlier), 2)
    return {"mttr_days": round(overall, 2), "mttr_delta_days": delta, "mttr_samples": len(times)}
