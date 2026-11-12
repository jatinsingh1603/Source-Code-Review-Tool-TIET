"""Routes for health, version, dashboard statistics, settings, policy, providers and audit.

Owning epic: E32.

``/health`` and ``/version`` are public; everything else needs a token. ``/stats`` aggregates the
dashboard's home page from the server database. ``/policy`` stores the privacy policy document
(``codekavach.policy.toml``) that every server scan applies; it is validated by the E25 policy
engine before it is saved. Provider keys are never accepted or returned here, only references.
"""

import contextlib
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

import codekavach
from codekavach.core.log import get_logger
from codekavach.server import audit
from codekavach.server.auth.dependencies import (
    SessionDep,
    StateDep,
    client_of,
    require,
)
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import AuditEvent, FindingRow, Project, ScanRow
from codekavach.server.errors import ApiError
from codekavach.server.insights import also_reported_by, merged_engines, mttr
from codekavach.server.providers import list_providers, test_provider
from codekavach.server.rbac import Permission
from codekavach.server.results import SEVERITY_ORDER, scan_env
from codekavach.server.schemas import PolicyBody, ProviderTestBody, SettingsBody
from codekavach.server.state import ServerState

_log = get_logger("codekavach.server.system")
router = APIRouter(tags=["system"])
ReadDep = Depends(require(Permission.read))
SettingsDep = Depends(require(Permission.settings_write))
POLICY_NAME: Final = "codekavach.policy.toml"
DEFAULT_POLICY: Final = """# CodeKavach privacy policy, applied to every server scan.
# Rules can only tighten the privacy level chosen for a scan; never_send keeps a path local.
policy_version = 1

[[path]]
pattern = "**/secrets/**"
never_send = true

[[path]]
pattern = "**/payments/**"
level = "L3"
"""


def _version() -> str:
    try:
        from importlib.metadata import version  # noqa: PLC0415

        return version("codekavach")
    except Exception:  # noqa: BLE001 - running from a source tree without metadata
        return str(getattr(codekavach, "__version__", "0.0.0"))


@router.get("/health")
def health(state: StateDep) -> dict[str, Any]:
    """Liveness and readiness: the database answers and the workers run."""
    try:
        with state.db.transaction() as session:
            session.execute(select(1))
        database = "ok"
    except Exception:  # noqa: BLE001 - reported, not raised
        database = "error"
    return {
        "status": "ok" if database == "ok" else "degraded",
        "database": database,
        "active_scans": len(state.runner.active()),
        "uptime_seconds": int(time.time() - state.started_at),
        "network": network_posture(state),
    }


_posture: dict[str, tuple[float, str]] = {}


def network_posture(state: ServerState) -> str:
    """``online`` when the default provider is remote and enabled, else ``offline``.

    It says whether a default scan would send payloads off this machine (through the egress
    guard), not whether the host has a network connection. Cached for 30 seconds.
    """
    cached = _posture.get("value")
    if cached is not None and time.monotonic() - cached[0] < 30.0:
        return cached[1]
    value = "offline"
    try:
        default = str(state.get_settings().get("default_provider") or "mock")
        provider = _server_settings(state).llm.providers.get(default)
        if provider is not None and provider.is_remote and provider.enabled:
            value = "online"
    except Exception as error:  # noqa: BLE001 - an unreadable configuration sends nothing
        _log.info("server_network_posture_unknown", error_type=type(error).__name__)
    _posture["value"] = (time.monotonic(), value)
    return value


@router.get("/version")
def version() -> dict[str, Any]:
    """The version of the server and its API."""
    return {"name": "CodeKavach", "version": _version(), "api": "v1"}


@router.get("/stats", dependencies=[ReadDep])
def stats(session: SessionDep) -> dict[str, Any]:
    """Figures for the dashboard home page, over the latest completed scan of every project."""
    from codekavach.server.routers.scans import scan_json  # noqa: PLC0415

    projects = session.scalar(select(func.count()).select_from(Project)) or 0
    scans = session.scalar(select(func.count()).select_from(ScanRow)) or 0
    latest: dict[str, ScanRow] = {}
    completed = session.scalars(
        select(ScanRow).where(ScanRow.status == "completed").order_by(ScanRow.finished_at)
    ).all()
    for row in completed:
        latest[row.project_id] = row
    by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
    open_findings = 0
    rows = (
        list(session.scalars(select(FindingRow).where(FindingRow.scan_id.in_(
            [row.id for row in latest.values()]))))
        if latest
        else []
    )  # fmt: skip
    by_status: Counter[str] = Counter()
    for item in rows:
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
        by_status[item.status] += 1
        if item.status in {"open", "confirmed"}:
            open_findings += 1
    last = session.scalars(select(ScanRow).order_by(ScanRow.created_at.desc()).limit(1)).first()
    trend = [
        {
            "scan_id": row.id,
            "project_id": row.project_id,
            "date": as_utc(row.finished_at),
            **{name: int((row.counts or {}).get(name, 0)) for name in SEVERITY_ORDER},
        }
        for row in completed[-20:]
    ]
    folded: dict[str, list[str]] = {}
    for scan in latest.values():
        folded.update(also_reported_by(scan))
    return {
        "projects": projects,
        "scans": scans,
        "findings_by_severity": by_severity,
        "findings_by_status": dict(sorted(by_status.items())),
        "findings_total": sum(by_severity.values()),
        "open_findings": open_findings,
        "last_scan": scan_json(last, session.get(Project, last.project_id))
        if last is not None
        else None,
        "trend": trend,
        **mttr(session),
        "risk_matrix": _risk_matrix(rows),
        "risk_matrix_bands": _risk_bands(rows),
        "owasp_by_engine": _owasp_by_engine(rows, folded),
        "top_cwes": _top_cwes(rows),
        "scope": {"scan_ids": [row.id for row in latest.values()]},
    }


def _risk_matrix(rows: list[FindingRow]) -> list[dict[str, int]]:
    """Counts by likelihood level (1..5) and impact level (1..5) of the findings."""
    cells: Counter[tuple[int, int]] = Counter()
    for row in rows:
        data = row.data or {}
        likelihood = (data.get("likelihood") or {}).get("level")
        impact = (data.get("impact") or {}).get("level")
        if isinstance(likelihood, int) and isinstance(impact, int):
            cells[(likelihood, impact)] += 1
    return [
        {"likelihood": likelihood, "impact": impact, "count": count}
        for (likelihood, impact), count in sorted(cells.items())
    ]


def _risk_bands(rows: list[FindingRow]) -> list[dict[str, Any]]:
    """Counts by the OWASP Risk Rating likelihood and impact bands (low, medium, high)."""
    cells: Counter[tuple[str, str]] = Counter()
    for row in rows:
        risk = (row.data or {}).get("risk") or {}
        likelihood, impact = risk.get("owasp_likelihood_band"), risk.get("owasp_impact_band")
        if likelihood and impact:
            cells[(str(likelihood), str(impact))] += 1
    return [
        {"likelihood": likelihood, "impact": impact, "count": count}
        for (likelihood, impact), count in sorted(cells.items())
    ]


def _owasp_by_engine(rows: list[FindingRow], folded: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Counts by OWASP Top 10 category and every engine that reported the finding."""
    cells: Counter[tuple[str, str]] = Counter()
    titles: dict[str, str] = {}
    for row in rows:
        refs = [ref for ref in (row.data or {}).get("owasp") or [] if isinstance(ref, dict)]
        engines = [item["engine"] for item in merged_engines(row, folded)]
        for ref in refs:
            category = str(ref.get("id") or "")
            if not category:
                continue
            titles.setdefault(category, str(ref.get("title") or ""))
            for engine in engines:
                cells[(category, engine)] += 1
    return [
        {"owasp": owasp, "title": titles.get(owasp, ""), "engine": engine, "count": count}
        for (owasp, engine), count in sorted(cells.items())
    ]


def _top_cwes(rows: list[FindingRow], limit: int = 10) -> list[dict[str, Any]]:
    """The most frequent CWEs with their names, most frequent first."""
    counts: Counter[str] = Counter()
    names: dict[str, str | None] = {}
    for row in rows:
        primary = next((item for item in row.cwe.split(",") if item), None)
        if primary is None:
            continue
        counts[primary] += 1
        risk = (row.data or {}).get("risk") or {}
        names.setdefault(primary, risk.get("cwe_name"))
    return [
        {"cwe": cwe, "name": names.get(cwe), "count": count}
        for cwe, count in counts.most_common(limit)
    ]


def _server_settings(state: ServerState) -> Any:
    from codekavach.config import load_settings  # noqa: PLC0415

    return load_settings(
        target=None,
        env=scan_env(state.config.home_dir, state.passphrase_env),
        cli_overrides=state.provider_overrides() or None,
    ).settings


@router.get("/settings", dependencies=[ReadDep])
def get_settings(state: StateDep) -> dict[str, Any]:
    """Server settings: default provider, model and privacy level, report organisation."""
    return state.get_settings()


@router.put("/settings")
def put_settings(
    body: SettingsBody, request: Request, state: StateDep, principal: Any = SettingsDep
) -> dict[str, Any]:
    """Change server settings (admin)."""
    values = body.model_dump(exclude_none=True)
    try:
        updated = state.put_settings(values)
    except ValueError as error:
        raise ApiError(400, "key_not_reference", str(error)) from None
    audit.record(state.db, actor=principal.username, action="settings.update",
                 client=client_of(request), detail={"fields": sorted(values)})  # fmt: skip
    return updated


def policy_path(state: ServerState) -> Path:
    """Where the server keeps its policy document."""
    return state.config.data_dir / POLICY_NAME


def _parse_policy(text: str) -> dict[str, Any]:
    try:
        from codekavach.privacy.policy.engine import PolicyError, load_document  # noqa: PLC0415
    except ImportError:
        import tomllib  # noqa: PLC0415

        try:
            return {"valid": True, "document": tomllib.loads(text), "hash": None}
        except tomllib.TOMLDecodeError as error:
            raise ApiError(400, "policy_invalid", f"invalid TOML: {error}") from None
    try:
        document, digest = load_document(text)
    except PolicyError as error:
        raise ApiError(400, "policy_invalid", str(error)) from None
    return {"valid": True, "document": document.model_dump(mode="json"), "hash": digest}


@router.get("/policy", dependencies=[ReadDep])
def get_policy(state: StateDep) -> dict[str, Any]:
    """The privacy policy document every server scan applies."""
    path = policy_path(state)
    text = path.read_text(encoding="utf-8") if path.is_file() else DEFAULT_POLICY
    return {"toml": text, "parsed": _parse_policy(text), "active": path.is_file()}


@router.put("/policy")
def put_policy(
    body: PolicyBody, request: Request, state: StateDep, principal: Any = SettingsDep
) -> dict[str, Any]:
    """Validate and store the policy document (admin)."""
    parsed = _parse_policy(body.toml)
    policy_path(state).write_text(body.toml, encoding="utf-8")
    audit.record(state.db, actor=principal.username, action="policy.update",
                 client=client_of(request), detail={"hash": parsed.get("hash")})  # fmt: skip
    return {"toml": body.toml, "parsed": parsed, "active": True}


@router.get("/providers", dependencies=[ReadDep])
def providers(state: StateDep) -> list[dict[str, Any]]:
    """The LLM providers this server can use."""
    try:
        settings = _server_settings(state)
    except Exception as error:  # noqa: BLE001 - an invalid configuration is reported
        raise ApiError(500, "config_invalid", f"the configuration is invalid: "
                       f"{type(error).__name__}") from None  # fmt: skip
    default = state.get_settings().get("default_provider")
    return list_providers(settings, str(default) if default else None)


USAGE_FILE: Final = "usage.json"


def _scan_usage(state: ServerState, row: ScanRow) -> list[dict[str, Any]]:
    """Per (provider, model, month) requests and tokens of one completed scan (cached)."""
    from codekavach.server.routers.scans import scan_results  # noqa: PLC0415

    if not row.workspace:
        return []
    cache = Path(row.workspace) / USAGE_FILE
    if cache.is_file():
        try:
            loaded = json.loads(cache.read_text(encoding="utf-8"))
            return list(loaded) if isinstance(loaded, list) else []
        except (OSError, ValueError):
            pass
    try:
        records = scan_results(state, row).records()
    except ApiError:
        return []
    totals: dict[tuple[str, str, str], Counter[str]] = {}
    for record in records:
        outcome = str(record.outcome.value)
        key = (record.provider, record.model, record.timestamp.strftime("%Y-%m"))
        counter = totals.setdefault(key, Counter())
        if outcome == "sent":
            counter["requests"] += 1
            counter["input_tokens"] += int(record.token_counts.prompt)
        elif outcome == "completed":
            counter["output_tokens"] += int(record.token_counts.completion or 0)
        elif outcome == "blocked":
            counter["blocked"] += 1
        elif outcome == "not_sent_dry_run":
            counter["recorded"] += 1
    rows = [
        {"provider": provider, "model": model, "month": month, **dict(counter)}
        for (provider, model, month), counter in sorted(totals.items())
    ]
    with contextlib.suppress(OSError):
        cache.write_text(json.dumps(rows), encoding="utf-8")
    return rows


@router.get("/providers/usage", dependencies=[Depends(require(Permission.ledger_read))])
def provider_usage(
    state: StateDep, session: SessionDep, month: str | None = None
) -> dict[str, Any]:
    """Requests and tokens per provider and month, summed from every scan's egress ledger."""
    if month is not None and not re.fullmatch(r"\d{4}-\d{2}", month):
        raise ApiError(400, "invalid_month", "give the month as YYYY-MM")
    totals: dict[tuple[str, str], Counter[str]] = {}
    models: dict[tuple[str, str], set[str]] = {}
    scans = session.scalars(select(ScanRow).where(ScanRow.status == "completed"))
    for row in scans:
        for item in _scan_usage(state, row):
            if month is not None and item["month"] != month:
                continue
            key = (str(item["provider"]), str(item["month"]))
            counter = totals.setdefault(key, Counter())
            for name in ("requests", "input_tokens", "output_tokens", "blocked", "recorded"):
                counter[name] += int(item.get(name, 0))
            counter["scans"] += 1
            models.setdefault(key, set()).add(str(item["model"]))
    return {
        "month": month,
        "source": "egress ledgers of the completed scans; tokens are estimates when the "
        "provider reported none",
        "usage": [
            {"provider": provider, "month": item_month, "models": sorted(models[(provider,
             item_month)]), **{name: counter.get(name, 0) for name in (
                "requests", "input_tokens", "output_tokens", "blocked", "recorded", "scans")}}
            for (provider, item_month), counter in sorted(totals.items())
        ],
    }  # fmt: skip


@router.post("/providers/{provider_id}/test")
def provider_test(
    provider_id: str,
    request: Request,
    state: StateDep,
    model: str | None = None,
    body: ProviderTestBody | None = None,
    principal: Any = Depends(require(Permission.provider_test)),
) -> dict[str, Any]:
    """Probe a provider with a constant synthetic payload: reachability, latency and model."""
    settings = _server_settings(state)
    chosen = (body.model if body is not None else None) or model
    result = test_provider(provider_id, settings, chosen, state.config.home_dir / "probes")
    audit.record(state.db, actor=principal.username, action="provider.test",
                 resource=provider_id, client=client_of(request),
                 outcome="allowed" if result["ok"] else "failed")  # fmt: skip
    return result


@router.get("/audit", dependencies=[Depends(require(Permission.audit_read))])
def audit_log(session: SessionDep, limit: int = 200) -> dict[str, Any]:
    """The newest audit events and whether the hash chain is intact."""
    intact, checked = audit.verify_audit_chain(session)
    rows = session.scalars(
        select(AuditEvent).order_by(AuditEvent.id.desc()).limit(max(1, min(limit, 1000)))
    )
    return {
        "chain_intact": intact,
        "checked": checked,
        "events": [
            {
                "id": row.id,
                "at": as_utc(row.at),
                "actor": row.actor,
                "action": row.action,
                "resource": row.resource,
                "outcome": row.outcome,
                "client": row.client,
                "detail": row.detail,
            }
            for row in rows
        ],
    }
