"""Routes for health, version, dashboard statistics, settings, policy, providers and audit.

Owning epic: E32.

``/health`` and ``/version`` are public; everything else needs a token. ``/stats`` aggregates the
dashboard's home page from the server database. ``/policy`` stores the privacy policy document
(``codekavach.policy.toml``) that every server scan applies; it is validated by the E25 policy
engine before it is saved. Provider keys are never accepted or returned here, only references.
"""

import time
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

import codekavach
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
from codekavach.server.providers import list_providers, test_provider
from codekavach.server.rbac import Permission
from codekavach.server.results import SEVERITY_ORDER, scan_env
from codekavach.server.schemas import PolicyBody, ProviderTestBody, SettingsBody
from codekavach.server.state import ServerState

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
    }


@router.get("/version")
def version() -> dict[str, Any]:
    """The version of the server and its API."""
    return {"name": "CodeKavach", "version": _version(), "api": "v1"}


@router.get("/stats", dependencies=[ReadDep])
def stats(session: SessionDep) -> dict[str, Any]:
    """Figures for the dashboard home page."""
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
    latest_ids = [row.id for row in latest.values()]
    if latest_ids:
        query = (
            select(FindingRow.severity, FindingRow.status, func.count())
            .where(FindingRow.scan_id.in_(latest_ids))
            .group_by(FindingRow.severity, FindingRow.status)
        )
        for severity, status, count in session.execute(query):
            by_severity[severity] = by_severity.get(severity, 0) + int(count)
            if status in {"open", "confirmed"}:
                open_findings += int(count)
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
    from codekavach.server.routers.scans import scan_json  # noqa: PLC0415

    return {
        "projects": projects,
        "scans": scans,
        "findings_by_severity": by_severity,
        "findings_total": sum(by_severity.values()),
        "open_findings": open_findings,
        "last_scan": scan_json(last) if last is not None else None,
        "trend": trend,
    }


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
