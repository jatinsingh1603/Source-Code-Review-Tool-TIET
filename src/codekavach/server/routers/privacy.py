"""Routes for the privacy centre: exposure budgets, policy explain, validation and templates.

Owning epic: E32.

``/privacy/budgets`` compares the egress limits of the configuration (``privacy.egress`` and
``llm.budget``) with what a scan used. ``/policy/explain`` runs the E25 policy engine
(``codekavach.privacy.policy.engine.PolicyEngine``) over the server's policy document for one path
and returns every contribution, as ``codekavach privacy explain`` prints it. ``/policy/validate``
checks a draft document (schema, minimum level) and resolves every file of the project's
inventory under it, so the editor can show how many files each rule matches and which level each
file would get; nothing is saved and nothing is sent. ``/policy/templates`` lists the example
documents shipped in ``docs/examples``.
"""

from collections import Counter
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

import codekavach
from codekavach.core.log import get_logger
from codekavach.server.auth.dependencies import SessionDep, StateDep, require
from codekavach.server.db.models import Project, ScanRow
from codekavach.server.errors import ApiError, not_found
from codekavach.server.rbac import Permission
from codekavach.server.results import ScanPaths
from codekavach.server.routers.platform import server_settings
from codekavach.server.routers.system import DEFAULT_POLICY, policy_path
from codekavach.server.schemas import PolicyValidateBody
from codekavach.server.state import ServerState

_log = get_logger("codekavach.server.privacy")

router = APIRouter(tags=["privacy"])
ReadDep = Depends(require(Permission.read))
LedgerDep = Depends(require(Permission.ledger_read))
EXAMPLES: Final = Path(codekavach.__file__).resolve().parents[2] / "docs" / "examples"
MAX_PREVIEW_FILES: Final = 200


def _latest_scan(session: Session, project_id: str | None) -> ScanRow | None:
    query = select(ScanRow).where(ScanRow.status == "completed")
    if project_id:
        query = query.where(ScanRow.project_id == project_id)
    return session.scalars(query.order_by(ScanRow.finished_at.desc())).first()


def _inventory(scan: ScanRow | None) -> list[tuple[str, str]]:
    """``(path, language)`` of every file the scan's ingest stage listed."""
    if scan is None or not scan.workspace or not scan.core_scan_id:
        return []
    from codekavach.core.pipeline import keys  # noqa: PLC0415
    from codekavach.core.store.artefacts import OnDiskArtefactStore  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415
    from codekavach.ingest.models import SourceFile  # noqa: PLC0415

    try:
        store = OnDiskArtefactStore.open_existing(
            StateLayout(ScanPaths(Path(scan.workspace)).state_dir), scan.core_scan_id
        )
        if not store.has(keys.FILES):
            return []
        return [
            (str(item.path), str(item.language.value))
            for item in store.get_list(keys.FILES, SourceFile)
        ]
    except Exception as error:  # noqa: BLE001 - no inventory is an empty list
        _log.info("server_inventory_unreadable", error_type=type(error).__name__)
        return []


def _tier(settings: Any, provider_id: str | None) -> Any:
    from codekavach.core.models.enums import TrustTier  # noqa: PLC0415

    provider = settings.llm.providers.get(provider_id or "")
    return provider.effective_trust_tier if provider is not None else TrustTier.LOCAL


def _engine(settings: Any, text: str) -> Any:
    from codekavach.privacy.policy.engine import (  # noqa: PLC0415
        PolicyEngine,
        PolicyError,
        load_document,
    )
    from codekavach.privacy.policy.loader import check_floor  # noqa: PLC0415

    try:
        document, digest = load_document(text)
        check_floor(document, settings, text, None)
    except PolicyError as error:
        raise ApiError(400, "policy_invalid", str(error)) from None
    return PolicyEngine(settings, document, digest), document


def _decision_json(path: str, decision: Any) -> dict[str, Any]:
    winner = decision.winner
    return {
        "path": path,
        "level": decision.level.value,
        "never_send": decision.never_send,
        "classifications": list(decision.classifications),
        "rule_key": decision.rule_key,
        "policy_hash": decision.policy_hash,
        "decided_by": str(winner.axis.value),
        "contributions": [
            {
                "axis": str(item.axis.value),
                "key": item.key,
                "level": item.level.value if item.level is not None else "never_send",
                "source": item.detail,
                "winner": item is winner,
            }
            for item in decision.contributions
        ],
        "explanation": decision.explain(path),
    }


def _policy_text(state: ServerState) -> str:
    path = policy_path(state)
    return path.read_text(encoding="utf-8") if path.is_file() else DEFAULT_POLICY


@router.get("/policy/explain", dependencies=[LedgerDep])
def explain(
    path: str,
    state: StateDep,
    session: SessionDep,
    project_id: str | None = None,
    provider: str | None = None,
    language: str | None = None,
    rule_id: str | None = None,
    cwe: str | None = None,
) -> dict[str, Any]:
    """Why ``path`` is prepared at its level: every axis's contribution, the winner marked."""
    from codekavach.ingest.langdetect import detect_language  # noqa: PLC0415

    if not path or len(path) > 1024 or path.startswith("/") or ".." in Path(path).parts:
        raise ApiError(400, "invalid_path", "give a path relative to the project root")
    settings = server_settings(state)
    engine, _document = _engine(settings, _policy_text(state))
    chosen = provider or str(state.get_settings().get("default_provider") or "mock")
    tier = _tier(settings, chosen)
    known = dict(_inventory(_latest_scan(session, project_id)))
    lang = language or known.get(path) or str(detect_language(path, b"").value)
    cwes = tuple(item.strip() for item in (cwe or "").split(",") if item.strip())
    decision = engine.resolve(path, tier, language=lang, rule_id=rule_id, cwes=cwes)
    return {
        **_decision_json(path, decision),
        "language": lang,
        "provider": chosen,
        "provider_tier": str(tier.value),
        "in_inventory": path in known,
    }


@router.post("/policy/validate", dependencies=[ReadDep])
def validate(body: PolicyValidateBody, state: StateDep, session: SessionDep) -> dict[str, Any]:
    """Check a draft policy and preview it over the project's files (dry run, nothing saved)."""
    from codekavach.privacy.policy.engine import PolicyError, load_document  # noqa: PLC0415
    from codekavach.privacy.policy.globs import GlobMatcher  # noqa: PLC0415
    from codekavach.privacy.policy.loader import check_floor  # noqa: PLC0415

    settings = server_settings(state)
    try:
        document, digest = load_document(body.toml)
        check_floor(document, settings, body.toml, None)
    except PolicyError as error:
        return {
            "valid": False,
            "schema": "codekavach.policy.toml v1",
            "errors": [{"code": error.code, "message": str(error), "line": error.line}],
            "notes": [],
            "matches": {},
            "files_resolved": 0,
        }
    if body.project_id and session.get(Project, body.project_id) is None:
        raise not_found("project")
    files = _inventory(_latest_scan(session, body.project_id))
    engine, _ = _engine(settings, body.toml)
    tier = _tier(settings, str(state.get_settings().get("default_provider") or "mock"))
    matches: dict[str, int] = {}
    rules = [(f"path[{i}]", rule.pattern) for i, rule in enumerate(document.path)]
    for index, rule in enumerate(document.classification):
        rules += [(f"classification[{index}]", pattern) for pattern in rule.patterns]
    for key, pattern in rules:
        matcher = GlobMatcher([pattern])
        matches[key] = matches.get(key, 0) + sum(1 for path, _ in files if matcher.any(path))
    for index, lang_rule in enumerate(document.language):
        matches[f"language[{index}]"] = sum(1 for _, lang in files if lang == lang_rule.language)
    levels: Counter[str] = Counter()
    preview: list[dict[str, Any]] = []
    for path, lang in files:
        decision = engine.resolve(path, tier, language=lang)
        verdict = "never_send" if decision.never_send else decision.level.value
        levels[verdict] += 1
        if len(preview) < MAX_PREVIEW_FILES:
            preview.append({"path": path, "level": verdict, "decided_by":
                            str(decision.winner.axis.value)})  # fmt: skip
    notes = []
    if not files:
        notes.append("no completed scan of the project: run a scan to preview rule matches")
    notes += [f"{key} matches no file" for key, count in matches.items() if count == 0 and files]
    return {
        "valid": True,
        "schema": "codekavach.policy.toml v1",
        "hash": digest,
        "errors": [],
        "notes": notes,
        "rules": document.rule_count(),
        "matches": matches,
        "files_resolved": len(files),
        "levels": dict(sorted(levels.items())),
        "provider_tier": str(tier.value),
        "preview": preview,
    }


@router.get("/policy/templates", dependencies=[ReadDep])
def templates() -> list[dict[str, Any]]:
    """The example policies shipped with CodeKavach, and whether the editor can load each."""
    from codekavach.privacy.policy.engine import PolicyError, load_document  # noqa: PLC0415

    found = [{"id": "server-default", "name": "Server default", "kind": "project",
              "editor": True, "toml": DEFAULT_POLICY, "source": "built in"}]  # fmt: skip
    if EXAMPLES.is_dir():
        for path in sorted(EXAMPLES.glob("*policy*.toml")):
            text = path.read_text(encoding="utf-8")
            try:
                load_document(text)
                editor = True
            except PolicyError:
                editor = False
            kind = "project" if path.name.startswith("codekavach.policy") else "organisation"
            found.append(
                {"id": path.stem, "name": path.stem.replace(".", " "), "kind": kind,
                 "editor": editor, "toml": text, "source": f"docs/examples/{path.name}"}
            )  # fmt: skip
    return found


@router.get("/privacy/budgets", dependencies=[LedgerDep])
def budgets(state: StateDep, session: SessionDep, scan_id: str | None = None) -> dict[str, Any]:
    """Configured exposure and request budgets against what a scan used."""
    scan = session.get(ScanRow, scan_id) if scan_id else _latest_scan(session, None)
    if scan_id and scan is None:
        raise not_found("scan")
    settings = server_settings(state)
    egress = settings.privacy.egress
    limits = settings.llm.budget
    privacy = (scan.privacy or {}) if scan is not None else {}
    disclosure = privacy.get("disclosure") or {}
    used_pct = disclosure.get("repository_fraction_pct")
    summary_requests = privacy.get("sent")
    rows = [
        {"id": "scan_disclosure", "label": "Repository share disclosed in one scan",
         "unit": "percent", "limit": egress.aggregation_budget_pct,
         "used": float(used_pct) if used_pct is not None else None,
         "source": "privacy.egress.aggregation_budget_pct"},
        {"id": "lifetime_disclosure", "label": "Repository share disclosed to one provider "
         "across the engagement", "unit": "percent",
         "limit": egress.lifetime_budget_pct or egress.aggregation_budget_pct, "used": None,
         "source": "privacy.egress.lifetime_budget_pct",
         "note": "the server keeps one state directory per scan, so it has no cross-scan "
         "exposure account; the CLI keeps one per project"},
        {"id": "payload_bytes", "label": "Largest request body", "unit": "bytes",
         "limit": egress.max_payload_bytes, "used": None,
         "source": "privacy.egress.max_payload_bytes"},
        {"id": "requests", "label": "LLM requests per scan", "unit": "requests",
         "limit": limits.max_requests, "used": summary_requests,
         "source": "llm.budget.max_requests"},
        {"id": "input_tokens", "label": "Input tokens per scan", "unit": "tokens",
         "limit": limits.max_total_input_tokens, "used": privacy.get("tokens_sent"),
         "source": "llm.budget.max_total_input_tokens"},
        {"id": "rate", "label": "Requests per minute", "unit": "requests/min",
         "limit": egress.rate_per_minute, "used": None, "source": "privacy.egress.rate_per_minute"},
    ]  # fmt: skip
    for row in rows:
        limit, used = row["limit"], row["used"]
        row["usage_pct"] = (
            round(100.0 * float(used) / float(limit), 1) if limit and used is not None else None
        )
    return {
        "scan_id": scan.id if scan is not None else None,
        "bytes_sent": privacy.get("bytes_sent"),
        "budgets": rows,
    }
