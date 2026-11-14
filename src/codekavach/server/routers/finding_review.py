"""Route ``POST /findings/{id}/review``: ask the model about one finding now (on-demand review).

Owning epic: E32.

A quick review (``review_limit``) leaves most candidates with their deterministic evidence only.
An auditor can then ask for the model's view of one chosen finding. The server never talks to a
model itself (I1): the request runs the real pipeline again over the scan's source with
``llm.review_only`` set to the finding's fingerprint, so exactly that one candidate goes through
privacy-prepare (slice, redaction, pseudonymisation), the egress guard, the ledger, the transport
and the local restore, with the combined ``review`` task (one request). The run uses the scan's
own state directory, so its ledger entries join the scan's hash chain under a new pipeline scan
id (recorded in the scan's ``reviews.json``, so the scan's ledger lists them), and the response
cache answers a repeated request without egress.

The finding keeps its id, status, assignee and history; its model review, confidence, impact and
remediation are replaced by the new run's, an ``llm_review`` entry is added to its history, and
the scan's reports are marked stale. Calling the endpoint is the operator's consent to send that
one finding's sanitised slice to the chosen provider, as ``send = true`` is for a scan.
"""

import json
import threading
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from codekavach.core.log import get_logger
from codekavach.server import audit
from codekavach.server.auth.dependencies import SessionDep, StateDep, client_of, require
from codekavach.server.db.models import FindingEvent, FindingRow, ScanRow, utcnow
from codekavach.server.errors import ApiError, not_found
from codekavach.server.rbac import Permission
from codekavach.server.results import (
    ScanPaths,
    finding_columns,
    policy_withheld,
    read_findings,
    scan_env,
)
from codekavach.server.routers.findings import get_finding
from codekavach.server.state import ServerState

_log = get_logger("codekavach.server.routers.finding_review")
router = APIRouter(tags=["findings"])
ReviewDep = Depends(require(Permission.finding_review))
KEPT_COLUMNS: Final = frozenset({"id", "status", "data"})
_busy_lock = threading.Lock()
_busy: set[str] = set()


class ReviewBody(BaseModel):
    """``POST /findings/{id}/review`` (every field optional)."""

    model_config = ConfigDict(extra="forbid")

    provider: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    model: str | None = Field(default=None, max_length=128)


def _overrides(paths: ScanPaths, provider: str, model: str | None, fingerprint: str) -> Any:
    stored: dict[str, Any] = {}
    if paths.settings_json.is_file():
        stored = json.loads(paths.settings_json.read_text(encoding="utf-8"))
    llm: dict[str, Any] = dict(stored.get("llm") or {})
    llm.update(
        {"enabled": True, "default_provider": provider, "review_only": [fingerprint],
         "review_limit": 0}
    )  # fmt: skip
    if model:
        llm["model"] = model
    return {**stored, "llm": llm}


def _run_review(state: ServerState, paths: ScanPaths, overrides: Any, provider: str) -> Any:
    """Run the pipeline for the one fingerprint in ``overrides``; the new findings."""
    from codekavach.config import load_settings  # noqa: PLC0415
    from codekavach.core.pipeline.context import ConsentDecision  # noqa: PLC0415
    from codekavach.core.pipeline.runner import run_scan  # noqa: PLC0415
    from codekavach.core.pipeline.salt import ScanSalt  # noqa: PLC0415

    env = scan_env(state.config.home_dir, state.passphrase_env)
    loaded = load_settings(target=paths.source, env=env, cli_overrides=overrides)
    chosen = loaded.settings.llm.providers.get(provider)
    if chosen is None:
        raise ApiError(400, "provider_unknown", f"provider {provider} is not configured")
    consent = ConsentDecision(granted=True, source="flag") if chosen.is_remote else None
    outcome = run_scan(
        loaded,
        str(paths.source),
        salt=ScanSalt.generate(),
        consent=consent,
        persist=False,
        no_send=False,
    )
    # The review's ledger entries belong to this scan's egress: list them with the scan's own.
    paths.add_review_scan_id(str(outcome.scan.id))
    if outcome.result.status.value == "failed":
        failed = ", ".join(outcome.result.failed_stages()) or "unknown"
        raise ApiError(502, "review_failed", f"the review run failed in stage {failed}")
    failures = sorted(
        {f.error_code for f in outcome.result.item_failures if f.stage == "llm-review"}
        | {f.error_code for f in outcome.result.item_failures if f.stage == "privacy-prepare"}
    )
    if not failures and policy_withheld(paths, str(outcome.scan.id)):
        failures = ["policy_withheld"]
    return read_findings(paths, str(outcome.scan.id)), failures


@router.post("/findings/{finding_id}/review")
def review_finding(
    finding_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    body: ReviewBody | None = Body(default=None),
    principal: Any = ReviewDep,
) -> dict[str, Any]:
    """Review one finding with the model now and return the updated finding."""
    row = session.get(FindingRow, finding_id)
    if row is None:
        raise not_found("finding")
    scan = session.get(ScanRow, row.scan_id)
    if scan is None or scan.status != "completed" or not scan.workspace:
        raise ApiError(409, "scan_not_completed", "the finding's scan has not completed")
    body = body or ReviewBody()
    defaults = state.get_settings()
    provider = (
        body.provider
        or (scan.provider if scan.provider not in {"", "none"} else None)
        or str(defaults.get("default_provider") or "mock")
    )
    model = body.model or (scan.model if provider == scan.provider else None)
    paths = ScanPaths(Path(scan.workspace))
    with _busy_lock:
        if scan.id in _busy:
            raise ApiError(409, "review_in_progress", "a review of this scan is already running")
        _busy.add(scan.id)
    try:
        findings, failures = _run_review(
            state, paths, _overrides(paths, provider, model, row.fingerprint), provider
        )
    finally:
        with _busy_lock:
            _busy.discard(scan.id)
    found = next((f for f in findings if f.fingerprint == row.fingerprint), None)
    if found is None or not found.provenance.llm_reviews:
        reason = ", ".join(failures) or "no_verdict"
        if failures == ["policy_withheld"]:
            why = (
                "the scan is at L4, which this build does not deliver, so it fails closed"
                if str(scan.privacy_level) == "L4"
                else "the privacy policy keeps this finding's file local (a never-send path)"
            )
            raise ApiError(
                422, "nothing_to_send", f"nothing was sent: {why}; the engine evidence stands"
            )
        if failures and all(code.startswith("privacy_") for code in failures):
            # The privacy layer withheld the request (I4): the model was never asked, so this is
            # not a gateway failure and must not read like one.
            raise ApiError(
                422,
                "nothing_to_send",
                f"nothing was sent: no sanitised code slice could be prepared for this finding at "
                f"{scan.privacy_level} (a language CodeKavach cannot slice yet, or a secret, "
                f"dependency or configuration finding), so the request was withheld ({reason}); "
                "the engine evidence stands",
            )
        raise ApiError(502, "review_failed", f"the model gave no usable verdict ({reason})")
    previous: dict[str, Any] = dict(row.data or {})
    data = found.model_dump(mode="json")
    for key in ("id", "status", "status_history", "created_at", "first_seen_scan_id"):
        if key in previous:
            data[key] = previous[key]
    columns = finding_columns(found)
    for name, value in columns.items():
        if name not in KEPT_COLUMNS:
            setattr(row, name, value)
    row.data = data
    row.updated_at = utcnow()
    review = found.provenance.llm_reviews[-1]
    verdict = {True: "vulnerable", False: "not vulnerable", None: "undecided"}[review.is_vulnerable]
    session.add(
        FindingEvent(
            finding_id=finding_id,
            actor=principal.username,
            action="llm_review",
            from_status=row.status,
            to_status=row.status,
            comment=f"Model review ({review.provider}, {review.model}): {verdict}, "
            f"{review.confidence.value} confidence",
        )
    )
    scan.triage_updated_at = utcnow()
    audit.record(state.db, actor=principal.username, action="finding.review",
                 resource=finding_id, client=client_of(request),
                 detail={"provider": provider, "verdict": verdict})  # fmt: skip
    session.flush()
    _log.info("server_finding_reviewed", provider=provider, verdict=verdict)
    return get_finding(finding_id, state, session, principal)
