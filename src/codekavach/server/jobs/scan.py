"""The scan job: materialise the source, run the real pipeline, store the results.

Owning epic: E32.

``execute_scan`` runs in a worker thread. It copies or extracts the project's source into the
scan's workspace, loads the configuration the way ``codekavach scan`` does (privacy level,
provider and model as overrides), calls ``run_scan`` with a cancellation token and an event bus,
and translates the pipeline's token-only events into the dashboard's stream. Afterwards it stores
the findings, computes the privacy summary from the ledger and renders the reports. The server
never talks to a model itself: when a remote provider is chosen and ``send`` is set, the request
carries the operator's consent into the pipeline, whose egress guard decides what leaves (I1, I4).

While the LLM stage runs, each verdict that lands is streamed at once as a ``finding`` event with
``phase = "verdict"`` and the candidate's id (most severe candidates are reviewed first); the
rated findings follow as ordinary ``finding`` events when the scan ends, each naming its
``candidate_ids`` so a client can replace the live entry.
"""

import json
import shutil
import traceback
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from codekavach.core.log import get_logger
from codekavach.server.db.models import FindingRow, Project, ScanRow, utcnow
from codekavach.server.events import EventLog
from codekavach.server.insights import carry_triage
from codekavach.server.jobs.workspace import (
    SAMPLE_IGNORE,
    ArchiveLimits,
    IntakeError,
    assert_safe_clone_url,
    clone_git,
    copy_tree,
    extract_archive,
)
from codekavach.server.results import (
    SEVERITY_ORDER,
    ScanPaths,
    ScanResults,
    finding_columns,
    read_findings,
    scan_env,
    with_attestation,
)

if TYPE_CHECKING:
    from codekavach.core.pipeline.cancel import CancellationToken
    from codekavach.core.pipeline.events import Event
    from codekavach.server.state import ServerState

_log = get_logger("codekavach.server.jobs.scan")

LOCAL_PROVIDERS: Final = frozenset({"mock", "replay"})
STAGE_LABELS: Final = {
    "intake": "Preparing source",
    "ingest": "Ingesting files",
    "parse": "Parsing code",
    "analyse-engines": "Running external engines",
    "analyse-rules": "Matching security rules",
    "analyse-taint": "Tracing tainted data flows",
    "aggregate": "Aggregating candidates",
    "privacy-prepare": "Sanitising payloads (redaction, pseudonymisation, slicing)",
    "llm-review": "LLM review through the egress guard",
    "restore": "Restoring verdicts locally",
    "rate": "Rating risk and compliance",
    "privacy-check": "Verifying the egress ledger",
    "report": "Rendering reports",
}
TERMS_FILE: Final = Path("ground-truth") / "terms.txt"
OPTIONS_FILE: Final = "scan-options.json"  # per-scan request options (review_limit)
# Item failures that are expected on most code bases, worded for the scan log (reason, level).
ITEM_FAILURE_WORDS: Final = {
    "privacy_slice_failed": (
        "no code slice to send (secrets, dependencies or configuration findings)",
        "info",
    ),
    "privacy_pseudonymise_failed": (
        "pseudonymisation did not succeed, so the request was aborted (fail closed, I4)",
        "info",
    ),
}
# Pipeline warning codes, worded for the scan log; an unknown code is shown as it is.
WARNING_WORDS: Final = {
    "engine_network_not_isolated": (
        "External engines ran without network isolation (this host cannot create a network "
        "namespace); they read a read-only copy of the code and nothing is sent to a model"
    ),
    "engine_unknown_id": "The settings name an engine this version does not know; it was ignored",
    "files_skipped": "Some files could not be parsed and were left out of code analysis",
    "partial_input": "A stage ran on partial input because an earlier stage failed",
    "scan_deadline": "The scan reached its time limit and stopped",
    "tool_versions_invalid": "Engine versions could not be recorded",
    "diff_base_unresolved": "The diff base could not be resolved; the whole tree was scanned",
    "submodules_not_scanned": "Git submodules were not scanned",
    "no_files_found": "No files to scan were found",
}
VERDICT_WORDS: Final = {
    "vulnerable": "confirmed by the model",
    "not_vulnerable": "judged not exploitable by the model",
    "undecided": "undecided by the model",
}
POLICY_FILE: Final = "codekavach.policy.toml"
EAGER_FORMATS: Final = ("html", "json", "sarif")


class ScanCancelled(Exception):  # noqa: N818 - a control-flow signal, not an error
    """The scan was cancelled by a user."""


@dataclass
class ScanJob:
    """What a worker needs to run one scan."""

    scan_id: str
    state: "ServerState"
    token: "CancellationToken"


class _Progress:
    """Turns pipeline events into dashboard events and progress figures."""

    def __init__(self, job: ScanJob, log: EventLog) -> None:
        self.job = job
        self.log = log
        self.total = 10
        self.done = 0
        self.findings_hint = 0
        self.counts: dict[str, tuple[Any, Any]] = {}
        self.queued: dict[str, tuple[str, list[int]]] = {}
        self.limited: dict[str, int] = {}  # per stage: candidates left out by the review limit
        self.failed: dict[str, Counter[str]] = {}  # per stage: item failures by error code

    def _update(self, *, stage: str | None = None, progress: int | None = None) -> None:
        with self.job.state.db.transaction() as session:
            row = session.get(ScanRow, self.job.scan_id)
            if row is None:
                return
            if stage is not None:
                row.stage = stage
            if progress is not None:
                row.progress = max(row.progress, min(progress, 100))

    def percent(self) -> int:
        """Pipeline progress mapped to 5..90 percent."""
        return 5 + int(85 * self.done / max(self.total, 1))

    def _stage_ended(self, kind: str, stage: str, label: str, data: dict[str, Any]) -> None:
        """A stage finished, failed or was skipped: counts, log lines and progress."""
        self.done += 1
        if self.limited.get(stage):
            self.log.append(
                "log",
                {"level": "info", "message": f"{self.limited.pop(stage)} candidates kept "
                 "their deterministic evidence and were not sent to the model (review "
                 "limit); review any of them from its finding page"},
            )  # fmt: skip
        for code, number in sorted(self.failed.pop(stage, Counter()).items()):
            reason, level = ITEM_FAILURE_WORDS.get(code, (f"{stage} failed ({code})", "warning"))
            self.log.append(
                "log",
                {"level": level, "message": f"{number} candidate{'s' if number != 1 else ''} "
                 f"not sent to the model: {reason}; reported with deterministic evidence"},
            )  # fmt: skip
        status = {"stage.finished": "completed", "stage.failed": "failed"}.get(str(kind), "skipped")
        count, total = self.counts.get(stage, (None, None))
        self.log.append(
            "stage",
            {"name": stage, "status": status, "label": label, "count": count, "total": total},
        )
        if kind == "stage.failed":
            self.log.append(
                "log",
                {"level": "warning", "message": f"stage {stage} failed "
                 f"({data.get('error_code', 'error')}); the scan continued without it"},
            )  # fmt: skip
        elif kind == "stage.finished":
            took = data.get("duration_ms")
            self.log.append("log", {"level": "info", "message": f"{label} done in {took} ms"})
        percent = self.percent()
        self.log.append("progress", {"percent": percent, "message": f"{label} {status}"})
        self._update(progress=percent)

    def handle(self, event: "Event") -> None:
        """Map one pipeline event (only token fields are read)."""
        data = event.to_dict()
        kind = data.get("event")
        stage = str(data.get("stage", ""))
        label = STAGE_LABELS.get(stage, stage)
        if kind == "plan.resolved":
            stages = data.get("stages")
            self.total = len(stages) if isinstance(stages, list) else self.total
        elif kind == "stage.started":
            self.log.append(
                "stage",
                {"name": stage, "status": "started", "label": label, "count": 0, "total": None},
            )
            self._update(stage=stage)
        elif kind == "stage.progress":
            current, total = data.get("current"), data.get("total")
            unit = data.get("unit", "items")
            self.counts[stage] = (current, total)
            message = f"{label}: {current}/{total} {unit}" if total else f"{label}: {current}"
            self.log.append(
                "progress",
                {"percent": self.percent(), "message": message, "stage": stage,
                 "count": current, "total": total, "unit": unit},
            )  # fmt: skip
            if stage == "llm-review":
                # Live meter: candidates reviewed so far; bytes and checks follow at the end.
                self.log.append("egress", {"payloads": current, "total": total, "final": False})
        elif kind in {"stage.finished", "stage.failed", "stage.skipped"}:
            self._stage_ended(str(kind), stage, label, data)
        elif kind == "item.queued":
            cwe = data.get("cwe")
            self.queued[str(data.get("item_id"))] = (
                str(data.get("severity") or "medium"),
                [int(c) for c in cwe if isinstance(c, int)] if isinstance(cwe, list) else [],
            )
        elif kind == "item.reviewed":
            self._verdict(data)
        elif kind == "item.failed" and data.get("error_code") == "llm_review_limit":
            # One summary line when the stage ends, not one line per candidate.
            self.limited[stage] = self.limited.get(stage, 0) + 1
        elif kind == "item.failed":
            # Counted and logged once per error code when the stage ends (no raw item ids).
            self.failed.setdefault(stage, Counter())[str(data.get("error_code"))] += 1
        elif kind == "warning":
            code = str(data.get("code"))
            self.log.append("log", {"level": "warning", "message": WARNING_WORDS.get(code, code)})

    def _verdict(self, data: dict[str, Any]) -> None:
        """A model verdict landed: stream it as a live ``finding`` event (codes only)."""
        item = str(data.get("item_id"))
        severity, cwe = self.queued.get(item, ("medium", []))
        verdict = str(data.get("verdict"))
        label = ", ".join(f"CWE-{number}" for number in cwe) or "Candidate"
        current, total = data.get("current"), data.get("total")
        if current and total:
            # Two candidates of the same class otherwise read as one verdict, then its opposite.
            label = f"{current} of {total} · {label} ({severity})"
        words = VERDICT_WORDS.get(verdict, verdict)
        if verdict == "vulnerable" and _low_confidence(data.get("confidence")):
            # The findings table shows these as "Needs review"; the log must not say "confirmed".
            words = "vulnerable per the model, low confidence: needs review"
        self.log.append(
            "finding",
            {
                "id": item,
                "phase": "verdict",
                "severity": severity,
                "title": f"{label}: {words}",
                "verdict": verdict,
                "confidence": data.get("confidence"),
                "cwe": cwe,
                "reviewed": data.get("current"),
                "total": data.get("total"),
            },
        )


def _materialise(project: Project, paths: ScanPaths, job: ScanJob) -> None:
    config = job.state.config
    source = paths.source
    if source.exists():
        shutil.rmtree(source)
    if project.source_type == "sample":
        sample = config.sample_dir
        if sample is None or not sample.is_dir():
            raise IntakeError("sample_missing", "the KavachBank sample is not installed")
        copy_tree(sample, source, ignore=SAMPLE_IGNORE)
    elif project.source_type == "path":
        if not config.allow_local_paths:
            raise IntakeError("path_source_disabled", "local path sources are disabled")
        copy_tree(Path(project.source_path or ""), source)
    elif project.source_type == "upload":
        archive = config.uploads_dir / project.id / (project.upload_name or "")
        if not project.upload_name or not archive.is_file():
            raise IntakeError("upload_missing", "no archive has been uploaded for this project")
        limits = ArchiveLimits(
            max_entries=config.max_archive_entries,
            max_bytes=config.max_extracted_bytes,
            max_ratio=config.max_compression_ratio,
        )
        extract_archive(archive, source, limits)
    elif project.source_type == "git":
        url = assert_safe_clone_url(project.source_url or "", config.git_allowed_hosts)
        clone_git(url, source, ref=project.source_ref)
    else:
        raise IntakeError("source_type_unknown", f"unknown source type {project.source_type}")
    policy = config.data_dir / POLICY_FILE
    if policy.is_file():
        # The admin's policy always wins: a policy file shipped in the project (a PR author's or
        # a third party's) must not replace its never_send and per-path levels.
        (source / POLICY_FILE).unlink(missing_ok=True)
        shutil.copyfile(policy, source / POLICY_FILE)
    # An empty .git marks the project root, as the demo does, so the configuration loader does
    # not climb into the server's data directory.
    (source / ".git").mkdir(exist_ok=True)


def _overrides(row: ScanRow, base: dict[str, Any]) -> dict[str, Any]:
    llm: dict[str, Any] = dict(base.get("llm", {}))
    if row.provider in {"", "none"}:
        llm["enabled"] = False
    else:
        llm["enabled"] = True
        llm["default_provider"] = row.provider
        if row.model:
            llm["model"] = row.model
    options = _options(row)
    if llm["enabled"] and isinstance(options.get("review_limit"), int):
        llm["review_limit"] = options["review_limit"]
    overrides: dict[str, Any] = {"privacy": {"level": row.privacy_level}, "llm": llm}
    if row.rules:
        overrides["rules"] = {"paths": [str(item) for item in row.rules]}
    return overrides


def _options(row: ScanRow) -> dict[str, Any]:
    """The request options stored beside the scan (``scan-options.json``), or none."""
    if not row.workspace:
        return {}
    try:
        found = json.loads((Path(row.workspace) / OPTIONS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def _terms_file(project: Project, job: ScanJob, paths: ScanPaths) -> Path | None:
    if project.source_type == "sample" and job.state.config.sample_dir is not None:
        candidate = job.state.config.sample_dir / TERMS_FILE
        return candidate if candidate.is_file() else None
    candidate = paths.source / ".codekavach-terms.txt"
    return candidate if candidate.is_file() else None


def _finish(job: ScanJob, status: str, *, error: str | None = None) -> None:
    with job.state.db.transaction() as session:
        row = session.get(ScanRow, job.scan_id)
        if row is not None:
            row.status = status
            row.finished_at = utcnow()
            row.error = error
            if status == "completed":
                row.progress = 100
                row.stage = "done"
    job.state.hub.log(job.scan_id).append("done", {"status": status, "error": error})


def execute_scan(job: ScanJob) -> None:
    """Run the scan ``job.scan_id`` end to end; every failure ends in a ``failed`` status."""
    state = job.state
    log = state.hub.log(job.scan_id)
    cancelled_before_start = False
    try:
        with state.db.transaction() as session:
            row = session.get(ScanRow, job.scan_id)
            if row is None or row.status == "cancelled":
                return
            if cancelled_before_start := job.token.is_cancelled:
                # Cancelled after a worker took the job but before it started: the runner could
                # not cancel the future, so the job records the final status itself.
                row.status, row.finished_at = "cancelled", utcnow()
                return
            project = session.get(Project, row.project_id)
            if project is None:
                row.status, row.error = "failed", "project deleted"
                return
            row.status, row.started_at, row.stage, row.progress = "running", utcnow(), "intake", 1
            session.expunge(project)
            scan = {
                "level": row.privacy_level,
                "provider": row.provider,
                "model": row.model,
                "send": row.send,
                "overrides": _overrides(row, state.provider_overrides()),
                "workspace": row.workspace,
            }
    finally:
        # After the commit, so a client that sees the event also reads the final status.
        if cancelled_before_start:
            log.append("done", {"status": "cancelled", "error": None})
    paths = ScanPaths(Path(str(scan["workspace"])))
    progress = _Progress(job, log)
    try:
        log.append(
            "stage", {"name": "intake", "status": "started", "label": STAGE_LABELS["intake"]}
        )
        log.append("log", {"level": "info", "message": f"Source type: {project.source_type}"})
        _materialise(project, paths, job)
        log.append("stage", {"name": "intake", "status": "completed", "label": "Source ready"})
        if job.token.is_cancelled:
            raise ScanCancelled
        outcome, settings = _run_pipeline(job, scan, paths, progress)
        if outcome.result.status.value == "cancelled" or job.token.is_cancelled:
            raise ScanCancelled
        if outcome.result.status.value == "failed":
            failed = ", ".join(outcome.result.failed_stages()) or "unknown"
            raise RuntimeError(f"the pipeline failed in stage {failed}")
        _store(job, outcome, settings, project, paths, log)
        _finish(job, "completed")
        _log.info("server_scan_completed", scan_id=job.scan_id)
    except ScanCancelled:
        log.append("log", {"level": "warning", "message": "Scan cancelled by user"})
        _finish(job, "cancelled")
    except IntakeError as error:
        log.append("log", {"level": "error", "message": f"{error.code}: {error.message}"})
        _finish(job, "failed", error=f"{error.code}: {error.message}")
    except Exception as error:  # noqa: BLE001 - a failed job is reported, never a crashed worker
        _log.error(
            "server_scan_failed",
            scan_id=job.scan_id,
            error_type=type(error).__name__,
            where=traceback.extract_tb(error.__traceback__)[-1].name
            if error.__traceback__
            else None,
        )
        message = _safe_message(error)
        log.append("log", {"level": "error", "message": message})
        _finish(job, "failed", error=message)


def _safe_message(error: Exception) -> str:
    """A short error text that names the error and, for our own errors, their message."""
    name = type(error).__name__
    module = type(error).__module__
    if module.startswith("codekavach") or isinstance(error, RuntimeError | ValueError):
        text = str(error).splitlines()[0] if str(error) else ""
        return f"{name}: {text[:300]}" if text else name
    return name


def _zero_leak_words(zero_leak: dict[str, Any]) -> str:
    """The zero-leak result for the log: passed, failed, or not run (no listed terms)."""
    checked = int(zero_leak.get("checked") or 0)
    if not checked:
        return "zero-leak check not run (no listed project terms)"
    if zero_leak.get("passed"):
        return f"zero-leak passed ({checked} listed terms)"
    found = int(zero_leak.get("occurrences") or 0)
    return f"zero-leak FAILED ({found} occurrence{'s' if found != 1 else ''})"


def _low_confidence(confidence: object) -> bool:
    """True when the dashboard shows this verdict as "Needs review" (below 0.65, as in the UI)."""
    if isinstance(confidence, int | float):
        return float(confidence if confidence <= 1 else confidence / 100) < 0.65
    return str(confidence).lower() in {"low", "medium", "very low"}


def _run_pipeline(
    job: ScanJob, scan: dict[str, Any], paths: ScanPaths, progress: _Progress
) -> tuple[Any, Any]:
    from codekavach.config import load_settings  # noqa: PLC0415
    from codekavach.core.pipeline.context import ConsentDecision  # noqa: PLC0415
    from codekavach.core.pipeline.events import InMemoryEventBus  # noqa: PLC0415
    from codekavach.core.pipeline.runner import run_scan  # noqa: PLC0415
    from codekavach.core.pipeline.salt import ScanSalt  # noqa: PLC0415

    state = job.state
    overrides = scan["overrides"]
    paths.workspace.mkdir(parents=True, exist_ok=True)
    paths.settings_json.write_text(json.dumps(overrides), encoding="utf-8")
    env = scan_env(state.config.home_dir, state.passphrase_env)
    loaded = load_settings(target=paths.source, env=env, cli_overrides=overrides)
    llm = loaded.settings.llm
    consent = None
    remote = False
    if llm.enabled:
        provider = llm.providers.get(scan["provider"])
        if provider is None:
            raise ValueError(f"provider {scan['provider']} is not configured on this server")
        remote = bool(provider.is_remote)
        model = scan["model"] or llm.model or provider.model
        with state.db.transaction() as session:
            row = session.get(ScanRow, job.scan_id)
            if row is not None and model and not row.model:
                row.model = str(model)
        if remote and scan["send"]:
            consent = ConsentDecision(granted=True, source="flag")
    where = "remote" if remote else "local"
    progress.log.append(
        "log",
        {"level": "info", "message": f"Privacy level {scan['level']}; provider "
         f"{scan['provider']} ({where}); payloads {'sent' if scan['send'] else 'recorded only'}"},
    )  # fmt: skip
    bus = InMemoryEventBus()
    unsubscribe = bus.subscribe(progress.handle)
    try:
        outcome = run_scan(
            loaded,
            str(paths.source),
            salt=ScanSalt.generate(),
            bus=bus,
            cancellation=job.token,
            consent=consent,
            persist=False,
            no_send=not scan["send"],
        )
    finally:
        unsubscribe()
    return outcome, loaded.settings


def _store(  # noqa: PLR0917 - the parts of one result
    job: ScanJob,
    outcome: Any,
    settings: Any,
    project: Project,
    paths: ScanPaths,
    log: EventLog,
) -> None:
    from codekavach.server.reports import available_formats, render  # noqa: PLC0415

    state = job.state
    core_id = str(outcome.scan.id)
    paths.scan_json.write_text(outcome.scan.model_dump_json(), encoding="utf-8")
    findings = read_findings(paths, core_id)
    summary = outcome.scan.summary
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[str(finding.severity.value)] = counts.get(str(finding.severity.value), 0) + 1
    with state.db.transaction() as session:
        row = session.get(ScanRow, job.scan_id)
        if row is None:
            return
        row.core_scan_id = core_id
        row.state_dir = str(paths.state_dir)
        row.counts = counts
        row.languages = [str(getattr(item, "value", item)) for item in outcome.scan.languages]
        row.files = int(getattr(summary, "files_scanned", 0) or 0) if summary else 0
        row.lines = int(getattr(summary, "lines_scanned", 0) or 0) if summary else 0
        for finding in findings:
            columns = finding_columns(finding)
            session.merge(FindingRow(scan_id=job.scan_id, **columns))
        session.flush()
        carried = carry_triage(session, row)
    if carried:
        log.append(
            "log",
            {"level": "info",
             "message": f"{carried} unchanged finding{'s' if carried != 1 else ''} kept the "
             "reviewer's status from the previous scan"},
        )  # fmt: skip
    for finding in findings:
        log.append(
            "finding",
            {
                "id": str(finding.id),
                "severity": str(finding.severity.value),
                "title": finding.title,
                "candidate_ids": [str(item) for item in finding.provenance.candidate_ids],
            },
        )
    log.append(
        "stage", {"name": "privacy-check", "status": "started",
                  "label": STAGE_LABELS["privacy-check"]},
    )  # fmt: skip
    results = ScanResults(paths, core_id, settings)
    privacy = results.privacy_summary(
        level=str(outcome.scan.privacy_level.value)
        if outcome.scan.privacy_level
        else str(settings.privacy.level.value),
        provider=None if not settings.llm.enabled else settings.llm.default_provider,
        model=None,
        terms_file=_terms_file(project, job, paths),
    )
    privacy_json = with_attestation(
        privacy, paths, core_id, settings, _terms_file(project, job, paths)
    )
    with state.db.transaction() as session:
        row = session.get(ScanRow, job.scan_id)
        if row is not None:
            row.privacy = privacy_json
            if not row.model and privacy.model:
                row.model = privacy.model
            row.progress = 92
            row.stage = "report"
    log.append(
        "egress",
        {
            "payloads": privacy.payloads,
            "total": privacy.payloads,
            "sent": privacy.sent,
            "recorded": privacy.recorded,
            "blocked": privacy.blocked,
            "bytes": privacy.bytes_sent + privacy.bytes_recorded,
            "bytes_sent": privacy.bytes_sent,
            "secrets_checked": int(privacy.placeholders_by_type.get("secret", 0)),
            "terms_checked": int(privacy.zero_leak.get("checked", 0)),
            "terms_found": int(privacy.zero_leak.get("occurrences", 0)),
            "chain_ok": privacy.chain_ok,
            "final": True,
        },
    )
    log.append(
        "stage",
        {"name": "privacy-check", "status": "completed", "label": "Ledger verified",
         "count": privacy.chain_entries, "total": privacy.chain_entries},
    )  # fmt: skip
    log.append(
        "log",
        {"level": "info" if privacy.chain_ok else "error",
         "message": f"Ledger chain {'intact' if privacy.chain_ok else 'BROKEN'}; "
         f"{privacy.payloads} payloads, {privacy.blocked} blocked; "
         f"{_zero_leak_words(privacy_json.get('zero_leak') or privacy.zero_leak)}"},
    )  # fmt: skip
    log.append("stage", {"name": "report", "status": "started", "label": STAGE_LABELS["report"]})
    formats = [fmt for fmt in EAGER_FORMATS if fmt in available_formats(settings)]
    for fmt in formats:
        try:
            render(
                fmt,
                scan_json=paths.scan_json,
                state_dir=paths.state_dir,
                findings=findings,
                settings=job.state.report_settings(settings),
                out_dir=paths.reports,
                zero_leak=privacy.zero_leak,
                stem="report",
                project_name=project.name,
            )
        except Exception as error:  # noqa: BLE001 - a report can be rendered later on demand
            log.append("log", {"level": "warning", "message": f"{fmt} report not rendered: "
                               f"{type(error).__name__}"})  # fmt: skip
    log.append(
        "stage",
        {"name": "report", "status": "completed", "label": "Reports ready",
         "count": len(formats), "total": len(formats)},
    )  # fmt: skip
    log.append("progress", {"percent": 100, "message": f"{len(findings)} findings"})
