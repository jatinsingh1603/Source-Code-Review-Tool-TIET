"""``run_scan``: the single entry point every caller uses to execute a scan.

Owning epic: E04.

The runner prepares the state directory and the on-disk store, seeds the scan target, builds the
budget and the plan, runs the orchestrator and assembles the E02 ``Scan`` record, which it stores
under ``scan.record`` so that another process (``codekavach report``) can find it.

Privacy-relevant wiring lives here only: the salt is supplied by the caller and placed on the
context and nowhere else (the runner never generates, derives or stores one; I3, I5); the state
directory is prepared through the safe layout helper; a target URL carrying credentials is refused
before anything is written; ``Scan`` records carry no exception text. The runner opens no network
connection (I1). Consent for remote egress is passed through unchanged; ``None`` means none.

With ``persist=True`` the scan is also recorded in the local database (E04-27): a ``running`` row
before the orchestrator starts, the final scan, its stage runs and its findings afterwards. The
database modules are imported only then, and no transaction stays open while the scan runs.
"""

import contextlib
import dataclasses
import importlib.metadata
import json
import sys
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from codekavach.config import LoadedConfig, Settings
from codekavach.config.paths import resolve_state_dir
from codekavach.config.snapshot import build_snapshot, settings_fingerprint
from codekavach.core.log import get_logger
from codekavach.core.models import Language, ScanStatus
from codekavach.core.models.finding import Finding
from codekavach.core.models.ids import new_project_id, new_scan_id
from codekavach.core.models.scan import Project, Scan
from codekavach.core.models.summary import EgressTotals, ScanSummary
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.budget import (
    LLM_COST_MICRO_USD,
    LLM_INPUT_TOKENS,
    LLM_OUTPUT_TOKENS,
    LLM_REQUESTS,
    Budget,
)
from codekavach.core.pipeline.cache import StageCache
from codekavach.core.pipeline.cancel import CancellationToken
from codekavach.core.pipeline.context import ConsentDecision, RunContext
from codekavach.core.pipeline.errors import PersistenceError
from codekavach.core.pipeline.events import EventBus, NullEventBus
from codekavach.core.pipeline.manifest import (
    ConsentSource,
    ManifestCounters,
    ScanManifest,
    build_manifest,
)
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import PlanError, RunPlan, build_plan
from codekavach.core.pipeline.result import PipelineResult, StageRun
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.registry import PluginRegistry, registry_from_environment
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.base import ArtefactError, ArtefactStore
from codekavach.core.store.layout import StateLayout, atomic_write_bytes

if TYPE_CHECKING:
    from codekavach.core.store.repositories import ScanRecorder

CREDENTIALS_IN_TARGET = (
    "target must not contain credentials; configure them through a secret reference"
)
_FINISHED = frozenset({ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS})
_log = get_logger("codekavach.pipeline.runner")


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """The orchestrator result, the ``Scan`` record and where the records live."""

    result: PipelineResult
    scan: Scan
    state_dir: Path
    manifest_path: Path | None = None


def check_target(target: str) -> str:
    """Refuse a target URL with user information (``user:password@``)."""
    try:
        parts = urlsplit(target)
        has_credentials = bool(parts.username or parts.password)
    except ValueError:
        has_credentials = "@" in target and "://" in target
    if has_credentials:
        raise ValueError(CREDENTIALS_IN_TARGET)
    return target


def build_budget(settings: Settings) -> Budget:
    """Limits from ``llm.budget`` (money in micro-USD) and the wall clock from ``scan``."""
    budget = settings.llm.budget
    limits: dict[str, int] = {}
    if budget.max_requests is not None:
        limits[LLM_REQUESTS] = budget.max_requests
    if budget.max_total_input_tokens is not None:
        limits[LLM_INPUT_TOKENS] = budget.max_total_input_tokens
    if budget.max_total_output_tokens is not None:
        limits[LLM_OUTPUT_TOKENS] = budget.max_total_output_tokens
    if budget.max_cost_usd is not None:
        limits[LLM_COST_MICRO_USD] = round(budget.max_cost_usd * 1_000_000)
    return Budget(limits, wall_seconds=settings.scan.timeout_seconds)


def config_hash(settings: Settings) -> str:
    """The settings fingerprint of E03-39 (``ck-fp-v1``): volatile settings do not count."""
    return settings_fingerprint(settings)


def codekavach_version() -> str:
    """The installed version of CodeKavach."""
    try:
        return importlib.metadata.version("codekavach")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0+unknown"


def _prepare_state(loaded: LoadedConfig) -> StateLayout:
    root = resolve_state_dir(loaded.project_root, loaded.settings.project.state_dir)
    return StateLayout(root).ensure()


def _count(store: ArtefactStore, key: str) -> int:
    if not store.has(key):
        return 0
    try:
        value = store.get_json(key)
    except ArtefactError:
        return 0
    return len(value) if isinstance(value, list) else 0


def _languages(store: ArtefactStore) -> tuple[Language, ...]:
    if not store.has(keys.LANGUAGES):
        return ()
    try:
        value = store.get_json(keys.LANGUAGES)
    except ArtefactError:
        return ()
    items = value if isinstance(value, list) else []
    valid = {member.value for member in Language}
    return tuple(Language(item) for item in items if isinstance(item, str) and item in valid)


def minimal_summary(store: ArtefactStore, duration_seconds: float) -> ScanSummary:
    """A summary from the ``findings`` artefact (or none) with zero egress totals."""
    findings: list[Finding] = []
    if store.has(keys.FINDINGS):
        try:
            findings = store.get_list(keys.FINDINGS, Finding)
        except ArtefactError:
            _log.warning("findings_unreadable", key=keys.FINDINGS)
    return ScanSummary.from_findings(
        findings,
        files_scanned=_count(store, keys.FILES),
        lines_scanned=0,
        candidates_total=_count(store, keys.CANDIDATES),
        candidates_reviewed_by_llm=0,
        egress=EgressTotals.empty(),
        duration_seconds=max(0.0, duration_seconds),
    )


def _summary(store: ArtefactStore, duration_seconds: float) -> ScanSummary:
    if store.has(keys.SCAN_SUMMARY):
        try:
            return store.get(keys.SCAN_SUMMARY, ScanSummary)
        except ArtefactError:
            _log.warning("summary_unreadable", key=keys.SCAN_SUMMARY)
    return minimal_summary(store, duration_seconds)


def assemble_scan(
    *,
    result: PipelineResult,
    store: ArtefactStore,
    settings: Settings,
    project: Project,
    clock: Callable[[], datetime],
) -> Scan:
    """The E02 ``Scan`` for a finished orchestrator run."""
    started_at = result.started_at or clock()
    finished_at = result.finished_at or clock()
    duration = (finished_at - started_at).total_seconds()
    summary = _summary(store, duration) if result.status in _FINISHED else None
    return Scan.model_validate(
        {
            "id": result.scan_id,
            "project_id": project.id,
            "status": result.status,
            "started_at": started_at,
            "finished_at": finished_at,
            "codekavach_version": codekavach_version(),
            "config_hash": config_hash(settings),
            "privacy_level": settings.privacy.level,
            "languages": _languages(store),
            "stages": tuple(run.to_stage_result() for run in result.stage_runs),
            "summary": summary,
        }
    )


def run_scan(
    loaded: LoadedConfig,
    target: str,
    *,
    salt: ScanSalt,
    registry: PluginRegistry | None = None,
    bus: EventBus | None = None,
    cancellation: CancellationToken | None = None,
    skip: Collection[str] = (),
    until: str | None = None,
    project: Project | None = None,
    scan_id: str | None = None,
    store: ArtefactStore | None = None,
    clock: Callable[[], datetime] = utc_now,
    consent: ConsentDecision | None = None,
    use_cache: bool | None = None,
    refresh: Collection[str] = (),
    persist: bool = True,
) -> ScanOutcome:
    """Run one scan of ``target`` with the loaded configuration.

    ``use_cache`` (default ``scan.cache``) lets unchanged cacheable stages be served from the
    stage cache (E04-21); ``refresh`` names stages or groups that must run anyway. Records are
    written even with ``use_cache=False``. The cache is used only with the default on-disk store,
    whose blobs the records point at.

    ``persist`` records the scan in the local database, under the project found by its root
    directory; ``persist=False`` leaves no database file behind.

    Raises:
        ValueError: ``target`` carries credentials (nothing is written).
        PlanError, GraphError: the plan cannot be built, or a ``refresh`` selector matches no
            stage (``unknown_stage_selector``); nothing has run.
        PersistenceError: the database could not record the scan; when raised after the
            orchestrator finished, the artefacts and the manifest are already on disk.
    """
    check_target(target)
    settings = loaded.settings
    plan = build_plan(registry or registry_from_environment(), settings, skip=skip, until=until)
    for selector in sorted(refresh):
        if not any(keys.matches_stage_selector(info, selector) for info in plan.infos.values()):
            raise PlanError("unknown_stage_selector", repr(selector))
    layout = _prepare_state(loaded)
    scan_id = scan_id or new_scan_id()
    artefacts = store if store is not None else OnDiskArtefactStore(layout, scan_id)
    artefacts.put(keys.TARGET, {"target": target})
    recorder = _recorder(layout) if persist else None
    root = str(loaded.project_root)
    project = (
        project
        or (recorder.project_by_root(root) if recorder is not None else None)
        or Project.model_validate(
            {
                "id": new_project_id(),
                "name": settings.project.name or loaded.project_root.name or "project",
                "root": root,
                "created_at": clock(),
            }
        )
    )
    ctx = RunContext(
        scan_id=scan_id,
        config=settings,
        artefacts=artefacts,
        events=bus if bus is not None else NullEventBus(),
        cancellation=cancellation or CancellationToken(),
        budget=build_budget(settings),
        scan_salt=salt,
        project_root=loaded.project_root,
        state_dir=layout.root,
        consent=consent,
    )
    cache = StageCache(layout) if store is None else None
    orchestrator = Orchestrator(
        clock=clock,
        cache=cache,
        use_cache=settings.scan.cache if use_cache is None else use_cache,
        refresh=refresh,
        version=codekavach_version(),
    )
    started_at = clock()
    write_bytes = atomic_write_bytes
    snapshot = build_snapshot(loaded, codekavach_version=codekavach_version(), now=started_at)
    snapshot_text = json.dumps(snapshot.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    write_bytes(layout.snapshot_path(scan_id), snapshot_text.encode("utf-8"))
    manifest_inputs = _ManifestInputs(
        scan_id=scan_id,
        plan=plan,
        registry_rows=_registry_rows(registry),
        settings_fp=settings_fingerprint(settings),
        salt_fp=salt.fingerprint(),
        profile=loaded.profile,
        consent_source=consent.source if consent is not None else "none",
        started_at=started_at,
    )
    ctx = dataclasses.replace(
        ctx,
        manifest_provider=lambda: manifest_inputs.build(
            ctx.run_log.snapshot(), status="running", finished_at=None, result=None,
            tool_versions=orchestrator.tool_versions(),
        ),
    )  # fmt: skip
    if recorder is not None:
        running = Scan.model_validate(
            {
                "id": scan_id,
                "project_id": project.id,
                "status": ScanStatus.RUNNING,
                "started_at": started_at,
                "codekavach_version": codekavach_version(),
                "config_hash": config_hash(settings),
                "privacy_level": settings.privacy.level,
            }
        )
        stale_before = started_at - timedelta(seconds=settings.scan.timeout_seconds)
        recorder.start(project, running, stale_before=stale_before, now=started_at)
    result: PipelineResult | None = None
    manifest_path = layout.manifest_path(scan_id)
    try:
        result = orchestrator.run(plan, ctx)
    finally:
        failure = sys.exc_info()[1]
        status = result.status.value if result is not None else _status_after(failure, ctx)
        manifest = manifest_inputs.build(
            result.stage_runs if result is not None else ctx.run_log.snapshot(),
            status=status,
            finished_at=clock(),
            result=result,
            tool_versions=orchestrator.tool_versions(),
        )
        try:
            write_bytes(manifest_path, manifest.to_json().encode("utf-8"))
            artefacts.put(keys.MANIFEST, manifest)
        except (OSError, ArtefactError):
            _log.warning("manifest_write_failed", scan_id=scan_id)
        if result is None and recorder is not None:
            with contextlib.suppress(PersistenceError):  # logged; the original error propagates
                recorder.abort(scan_id, ScanStatus(status), clock())
    scan = assemble_scan(
        result=result, store=artefacts, settings=settings, project=project, clock=clock
    )
    artefacts.put(keys.SCAN_RECORD, scan)
    if recorder is not None:
        recorder.finish(scan, result.stage_runs, _findings(artefacts))
    return ScanOutcome(result=result, scan=scan, state_dir=layout.root, manifest_path=manifest_path)


def _recorder(layout: StateLayout) -> "ScanRecorder":
    from codekavach.core.store.repositories import ScanRecorder  # noqa: PLC0415 - lazy SQLAlchemy

    return ScanRecorder(layout)


def _findings(store: ArtefactStore) -> list[Finding] | None:
    """The ``findings`` artefact, or ``None`` when no stage produced a readable one."""
    if not store.has(keys.FINDINGS):
        return None
    try:
        return store.get_list(keys.FINDINGS, Finding)
    except ArtefactError:
        _log.warning("findings_unreadable", key=keys.FINDINGS)
        return None


def _registry_rows(registry: PluginRegistry | None) -> list[Any]:
    if registry is None:
        return []
    try:
        return list(registry.rows())
    except Exception:  # noqa: BLE001 - a plugin listing must not break the manifest
        return []


def _status_after(failure: BaseException | None, ctx: RunContext) -> str:
    """The status of a run whose orchestrator raised instead of returning a result."""
    if isinstance(failure, KeyboardInterrupt) or ctx.cancellation.is_cancelled:
        return ScanStatus.CANCELLED.value
    return ScanStatus.FAILED.value


@dataclass(frozen=True, slots=True)
class _ManifestInputs:
    """Everything the manifest needs that is fixed before the orchestrator runs."""

    scan_id: str
    plan: RunPlan
    registry_rows: list[Any]
    settings_fp: str
    salt_fp: str
    profile: str | None
    consent_source: ConsentSource
    started_at: datetime

    def build(
        self,
        stage_runs: Sequence[StageRun],
        *,
        status: str,
        finished_at: datetime | None,
        result: PipelineResult | None,
        tool_versions: Mapping[str, Mapping[str, str]],
    ) -> ScanManifest:
        counters = ManifestCounters(
            cache_hits=result.cache_hits if result else 0,
            cache_misses=result.cache_misses if result else 0,
            item_failures=len(result.item_failures) if result else 0,
            abandoned_threads=result.abandoned_threads if result else 0,
            egress_locked=result.egress_locked if result else False,
        )
        return build_manifest(
            scan_id=self.scan_id,
            plan=self.plan,
            stage_runs=stage_runs,
            registry_rows=self.registry_rows,
            settings_fp=self.settings_fp,
            salt_fp=self.salt_fp,
            started_at=self.started_at,
            finished_at=finished_at,
            status=status,
            counters=counters,
            profile=self.profile,
            tool_versions=tool_versions,
            consent_source=self.consent_source,
        )
