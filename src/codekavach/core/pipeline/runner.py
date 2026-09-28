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
"""

import hashlib
import importlib.metadata
import json
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from codekavach.config import LoadedConfig, Settings
from codekavach.config.introspect import flatten_leaves, has_marker
from codekavach.config.paths import resolve_state_dir
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
from codekavach.core.pipeline.events import EventBus, NullEventBus
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import PlanError, build_plan
from codekavach.core.pipeline.result import PipelineResult
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.registry import PluginRegistry, registry_from_environment
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.base import ArtefactError, ArtefactStore
from codekavach.core.store.layout import StateLayout

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
    """SHA-256 of the canonical effective settings without volatile keys.

    Interim implementation until the settings fingerprint of E03-39 is available.
    """
    flat = flatten_leaves(settings.model_dump(mode="json"))
    stable = {
        key: value for key, value in flat.items() if not has_marker(Settings, key, "volatile")
    }
    text = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
) -> ScanOutcome:
    """Run one scan of ``target`` with the loaded configuration.

    ``use_cache`` (default ``scan.cache``) lets unchanged cacheable stages be served from the
    stage cache (E04-21); ``refresh`` names stages or groups that must run anyway. Records are
    written even with ``use_cache=False``. The cache is used only with the default on-disk store,
    whose blobs the records point at.

    Raises:
        ValueError: ``target`` carries credentials (nothing is written).
        PlanError, GraphError: the plan cannot be built, or a ``refresh`` selector matches no
            stage (``unknown_stage_selector``); nothing has run.
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
    project = project or Project.model_validate(
        {
            "id": new_project_id(),
            "name": settings.project.name or loaded.project_root.name or "project",
            "created_at": clock(),
        }
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
    result = orchestrator.run(plan, ctx)
    scan = assemble_scan(
        result=result, store=artefacts, settings=settings, project=project, clock=clock
    )
    artefacts.put(keys.SCAN_RECORD, scan)
    return ScanOutcome(result=result, scan=scan, state_dir=layout.root)
