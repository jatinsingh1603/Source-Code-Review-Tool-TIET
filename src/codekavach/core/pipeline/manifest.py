"""The scan manifest: tool versions, configuration hash, stages and timings of one scan (E04-24).

Owning epic: E04.

Every scan, failed and cancelled ones included, leaves ``<state>/scans/<scan_id>/manifest.json``
next to the masked configuration snapshot (E03-39). The manifest is provenance metadata that is
designed to travel (report appendix, experiment archives), so it holds identifiers, versions,
codes, counts and durations only: no paths, no host or user names, no environment variables, no
exception messages, no settings values, and only a one-way fingerprint of the salt (I3). The scan
target is deliberately absent, because a path or URL can contain a user or client name.
"""

import platform
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from codekavach.core.pipeline.result import StageRun

if TYPE_CHECKING:
    from codekavach.core.pipeline.plan import RunPlan

TOOL_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
TOOL_VERSION: Final = re.compile(r"^[A-Za-z0-9 ._+:-]{1,64}$")
MAX_TOOL_VERSIONS: Final = 20

ConsentSource = Literal["none", "user-file", "flag", "env"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class StageManifestEntry(_Frozen):
    """One stage of the scan, as it ran."""

    name: str
    category: str | None = None
    version: str = "0"
    origin: str | None = None
    outcome: str
    duration_ms: int = 0
    error_code: str | None = None
    error_type: str | None = None
    skip_reason: str | None = None
    blocked_by: str | None = None
    items_in: int | None = None
    items_out: int | None = None
    stage_key: str | None = None
    tool_versions: dict[str, str] = Field(default_factory=dict)


class PluginManifestEntry(_Frozen):
    """One discovered plugin entry point (from ``PluginRegistry.rows()``)."""

    group: str
    name: str
    dist: str
    version: str
    status: str
    error_type: str | None = None


class ManifestCounters(_Frozen):
    """Counts that explain the run; zero when a feature has not produced any."""

    cache_hits: int = 0
    cache_misses: int = 0
    memo_hits: int = 0
    memo_misses: int = 0
    item_failures: int = 0
    abandoned_threads: int = 0
    egress_locked: bool = False


class ExcludedEntry(_Frozen):
    """A stage left out of the plan, with the reason code."""

    name: str
    reason_code: str


class ScanManifest(_Frozen):
    """Provenance of one scan: safe to attach to a report or an experiment archive."""

    schema_version: Literal[1] = 1
    scan_id: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int = 0
    codekavach_version: str
    python_version: str
    python_implementation: str
    os: str
    machine: str
    settings_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile: str | None = None
    config_snapshot: Literal["config-snapshot.json"] = "config-snapshot.json"
    salt_fingerprint: str = Field(pattern=r"^[0-9a-f]{16}$")
    consent_source: ConsentSource = "none"
    order: list[str] = Field(default_factory=list)
    waves: list[list[str]] = Field(default_factory=list)
    excluded: list[ExcludedEntry] = Field(default_factory=list)
    stages: list[StageManifestEntry] = Field(default_factory=list)
    plugins: list[PluginManifestEntry] = Field(default_factory=list)
    counters: ManifestCounters = Field(default_factory=ManifestCounters)

    def to_json(self) -> str:
        """Indented JSON with a final newline."""
        return self.model_dump_json(indent=2) + "\n"


def environment() -> dict[str, str]:
    """Interpreter and platform facts; never the host name, the user name or paths."""
    from codekavach.core.pipeline.runner import codekavach_version  # noqa: PLC0415 - cycle

    return {
        "codekavach_version": codekavach_version(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "os": sys.platform,
        "machine": platform.machine(),
    }


def collect_tool_versions(stage: object) -> tuple[dict[str, str], bool]:
    """The stage's ``tool_versions()`` if valid, and whether a returned value was rejected.

    A raising or missing method gives an empty mapping and no rejection; a value that is not a
    mapping of at most 20 well-formed names and versions is discarded as a whole.
    """
    method = getattr(stage, "tool_versions", None)
    if not callable(method):
        return {}, False
    try:
        value = method()
    except Exception:  # noqa: BLE001 - a broken probe must not affect the scan
        return {}, False
    if not isinstance(value, Mapping) or len(value) > MAX_TOOL_VERSIONS:
        return {}, True
    checked: dict[str, str] = {}
    for name, version in value.items():
        if not (
            isinstance(name, str)
            and isinstance(version, str)
            and TOOL_NAME.match(name)
            and TOOL_VERSION.match(version)
        ):
            return {}, True
        checked[name] = version
    return checked, False


def build_manifest(
    *,
    scan_id: str,
    plan: "RunPlan",
    stage_runs: Sequence[StageRun],
    registry_rows: Sequence[Any],
    settings_fp: str,
    salt_fp: str,
    started_at: datetime,
    finished_at: datetime | None,
    status: str,
    counters: ManifestCounters,
    profile: str | None = None,
    tool_versions: Mapping[str, Mapping[str, str]] | None = None,
    consent_source: ConsentSource = "none",
    env: Callable[[], dict[str, str]] = environment,
) -> ScanManifest:
    """The manifest of a scan, or of the part of it that has run so far."""
    versions = tool_versions or {}
    stages = []
    for run in stage_runs:
        info = plan.infos.get(run.stage)
        stages.append(
            StageManifestEntry(
                name=run.stage,
                category=info.category.value if info and info.category else None,
                version=info.version if info else "0",
                origin=info.origin if info else None,
                outcome=run.outcome.value,
                duration_ms=run.duration_ms,
                error_code=run.error_code,
                error_type=run.error_type,
                skip_reason=run.skip_reason,
                blocked_by=run.blocked_by,
                items_in=run.items_in,
                items_out=run.items_out,
                stage_key=run.stage_key,
                tool_versions=dict(versions.get(run.stage, {})),
            )
        )
    end = finished_at or started_at
    facts = env()
    return ScanManifest(
        scan_id=scan_id,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=max(0, int((end - started_at).total_seconds() * 1000)),
        codekavach_version=facts["codekavach_version"],
        python_version=facts["python_version"],
        python_implementation=facts["python_implementation"],
        os=facts["os"],
        machine=facts["machine"],
        settings_fingerprint=settings_fp,
        profile=profile,
        salt_fingerprint=salt_fp,
        consent_source=consent_source,
        order=list(plan.order),
        waves=[list(wave) for wave in plan.waves],
        excluded=[
            ExcludedEntry(name=item.name, reason_code=item.reason_code) for item in plan.excluded
        ],
        stages=stages,
        plugins=[
            PluginManifestEntry(
                group=row.group,
                name=row.name,
                dist=row.dist,
                version=row.version,
                status=row.status,
                error_type=row.error_type,
            )
            for row in registry_rows
        ],
        counters=counters,
    )


def render_manifest_summary(manifest: ScanManifest) -> list[str]:
    """Plain text lines for the CLI: versions, the stage table and the counters."""
    lines = [
        f"scan {manifest.scan_id}: {manifest.status} in {manifest.duration_ms} ms",
        f"codekavach {manifest.codekavach_version}, python {manifest.python_version} "
        f"({manifest.python_implementation}), {manifest.os} {manifest.machine}",
    ]
    width = max((len(stage.name) for stage in manifest.stages), default=5)
    for stage in manifest.stages:
        detail = stage.error_code or stage.skip_reason or ""
        row = f"  {stage.name:<{width}}  {stage.outcome:<10} {stage.duration_ms:>8} ms  {detail}"
        lines.append(row.rstrip())
    counters = manifest.counters
    lines.append(
        f"cache: {counters.cache_hits} hits, {counters.cache_misses} misses; "
        f"item failures: {counters.item_failures}; egress locked: "
        f"{'yes' if counters.egress_locked else 'no'}"
    )
    return lines
