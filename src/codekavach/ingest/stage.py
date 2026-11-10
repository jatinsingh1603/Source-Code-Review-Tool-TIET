"""``IngestStage``: the first pipeline stage, from scan target to ``files`` and ``languages``.

Owning epic: E06.

The stage resolves the target through :func:`~codekavach.ingest.sources.selection.select_source`,
walks it with :func:`~codekavach.ingest.discovery.discover` and publishes two artefacts: ``files``
(a ``list[SourceFile]``, so ``len()`` of the stored JSON is the file count and the cache digest has
file granularity) and ``languages`` (distinct, sorted by enum value, so a change in file order
does not change it). ``UNKNOWN`` is not listed in ``languages``: it names no grammar to load.

Category ``INGEST`` fails with ``ABORT_SCAN``: without files there is nothing to scan, and
carrying on would produce an empty, reassuring report. The orchestrator publishes
``StageStarted`` and ``StageFinished``; this stage adds ``StageProgress`` events, which carry
counts only (never a path, because the event bus feeds terminals, logs and the server stream).

**Sources that own their root** (git, archive, standard input) are materialised into
``<state>/work/<scan-id>`` (mode ``0700``), which is registered on ``ctx.scan_root`` so that every
later stage reads files from it (``ctx.source_root``) and the runner removes it when the scan ends
(unless ``--keep-state``). **Narrowing** (``--subproject``, ``--diff-since``) is applied after
``discover``; a third artefact, ``ingest.coverage``, records what was left out and why. A base that
cannot be resolved scans everything and warns (``diff_base_unresolved``); a requested sub-project
that matches nothing fails the stage, because an empty scan reads as a clean one.
"""

import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from codekavach.core.models import Language
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.layout import StateLayout
from codekavach.ingest.diff import resolve_diff
from codekavach.ingest.discovery import DiscoveryReport, discover
from codekavach.ingest.gitmeta import unfetched_submodules
from codekavach.ingest.limits import IngestLimits
from codekavach.ingest.models import SourceFile
from codekavach.ingest.options import IngestOptions
from codekavach.ingest.sources.base import Source
from codekavach.ingest.sources.selection import select_source
from codekavach.ingest.sources.workdir import remove_tree
from codekavach.ingest.subprojects import detect_subprojects, select_subprojects

PROGRESS_MIN_SECONDS: Final = 0.25
PROGRESS_MIN_FILES: Final = 500
SOURCE_DIR: Final = "source"


class ProgressThrottle:
    """Allows an event when both the time and the file-count spacing have passed."""

    def __init__(
        self,
        *,
        min_seconds: float = PROGRESS_MIN_SECONDS,
        min_items: int = PROGRESS_MIN_FILES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._min_seconds = min_seconds
        self._min_items = min_items
        self._clock = clock
        self._last_time = clock()
        self._last_items = 0

    def ready(self, items: int) -> bool:
        """True (and the window restarts) when an event may be sent for ``items`` handled."""
        now = self._clock()
        if now - self._last_time < self._min_seconds or items - self._last_items < self._min_items:
            return False
        self._last_time = now
        self._last_items = items
        return True


def _target_of(ctx: RunContext) -> tuple[str, IngestOptions]:
    value = ctx.artefacts.get_json(keys.TARGET)
    target = value.get("target") if isinstance(value, dict) else None
    if not isinstance(target, str):
        raise ValueError("the scan.target artefact has no target")
    options = value.get("options") if isinstance(value, dict) else None
    return target, IngestOptions.from_mapping(options)


@contextmanager
def _scratch(ctx: RunContext) -> Iterator[Path]:
    """Where a source may copy a single-file target: the scan's state directory, else a temp dir."""
    if ctx.state_dir is not None:
        yield StateLayout(ctx.state_dir).scan_dir(ctx.scan_id) / SOURCE_DIR
        return
    with tempfile.TemporaryDirectory(prefix="codekavach-ingest-") as name:
        yield Path(name)


def _working_root(ctx: RunContext) -> tuple[Path, Path]:
    """``(root, removable)``: a fresh private directory for a source that owns its root."""
    if ctx.state_dir is not None:
        into = StateLayout(ctx.state_dir).work_dir(ctx.scan_id)
        remove_tree(into)  # a resumed scan starts from nothing
        into.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return into, into
    holder = Path(tempfile.mkdtemp(prefix="codekavach-work-"))
    return holder / "tree", holder


def _narrow(
    ctx: RunContext,
    root: Path,
    files: list[SourceFile],
    options: IngestOptions,
    report: DiscoveryReport,
) -> list[SourceFile]:
    """Apply ``--subproject`` then ``--diff-since``, recording what each left out."""
    report.subprojects = tuple((s.path, s.kind) for s in detect_subprojects(root, files))
    kept = files
    if options.subprojects:
        kept = select_subprojects(files, options.subprojects)
        report.subproject_excluded = len(files) - len(kept)
    if options.diff_since is not None:
        diff = resolve_diff(root, options.diff_since, files, state_dir=ctx.state_dir)
        if diff is None:
            report.diff_unresolved = True
            ctx.warn("diff_base_unresolved")
        else:
            before = len(kept)
            kept = [f for f in kept if f.path in diff.changed]
            report.diff_base = options.diff_since
            report.diff_excluded = before - len(kept)
            if options.include_deleted:
                report.diff_deleted = len(diff.deleted)
    return kept


def _materialise(ctx: RunContext, source: Source, target: str, limits: IngestLimits) -> Path:
    """Materialise ``target`` into a working root that ``ctx.scan_root`` removes at scan end."""
    into, removable = _working_root(ctx)
    ctx.scan_root.set(into, cleanup=lambda: remove_tree(removable))
    return source.materialise(target, limits=limits, into=into)


class IngestStage:
    """Discovers, filters and classifies the files of the scan target."""

    name = "ingest"
    version = "1"
    requires = frozenset({keys.TARGET})
    provides = frozenset({keys.FILES, keys.LANGUAGES, keys.INGEST_COVERAGE})
    category = StageCategory.INGEST

    def run(self, ctx: RunContext) -> None:
        """Write ``files`` and ``languages`` for the target in the ``scan.target`` artefact."""
        target, options = _target_of(ctx)
        source = select_source(target, options)
        limits = IngestLimits.from_settings(ctx.config.ingest)
        throttle = ProgressThrottle()

        def checkpoint(done: int, total: int) -> None:
            ctx.check_cancelled()
            if throttle.ready(done):
                ctx.emit_progress(done, total, "files")

        report = DiscoveryReport()
        if source.owns_root:
            root = _materialise(ctx, source, target, limits)
            files = discover(root, ctx.config, on_candidate=checkpoint, report=report)
        else:
            with _scratch(ctx) as into:
                root = source.materialise(target, limits=limits, into=into)
                files = discover(root, ctx.config, on_candidate=checkpoint, report=report)
        report.submodules_not_scanned = unfetched_submodules(root)
        if report.submodules_not_scanned:
            ctx.warn("submodules_not_scanned")
        files = _narrow(ctx, root, files, options, report)

        languages = sorted({f.language for f in files} - {Language.UNKNOWN}, key=_by_value)
        ctx.emit_progress(len(files), len(files), "files")
        if not files:
            ctx.warn("no_files_found")
        ctx.artefacts.put(keys.FILES, files)
        ctx.artefacts.put(keys.LANGUAGES, languages)
        ctx.artefacts.put(keys.INGEST_COVERAGE, report.as_record())


def _by_value(language: Language) -> str:
    return language.value
