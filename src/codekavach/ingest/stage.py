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
from codekavach.ingest.discovery import discover
from codekavach.ingest.limits import IngestLimits
from codekavach.ingest.sources.selection import select_source

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


def _target_of(ctx: RunContext) -> str:
    value = ctx.artefacts.get_json(keys.TARGET)
    target = value.get("target") if isinstance(value, dict) else None
    if not isinstance(target, str):
        raise ValueError("the scan.target artefact has no target")
    return target


@contextmanager
def _scratch(ctx: RunContext) -> Iterator[Path]:
    """Where a source may copy a single-file target: the scan's state directory, else a temp dir."""
    if ctx.state_dir is not None:
        yield StateLayout(ctx.state_dir).scan_dir(ctx.scan_id) / SOURCE_DIR
        return
    with tempfile.TemporaryDirectory(prefix="codekavach-ingest-") as name:
        yield Path(name)


class IngestStage:
    """Discovers, filters and classifies the files of the scan target."""

    name = "ingest"
    version = "1"
    requires = frozenset({keys.TARGET})
    provides = frozenset({keys.FILES, keys.LANGUAGES})
    category = StageCategory.INGEST

    def run(self, ctx: RunContext) -> None:
        """Write ``files`` and ``languages`` for the target in the ``scan.target`` artefact."""
        target = _target_of(ctx)
        source = select_source(target)
        limits = IngestLimits.from_settings(ctx.config.ingest)
        throttle = ProgressThrottle()

        def checkpoint(done: int, total: int) -> None:
            ctx.check_cancelled()
            if throttle.ready(done):
                ctx.emit_progress(done, total, "files")

        with _scratch(ctx) as into:
            root = source.materialise(target, limits=limits, into=into)
            files = discover(root, ctx.config, on_candidate=checkpoint)

        languages = sorted({f.language for f in files} - {Language.UNKNOWN}, key=_by_value)
        ctx.emit_progress(len(files), len(files), "files")
        if not files:
            ctx.warn("no_files_found")
        ctx.artefacts.put(keys.FILES, files)
        ctx.artefacts.put(keys.LANGUAGES, languages)


def _by_value(language: Language) -> str:
    return language.value
