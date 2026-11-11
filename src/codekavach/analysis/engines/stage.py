"""``AnalyseEnginesStage``: external engines to a part of ``candidates.raw`` (E14-01).

Owning epic: E14.

The stage selects the engines for the scan (``engines.enabled``, ``engines.disabled`` and
``engines.options`` only), makes a read-only view of the source with each engine's own
configuration files hidden, runs the engines concurrently under the sandbox, and publishes their
candidates as this stage's part of the multi-provider ``candidates.raw`` key.

**Which switches.** ``engines.native.rules``, ``native.taint``, ``native.secrets``, ``native.sca``
and ``native.iac`` govern CodeKavach's own analysers and are not read here. The two sets of
switches share a settings section; do not wire the wrong one.

**Degrading.** An unavailable, timed-out, crashing, truncated or blocked engine never aborts the
scan. It is recorded with ``ctx.fail_item(engine_id, code)`` where ``code`` is one of the closed
set ``engine_unavailable``, ``engine_timeout``, ``engine_error``, ``engine_output_truncated``,
``engine_licence_blocked`` and ``engine_sandbox_error``, so the report can say which engine did not
run and why. Engine output is never put into a code or a log line: it quotes client code. This is
invariant I4 read for engines: degrade and report, never silently skip.

The stage is not cacheable as a whole, because a cached "engine unavailable" must not hide an
engine installed afterwards. Each engine's candidates are cached on their own by the scheduler.
"""

import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Final

from codekavach.analysis.engines.base import EngineAdapter, EngineProbe
from codekavach.analysis.engines.errors import CODE_ERROR
from codekavach.analysis.engines.manifest import ManifestEntry
from codekavach.analysis.engines.registry import EngineRegistry, default_registry
from codekavach.analysis.engines.sandbox import SandboxSet, build_sandboxes
from codekavach.analysis.engines.scheduler import run_all
from codekavach.analysis.engines.worktree import (
    materialise_readonly,
    neutralise_repo_config,
    remove_view,
)
from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, Language
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory
from codekavach.ingest.models import SourceFile

UNKNOWN_ID_WARNING: Final = "engine_unknown_id"
_log = get_logger("codekavach.analysis.engines.stage")


class AnalyseEnginesStage:
    """Runs the selected external engines and contributes their candidates."""

    name = "analyse-engines"
    version = "1"
    requires = frozenset({keys.FILES})
    optional_requires = frozenset({keys.LANGUAGES})
    provides = frozenset({keys.CANDIDATES_RAW})
    category = StageCategory.ANALYSE
    failure_policy = FailurePolicy.DEGRADE
    cacheable = False

    def __init__(
        self,
        registry: EngineRegistry | None = None,
        *,
        sandboxes: Callable[[Settings], SandboxSet] = build_sandboxes,
        manifest: dict[str, ManifestEntry] | None = None,
        discover_plugins: bool = True,
    ) -> None:
        self._registry = registry if registry is not None else default_registry()
        self._sandboxes = sandboxes
        self._manifest = manifest
        self._discover = discover_plugins

    def run(self, ctx: RunContext) -> None:
        """Publish this stage's part of ``candidates.raw``."""
        files = sorted(ctx.artefacts.get_list(keys.FILES, SourceFile), key=lambda f: f.path)
        languages = sorted({f.language for f in files} - {Language.UNKNOWN}, key=_by_value)
        if self._discover:
            self._registry.load_plugins(ctx.config)
        probes: dict[str, EngineProbe] = {}

        def probe(adapter: EngineAdapter) -> EngineProbe:
            if adapter.spec.id not in probes:
                probes[adapter.spec.id] = adapter.probe(ctx.config)
            return probes[adapter.spec.id]

        resolution = self._registry.resolve(
            ctx.config, languages, probe=probe, manifest=self._manifest
        )
        if resolution.unknown_ids:
            ctx.warn(UNKNOWN_ID_WARNING)
        for engine_id, error in resolution.blocked:
            ctx.fail_item(engine_id, error.code)
        candidates: list[Candidate] = []
        if resolution.adapters:
            candidates = self._run_engines(ctx, resolution.adapters, languages, files)
        ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, candidates)

    def _run_engines(
        self,
        ctx: RunContext,
        adapters: tuple[EngineAdapter, ...],
        languages: list[Language],
        files: list[SourceFile],
    ) -> list[Candidate]:
        sandboxes = self._sandboxes(ctx.config)
        scratch = Path(tempfile.mkdtemp(prefix="ck-engine-view-"))
        work_dir = (
            ctx.state_dir / "engines" / ctx.scan_id
            if ctx.state_dir is not None
            else scratch / "run"
        )
        try:
            view = materialise_readonly(ctx.source_root, into=scratch)
            for adapter in adapters:
                hidden = neutralise_repo_config(view, adapter.spec)
                if hidden:
                    _log.info("engine_config_hidden", engine=adapter.spec.id, count=len(hidden))
            runs = run_all(
                adapters,
                ctx,
                languages=languages,
                files=files,
                view=view,
                work_dir=work_dir,
                sandboxes=sandboxes,
                manifest=self._manifest,
            )
        finally:
            remove_view(scratch)
        found: list[Candidate] = []
        for done, run in enumerate(runs, start=1):
            _log.info(
                "engine_run",
                engine=run.engine,
                status=run.status,
                cached=run.cached,
                seconds=round(run.duration_seconds, 3),
            )
            if run.status != "skipped" and (run.status != "ok" or run.error_code):
                ctx.fail_item(run.engine, run.error_code or CODE_ERROR)
            found.extend(run.candidates)
            ctx.emit_progress(done, len(runs), "engines")
        for note in sandboxes.notes:
            ctx.warn(note)
        return found


def _by_value(language: Language) -> str:
    return language.value
