"""Run the selected engines concurrently and cache what they found (E14-01).

Owning epic: E14.

Engines run in a thread pool; each acquires as many units of a shared capacity (the scan's worker
count) as its weight, so four heavy JVM side-cars never run at once while many light engines do.
Results come back in engine-id order whatever the finishing order.

**Cache.** An engine's parsed candidates are stored in the per-item memo (E04-22) under
``sha256(engine id, resolved version, canonical invocation, sorted (path, sha256) of the files
handed to the engine, settings fingerprint)``. The canonical invocation replaces the scan root with
its token, so a different temporary directory does not change the key. Only a run that ended ``ok``
and was not truncated is stored; a failure is never cached, so the next scan tries again.
"""

import hashlib
import json
import os
import threading
import time
from collections.abc import Collection, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Final

from codekavach.analysis.engines.base import (
    ROOT_TOKEN,
    EngineAdapter,
    EngineInvocation,
    EngineRun,
)
from codekavach.analysis.engines.errors import CODE_ERROR, CODE_UNAVAILABLE
from codekavach.analysis.engines.install import verify_installed
from codekavach.analysis.engines.manifest import ManifestEntry, effective_policy
from codekavach.analysis.engines.runner import RunLimits, run_engine
from codekavach.analysis.engines.sandbox import SandboxSet, limits_from_settings
from codekavach.config.snapshot import settings_fingerprint
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, Language
from codekavach.core.pipeline.cancel import ScanCancelledError
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.memo import memo_key
from codekavach.ingest.models import SourceFile

# The key does not cover the adapters' own code: bump the suffix whenever an adapter changes the
# candidates it makes from the same engine output (v2: Bandit titles in plain words), or a server
# upgraded in place keeps serving the old candidates for unchanged files.
CACHE_NAMESPACE: Final = "engines.candidates.v2"
MIN_TIMEOUT_SECONDS: Final = 1.0

_log = get_logger("codekavach.analysis.engines.scheduler")


class _NotCacheable(Exception):  # noqa: N818 - control flow inside this module only
    """The run did not end cleanly: hand ``run`` back and store nothing."""

    def __init__(self, run: EngineRun) -> None:
        self.run = run
        super().__init__(run.engine)


class _Capacity:
    """A counting semaphore that grants several units at once."""

    def __init__(self, total: int) -> None:
        self._free = total
        self._condition = threading.Condition()

    def acquire(self, units: int) -> None:
        with self._condition:
            while self._free < units:
                self._condition.wait()
            self._free -= units

    def release(self, units: int) -> None:
        with self._condition:
            self._free += units
            self._condition.notify_all()


def canonical_invocation(invocation: EngineInvocation, root: Path) -> str:
    """The invocation as canonical JSON with the scan root replaced by its token."""
    spellings = {str(root), root.as_posix()}

    def clean(text: str) -> str:
        for spelling in sorted(spellings, key=len, reverse=True):
            text = text.replace(spelling, ROOT_TOKEN)
        return text

    document = {
        "argv": [clean(part) for part in invocation.argv],
        "workdir": clean(invocation.workdir),
        "env": {name: clean(value) for name, value in sorted(invocation.env.items())},
        "output_file": invocation.output_file,
        "stdout_is_output": invocation.stdout_is_output,
        "expect_exit_codes": sorted(invocation.expect_exit_codes),
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def cache_key(
    *,
    engine_id: str,
    version: str,
    invocation: EngineInvocation,
    root: Path,
    files: Sequence[SourceFile],
    fingerprint: str,
) -> str:
    """The memo key of one engine run, as described in the module docstring."""
    digest = hashlib.sha256()
    for file in sorted(files, key=lambda f: f.path):
        digest.update(f"{file.path}\x1f{file.sha256}\n".encode())
    return memo_key(
        engine_id, version, canonical_invocation(invocation, root), digest.hexdigest(), fingerprint
    )


def _skipped(adapter: EngineAdapter, version: str) -> EngineRun:
    return EngineRun(
        engine=adapter.spec.id,
        version=version,
        exit_code=None,
        duration_seconds=0.0,
        status="skipped",
    )


def _unavailable(adapter: EngineAdapter, version: str) -> EngineRun:
    return EngineRun(
        engine=adapter.spec.id,
        version=version,
        exit_code=None,
        duration_seconds=0.0,
        status="unavailable",
        error_code=CODE_UNAVAILABLE,
    )


def _timeout(ctx: RunContext, adapter: EngineAdapter, policy_timeout: int | None) -> float:
    options = ctx.config.engines.options.get(adapter.spec.id)
    seconds = float(
        (options.timeout_seconds if options and options.timeout_seconds else None)
        or policy_timeout
        or ctx.config.engines.timeout_seconds
    )
    remaining = ctx.remaining_seconds()
    if remaining is not None:
        seconds = min(seconds, max(MIN_TIMEOUT_SECONDS, remaining))
    return seconds


def _run_one(
    adapter: EngineAdapter,
    ctx: RunContext,
    *,
    languages: Collection[Language],
    files: Sequence[SourceFile],
    view: Path,
    work_dir: Path,
    sandboxes: SandboxSet,
    manifest: Mapping[str, ManifestEntry] | None,
    fingerprint: str,
) -> EngineRun:
    spec = adapter.spec
    policy = effective_policy(spec, manifest)
    probe = adapter.probe(ctx.config)
    version = probe.version or policy.pinned_version
    if verify_installed(spec.id, probe, manifest):
        return _unavailable(adapter, version)
    if not adapter.applies_to(languages, files):
        return _skipped(adapter, version)
    invocation = adapter.build_invocation(view, files, ctx.config)
    if invocation is None:
        return _skipped(adapter, version)
    options = ctx.config.engines.options.get(spec.id)
    key = cache_key(
        engine_id=spec.id,
        version=version,
        invocation=invocation,
        root=view,
        files=files,
        fingerprint=fingerprint,
    )
    ran: EngineRun | None = None

    def compute() -> list[Candidate]:
        nonlocal ran
        limits = RunLimits(
            timeout_seconds=_timeout(ctx, adapter, policy.timeout_seconds),
            root=view,
            out_dir=work_dir / "engines" / spec.id,
            sandbox=limits_from_settings(ctx.config),
            passthrough=tuple(options.env_passthrough) if options else (),
            extra_env=dict(policy.telemetry_env),
            image=policy.image,
        )
        sandbox = sandboxes.pick(spec.id, policy.image)
        run = run_engine(adapter, invocation, sandbox=sandbox, limits=limits, version=version)
        if run.status != "ok" or run.truncated:
            raise _NotCacheable(run)
        try:
            found = list(adapter.parse(run, view))
        except Exception as error:  # noqa: BLE001 - a broken parser must not lose the scan
            _log.warning("engine_parse_failed", engine=spec.id, error_type=type(error).__name__)
            raise _NotCacheable(replace(run, status="error", error_code=CODE_ERROR)) from None
        ran = run
        return found

    try:
        candidates = ctx.memo.get_or_compute_list(CACHE_NAMESPACE, key, compute, Candidate)
    except _NotCacheable as stop:
        return stop.run
    if ran is None:
        return EngineRun(
            engine=spec.id,
            version=version,
            exit_code=0,
            duration_seconds=0.0,
            status="ok",
            cached=True,
            candidates=tuple(candidates),
        )
    return replace(ran, candidates=tuple(candidates))


def run_all(
    adapters: Sequence[EngineAdapter],
    ctx: RunContext,
    *,
    languages: Collection[Language],
    files: Sequence[SourceFile],
    view: Path,
    work_dir: Path,
    sandboxes: SandboxSet,
    manifest: Mapping[str, ManifestEntry] | None = None,
) -> list[EngineRun]:
    """Run ``adapters`` concurrently; the result is in engine-id order.

    An engine that raises unexpectedly yields an ``error`` run, never an exception. Cancelling the
    scan stops engines that have not started.
    """
    ordered = sorted(adapters, key=lambda adapter: adapter.spec.id)
    if not ordered:
        return []
    workers = ctx.config.scan.jobs or os.cpu_count() or 1
    capacity = _Capacity(max(1, workers))
    total = max(1, workers)
    fingerprint = settings_fingerprint(ctx.config, sections=("engines",))

    def task(adapter: EngineAdapter) -> EngineRun:
        units = min(effective_policy(adapter.spec, manifest).weight, total)
        capacity.acquire(units)
        started = time.monotonic()
        try:
            ctx.check_cancelled()
            return _run_one(
                adapter,
                ctx,
                languages=languages,
                files=files,
                view=view,
                work_dir=work_dir,
                sandboxes=sandboxes,
                manifest=manifest,
                fingerprint=fingerprint,
            )
        except ScanCancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - one engine must not stop the others
            _log.warning("engine_failed", engine=adapter.spec.id, error_type=type(error).__name__)
            return EngineRun(
                engine=adapter.spec.id,
                version="",
                exit_code=None,
                duration_seconds=time.monotonic() - started,
                status="error",
                error_code=CODE_ERROR,
            )
        finally:
            capacity.release(units)

    with ThreadPoolExecutor(max_workers=len(ordered), thread_name_prefix="engine") as pool:
        futures = [pool.submit(task, adapter) for adapter in ordered]
        return [future.result() for future in futures]
