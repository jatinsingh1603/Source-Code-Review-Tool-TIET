"""Run one engine and describe what happened (E14-01).

Owning epic: E14.

``run_engine`` hands an :class:`EngineInvocation` to a sandbox and turns the outcome into an
:class:`EngineRun` with a closed status and a closed error code. It never raises for an engine
that is missing, slow, crashing or noisy: those are the degraded outcomes of invariant I4 read for
engines. Captured stdout and stderr, and the engine's output file, are written under the scan
state directory; their text is never put into a log message, an error or a code, because engine
output quotes client code.
"""

import os
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Final

from codekavach.analysis.engines.base import (
    EngineAdapter,
    EngineInvocation,
    EngineRun,
    RunStatus,
)
from codekavach.analysis.engines.errors import (
    CODE_ERROR,
    CODE_SANDBOX_ERROR,
    CODE_TIMEOUT,
    CODE_TRUNCATED,
    CODE_UNAVAILABLE,
    EngineError,
    EngineSandboxError,
    EngineUnavailable,
)
from codekavach.analysis.engines.sandbox import Sandbox, SandboxLimits, SandboxRequest
from codekavach.core.log import get_logger

STDOUT_NAME: Final = "stdout.txt"
STDERR_NAME: Final = "stderr.txt"

_log = get_logger("codekavach.analysis.engines.runner")


def _sandbox_limits(minimum_mb: int, limits: SandboxLimits) -> SandboxLimits:
    """Raise the memory limit to what the engine needs; 0 (no limit) stays unlimited."""
    if limits.memory_mb <= 0 or limits.memory_mb >= minimum_mb:
        return limits
    return replace(limits, memory_mb=minimum_mb)


@dataclass(frozen=True, slots=True)
class RunLimits:
    """What bounds one run, and where it happens."""

    timeout_seconds: float
    root: Path
    out_dir: Path
    sandbox: SandboxLimits = field(default_factory=SandboxLimits)
    passthrough: tuple[str, ...] = ()
    extra_env: dict[str, str] = field(default_factory=dict)
    image: str | None = None


def _failed(
    adapter: EngineAdapter,
    version: str,
    status: RunStatus,
    code: str,
    started: float,
) -> EngineRun:
    return EngineRun(
        engine=adapter.spec.id,
        version=version,
        exit_code=None,
        duration_seconds=time.monotonic() - started,
        status=status,
        error_code=code,
    )


def _output_inside(out_dir: Path, name: str) -> Path | None:
    candidate = (out_dir / name).resolve()
    try:
        candidate.relative_to(out_dir.resolve())
    except ValueError:
        return None
    return candidate


def run_engine(
    adapter: EngineAdapter,
    invocation: EngineInvocation,
    *,
    sandbox: Sandbox,
    limits: RunLimits,
    version: str = "",
) -> EngineRun:
    """Run ``invocation`` in ``sandbox``; the result carries the status, never an exception."""
    started = time.monotonic()
    out_dir = limits.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = out_dir / STDOUT_NAME, out_dir / STDERR_NAME
    output_path: Path | None = None
    if invocation.output_file is not None:
        output_path = _output_inside(out_dir, invocation.output_file)
        if output_path is None:
            _log.warning("engine_output_path_rejected", engine=adapter.spec.id)
            return _failed(adapter, version, "error", CODE_SANDBOX_ERROR, started)
    request = SandboxRequest(
        engine_id=adapter.spec.id,
        argv=invocation.argv,
        root=limits.root,
        out_dir=out_dir,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timeout_seconds=limits.timeout_seconds,
        workdir=invocation.workdir,
        env={**limits.extra_env, **invocation.env},
        passthrough=limits.passthrough,
        limits=_sandbox_limits(adapter.spec.min_memory_mb, limits.sandbox),
        image=limits.image,
        read_only_paths=invocation.read_only_paths,
    )
    try:
        result = sandbox.run(request)
    except EngineUnavailable:
        return _failed(adapter, version, "unavailable", CODE_UNAVAILABLE, started)
    except EngineSandboxError:
        return _failed(adapter, version, "error", CODE_SANDBOX_ERROR, started)
    except EngineError as error:
        return _failed(adapter, version, "error", error.code, started)
    truncated = result.truncated
    if invocation.stdout_is_output:
        output_path = stdout_path
    if output_path is not None and output_path.is_file():
        size = output_path.stat().st_size
        if size > limits.sandbox.max_output_bytes:
            os.truncate(output_path, limits.sandbox.max_output_bytes)
            truncated = True
    elif output_path is not None:
        output_path = None
    status: RunStatus = "ok"
    code: str | None = None
    if result.timed_out:
        status, code = "timeout", CODE_TIMEOUT
    elif result.exit_code not in invocation.expect_exit_codes:
        status, code = "error", CODE_ERROR
    elif truncated:
        code = CODE_TRUNCATED
    return EngineRun(
        engine=adapter.spec.id,
        version=version,
        exit_code=result.exit_code,
        duration_seconds=result.duration_seconds,
        status=status,
        stdout_path=stdout_path if stdout_path.exists() else None,
        stderr_path=stderr_path if stderr_path.exists() else None,
        output_path=output_path,
        truncated=truncated,
        error_code=code,
    )
