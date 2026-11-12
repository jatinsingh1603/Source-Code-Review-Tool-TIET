"""Shared plumbing for the optional matchers (E19-02).

Each matcher runs through the engine sandbox (:class:`SubprocessSandbox`: scrubbed environment,
resource limits, own network namespace where the platform allows it, output cap, timeout). A matcher
whose executable is absent raises :class:`MatcherUnavailable`, which callers treat as "skipped", not
as a failure: the native matcher always runs.
"""

import json
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codekavach.analysis.engines.errors import EngineSandboxError, EngineUnavailable
from codekavach.analysis.engines.sandbox import SandboxLimits, SandboxRequest, SubprocessSandbox
from codekavach.analysis.sca.model import Dependency


class MatcherUnavailable(RuntimeError):  # noqa: N818 - a skip signal, not an error
    """The matcher is not installed, was refused, or failed; the scan continues without it."""


def run_matcher(
    engine_id: str,
    argv: Sequence[str],
    root: Path,
    *,
    env: Mapping[str, str] | None = None,
    timeout: float = 300.0,
) -> Any:
    """Run ``argv`` in the sandbox over ``root`` and return its parsed JSON output."""
    with tempfile.TemporaryDirectory(prefix="kavach-sca-") as scratch:
        out = Path(scratch)
        request = SandboxRequest(
            engine_id=engine_id,
            argv=tuple(argv),
            root=root,
            out_dir=out,
            stdout_path=out / "stdout.json",
            stderr_path=out / "stderr.txt",
            timeout_seconds=timeout,
            env=dict(env or {}),
            limits=SandboxLimits(memory_mb=2048),
        )
        try:
            result = SubprocessSandbox().run(request)
        except (EngineUnavailable, EngineSandboxError) as error:
            raise MatcherUnavailable(f"{engine_id}: {error}") from None
        if result.timed_out or result.truncated:
            raise MatcherUnavailable(f"{engine_id}: timed out or produced too much output")
        try:
            return json.loads(request.stdout_path.read_text("utf-8") or "null")
        except (ValueError, OSError):
            raise MatcherUnavailable(f"{engine_id}: output is not JSON") from None


def index_dependencies(deps: Sequence[Dependency]) -> dict[tuple[str, str], list[Dependency]]:
    """Components by lower-cased ``(name, version)`` for mapping adapter rows back."""
    index: dict[tuple[str, str], list[Dependency]] = {}
    for dep in deps:
        index.setdefault((dep.name.lower().replace("_", "-"), dep.version), []).append(dep)
    return index
