"""Helpers shared by the concrete adapters (E15-01).

Owning epic: E15. Nothing here imports an engine. ``probe_version`` starts the engine once with its
version flag, without a shell, with the scrubbed environment of E14-01 and a short timeout; it never
scans anything.
"""

import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from codekavach.analysis.engines.base import EngineProbe
from codekavach.analysis.engines.manifest import ManifestEntry, load_manifest
from codekavach.analysis.engines.sandbox import build_environment
from codekavach.config import Settings
from codekavach.config.models.engines import EngineOptions
from codekavach.core.log import get_logger
from codekavach.core.models import Language
from codekavach.ingest.models import SourceFile

PROBE_TIMEOUT_SECONDS: Final = 15.0
_VERSION: Final = re.compile(r"\d+(?:\.\d+)+")
_log = get_logger(__name__)


def engine_options(settings: Settings, engine_id: str) -> EngineOptions | None:
    """The operator's per-engine settings, if any."""
    return settings.engines.options.get(engine_id)


def executable_for(settings: Settings, engine_id: str, default: str) -> str:
    """The executable to run: the operator's ``executable`` setting, else ``default`` on PATH."""
    options = engine_options(settings, engine_id)
    return str(options.executable) if options and options.executable else default


def extra_args(settings: Settings, engine_id: str) -> tuple[str, ...]:
    """Extra arguments the operator configured for the engine."""
    options = engine_options(settings, engine_id)
    return tuple(options.args) if options else ()


def option_int(settings: Settings, engine_id: str, key: str, default: int) -> int:
    """An integer engine-specific option, or ``default`` when absent or not a whole number."""
    options = engine_options(settings, engine_id)
    value = options.options.get(key) if options else None
    return (
        value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else default
    )


def option_text(settings: Settings, engine_id: str, key: str) -> str | None:
    """A text engine-specific option, or ``None``."""
    options = engine_options(settings, engine_id)
    value = options.options.get(key) if options else None
    return value if isinstance(value, str) and value else None


def manifest_row(engine_id: str) -> ManifestEntry:
    """The shipped manifest row of ``engine_id``; a missing row is a packaging error."""
    return load_manifest()[engine_id]


def telemetry_args(engine_id: str) -> tuple[str, ...]:
    """The documented telemetry opt-out flags from the manifest row."""
    return manifest_row(engine_id).telemetry_args


def files_in(files: Sequence[SourceFile], languages: frozenset[Language]) -> list[SourceFile]:
    """The discovered files written in one of ``languages``."""
    return [item for item in files if item.language in languages]


def version_in(text: str) -> str | None:
    """The first dotted version number in ``text``."""
    match = _VERSION.search(text)
    return match.group(0) if match else None


def unavailable(engine_id: str, reason: str) -> EngineProbe:
    """A probe result for an engine that cannot be used."""
    return EngineProbe(engine_id, available=False, version=None, path=None, reason=reason)


def probe_version(
    engine_id: str, executable: str, args: Sequence[str] = ("--version",)
) -> EngineProbe:
    """Find ``executable`` and ask it for its version."""
    path = shutil.which(executable)
    if path is None:
        return unavailable(engine_id, "executable not found")
    try:
        with tempfile.TemporaryDirectory(prefix="ck-probe-") as scratch:
            env = build_environment(home=scratch, tmp=scratch, extra={}, passthrough=())
            completed = subprocess.run(
                [path, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=PROBE_TIMEOUT_SECONDS,
                env=env,
                cwd=scratch,
                check=False,
            )
    except (OSError, subprocess.SubprocessError):
        _log.debug("engine_probe_failed", engine=engine_id)
        return unavailable(engine_id, "the version check did not run")
    version = version_in(completed.stdout + completed.stderr)
    if completed.returncode != 0 or version is None:
        return unavailable(engine_id, "the version check failed")
    return EngineProbe(engine_id, available=True, version=version, path=path, reason=None)


def resolve_path(text: str) -> Path:
    """``text`` as an absolute path (no symlink resolution, no existence check)."""
    return Path(text).expanduser().absolute()
