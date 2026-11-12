"""Secrets in repository history: credentials committed once and later removed (issue 236).

Reads the patch log of the checked-out repository (bounded by commit and byte caps), runs the
secret detectors over each commit's added lines and reports hits whose masked line no longer
occurs in the working tree (those are already reported by the normal scan). The commit's short
hash is the ``secret.commit`` property; values are masked as always.
"""

import re
import subprocess
from pathlib import Path
from typing import Final

from codekavach.config.models.root import Settings
from codekavach.core.models import Candidate, Language
from codekavach.privacy.detect.registry import DetectorRegistry

MAX_COMMITS: Final = 200
MAX_BYTES: Final = 20_000_000
_COMMIT = re.compile(r"^commit ([0-9a-f]{40})$")
_FILE = re.compile(r"^\+\+\+ b/(.+)$")


def scan_history(root: Path, settings: Settings, registry: DetectorRegistry) -> list[Candidate]:
    """Candidates for secrets added in past commits; empty when ``root`` is not a checkout."""
    from codekavach.analysis.secrets.stage import (  # noqa: PLC0415
        candidates_for,
        hits_in,
    )

    if not (root / ".git").exists():
        return []
    argv = [
        "git",
        "-C",
        str(root),
        "log",
        f"-n{MAX_COMMITS}",
        "-p",
        "--no-color",
        "--no-ext-diff",
        "--diff-filter=AM",
        "--format=commit %H",
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    out = proc.stdout[:MAX_BYTES].decode("utf-8", errors="replace")
    added: dict[tuple[str, str], list[str]] = {}
    commit = path = ""
    for line in out.splitlines():
        if (m := _COMMIT.match(line)) is not None:
            commit, path = m.group(1)[:12], ""
        elif (m := _FILE.match(line)) is not None:
            path = m.group(1)
        elif path and line.startswith("+") and not line.startswith("+++"):
            added.setdefault((commit, path), []).append(line[1:])
    candidates: list[Candidate] = []
    for (sha, file_path), lines in added.items():
        now = {
            h.masked_line
            for h in hits_in(
                _current(root, file_path), file_path, Language.UNKNOWN, settings, registry
            )
        }
        for hit in hits_in("\n".join(lines), file_path, Language.UNKNOWN, settings, registry):
            if hit.masked_line in now:
                continue
            hit.line = hit.end_line = 1
            candidates.extend(
                candidates_for(
                    file_path,
                    Language.UNKNOWN,
                    [hit],
                    extra=(("secret.commit", sha), ("secret.in_history", "true")),
                    rule_suffix=".history",
                )
            )
    return candidates


def _current(root: Path, path: str) -> str:
    try:
        return (root / path).read_text(errors="replace")
    except OSError:
        return ""
