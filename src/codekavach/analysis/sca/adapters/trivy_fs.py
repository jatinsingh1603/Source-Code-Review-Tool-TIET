"""Trivy filesystem adapter (Apache-2.0) (E19-02).

Why this adapter is pinned by digest and never by tag: ``docs/research/INSIGHTS.md`` section 5.3
records a malicious Trivy v0.69.4 release with rewritten action tags in March 2026 (advisory
GHSA-69fq-xp46-6x23). A tag can be moved after the fact; a content digest cannot. So the adapter
refuses to run a binary unless the operator has pinned its SHA-256 (``CODEKAVACH_TRIVY_SHA256``,
or the ``expected_sha256`` argument) and the binary on disk matches. A container image is pinned the
same way (``image@sha256:...``) and its signature is verified with ``cosign verify`` by the
operator's installer before the digest is recorded; this module does not pull images.

Runs ``trivy fs --format json --scanners vuln --skip-db-update --offline-scan`` with the cache
directory under the mirror, in the engine sandbox. Absent or unpinned: skipped.
"""

import hashlib
import os
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codekavach.analysis.sca.adapters.base import (
    MatcherUnavailable,
    index_dependencies,
    run_matcher,
)
from codekavach.analysis.sca.advisories import SEVERITY_WORDS, AdvisoryMatch
from codekavach.analysis.sca.model import Dependency

SOURCE = "trivy"
_CWE_PREFIX = "CWE-"


def binary_sha256(path: str) -> str:
    """SHA-256 of the executable at ``path``."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pinned(executable: str, expected_sha256: str | None) -> str:
    """The resolved executable path when its digest equals the pin; else ``MatcherUnavailable``."""
    resolved = shutil.which(executable)
    if resolved is None:
        raise MatcherUnavailable("trivy: executable not found")
    pin = (expected_sha256 or os.environ.get("CODEKAVACH_TRIVY_SHA256", "")).strip().lower()
    if not pin:
        raise MatcherUnavailable("trivy: no pinned SHA-256 digest configured; refusing to run it")
    if binary_sha256(resolved) != pin:
        raise MatcherUnavailable("trivy: the executable does not match the pinned digest")
    return resolved


def parse(output: Any, deps: Sequence[Dependency]) -> list[AdvisoryMatch]:
    """Normalise Trivy JSON (``Results[].Vulnerabilities``)."""
    index = index_dependencies(deps)
    found: list[AdvisoryMatch] = []
    for result in (output or {}).get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            key = (
                str(vuln.get("PkgName", "")).lower().replace("_", "-"),
                str(vuln.get("InstalledVersion", "")),
            )
            for dep in index.get(key, []):
                found.append(_row(dep, vuln))
    return found


def _row(dep: Dependency, vuln: dict[str, Any]) -> AdvisoryMatch:
    ident = str(vuln.get("VulnerabilityID", ""))
    cwes = tuple(
        int(c[len(_CWE_PREFIX) :])
        for c in vuln.get("CweIDs", []) or []
        if str(c).startswith(_CWE_PREFIX) and str(c)[len(_CWE_PREFIX) :].isdigit()
    )
    fixed = tuple(v.strip() for v in str(vuln.get("FixedVersion", "")).split(",") if v.strip())
    return AdvisoryMatch(
        dependency=dep,
        advisory_id=ident,
        aliases=(),
        summary=str(vuln.get("Title") or vuln.get("Description", ""))[:300],
        severity=SEVERITY_WORDS.get(str(vuln.get("Severity", "")).upper(), "medium"),
        cwe=cwes,
        fixed=fixed,
        references=tuple(str(r) for r in vuln.get("References", []) or [])[:6],
        source=SOURCE,
        sources=(SOURCE,),
    )


def scan(
    root: Path,
    deps: Sequence[Dependency],
    mirror_dir: Path,
    executable: str = "trivy",
    expected_sha256: str | None = None,
) -> list[AdvisoryMatch]:
    """Run Trivy over ``root`` after verifying its pinned digest."""
    resolved = verify_pinned(executable, expected_sha256)
    output = run_matcher(
        SOURCE,
        [
            resolved, "fs", "--format", "json", "--scanners", "vuln", "--quiet",
            "--skip-db-update", "--offline-scan", "--cache-dir", str(mirror_dir / "trivy"),
            "{root}",
        ],
        root,
    )  # fmt: skip
    return parse(output, deps)
