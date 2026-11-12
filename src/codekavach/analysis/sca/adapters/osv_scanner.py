"""OSV-Scanner adapter (Apache-2.0), offline by default (E19-02).

Runs ``osv-scanner scan source --format json --offline -r <root>`` with its local database
directory pointed at the mirror, so no package name or version leaves the machine. Absent
executable: skipped. Its vulnerabilities are normalised to :class:`AdvisoryMatch` rows and mapped
to our components by name and version, so reconciliation can compare like with like.
"""

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

SOURCE = "osv-scanner"


def available(executable: str = "osv-scanner") -> bool:
    """True when the executable is on PATH."""
    return shutil.which(executable) is not None


def parse(output: Any, deps: Sequence[Dependency]) -> list[AdvisoryMatch]:
    """Normalise OSV-Scanner JSON (``results[].packages[].vulnerabilities``)."""
    index = index_dependencies(deps)
    found: list[AdvisoryMatch] = []
    for result in (output or {}).get("results", []) or []:
        for entry in result.get("packages", []) or []:
            pkg = entry.get("package", {})
            key = (str(pkg.get("name", "")).lower().replace("_", "-"), str(pkg.get("version", "")))
            for dep in index.get(key, []):
                for vuln in entry.get("vulnerabilities", []) or []:
                    found.append(_row(dep, vuln))
    return found


def _row(dep: Dependency, vuln: dict[str, Any]) -> AdvisoryMatch:
    word = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    vector = next(
        (
            str(s.get("score"))
            for s in vuln.get("severity", []) or []
            if str(s.get("score", "")).startswith("CVSS:3")
        ),
        None,
    )
    refs = tuple(str(r.get("url")) for r in vuln.get("references", []) or [] if r.get("url"))
    return AdvisoryMatch(
        dependency=dep,
        advisory_id=str(vuln.get("id", "")),
        aliases=tuple(vuln.get("aliases", []) or []),
        summary=str(vuln.get("summary") or vuln.get("details", ""))[:300],
        severity=SEVERITY_WORDS.get(word, "medium"),
        cwe=(),
        fixed=(),
        references=refs[:6],
        cvss_vector=vector,
        source=SOURCE,
        sources=(SOURCE,),
    )


def scan(
    root: Path, deps: Sequence[Dependency], mirror_dir: Path, executable: str = "osv-scanner"
) -> list[AdvisoryMatch]:
    """Run the scanner over ``root``; ``MatcherUnavailable`` when it cannot run."""
    if not available(executable):
        raise MatcherUnavailable("osv-scanner: executable not found")
    output = run_matcher(
        SOURCE,
        [executable, "scan", "source", "--format", "json", "--offline", "-r", "{root}"],
        root,
        env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(mirror_dir / "osv-scanner-db")},
    )
    return parse(output, deps)
