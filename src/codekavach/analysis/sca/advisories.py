"""Advisory mirror loading and version-range matching (E19-01, E19-02).

The mirror is a directory of OSV snapshots (``<ecosystem>.zip`` of ``<id>.json`` files, as
published by osv.dev) refreshed only by ``codekavach sca update``. A small seed shipped with the
package covers the packages planted in the sample project, so a scan works on a fresh install.
``match`` evaluates the OSV ``affected`` ranges (``introduced``, ``fixed``, ``last_affected``)
per ecosystem with the comparison rules of ``versions.py``.
"""

import json
import re
import zipfile
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import platformdirs

from codekavach.analysis.sca.model import Dependency
from codekavach.analysis.sca.versions import compare

SEVERITY_WORDS = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}
_CWE = re.compile(r"CWE-(\d+)")


def default_mirror_dir() -> Path:
    """``<user data dir>/codekavach/sca``."""
    return Path(platformdirs.user_data_path("codekavach", appauthor=False)) / "sca"


def normalise_name(ecosystem: str, name: str) -> str:
    """The lookup form of a package name."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower() if ecosystem in {"npm", "RubyGems", "Packagist", "NuGet"} else name


@dataclass(frozen=True)
class AdvisoryMatch:
    """One advisory affecting one component."""

    dependency: Dependency
    advisory_id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    cwe: tuple[int, ...]
    fixed: tuple[str, ...]
    references: tuple[str, ...]
    cvss_vector: str | None = None
    source: str = "codekavach-native"
    modified: str = ""
    sources: tuple[str, ...] = ("codekavach-native",)
    symbols: tuple[str, ...] = ()
    cvss4_vector: str | None = None

    @property
    def cve(self) -> str | None:
        """The first CVE alias, when there is one."""
        return next((a for a in (self.advisory_id, *self.aliases) if a.startswith("CVE-")), None)


@dataclass
class Mirror:
    """Advisories indexed by ecosystem and normalised package name."""

    index: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    snapshot_date: str | None = None

    def add(self, record: dict[str, Any]) -> None:
        """Index one OSV record under every package it affects."""
        for affected in record.get("affected", []):
            package = affected.get("package") or {}
            eco, name = package.get("ecosystem", ""), package.get("name", "")
            eco = eco.split(":")[0]
            if eco and name:
                bucket = self.index.setdefault((eco, normalise_name(eco, name)), [])
                bucket[:] = [r for r in bucket if r.get("id") != record.get("id")]
                bucket.append(record)

    @property
    def size(self) -> int:
        """Number of distinct advisories."""
        return len({r["id"] for bucket in self.index.values() for r in bucket})


def load_seed() -> list[dict[str, Any]]:
    """The advisories bundled with the package."""
    text = (resources.files("codekavach.analysis.sca") / "data" / "seed_advisories.json").read_text(
        "utf-8"
    )
    return list(json.loads(text)["advisories"])


def load_mirror(
    directory: Path | None = None, wanted: set[tuple[str, str]] | None = None
) -> Mirror:
    """The seed plus every OSV zip under ``directory``; ``wanted`` limits what is indexed."""
    mirror = Mirror()
    for record in load_seed():
        mirror.add(record)
    mirror.sources.append("seed")
    directory = directory or default_mirror_dir()
    osv = directory / "osv"
    if osv.is_dir():
        for archive in sorted(osv.glob("*.zip")):
            try:
                with zipfile.ZipFile(archive) as zf:
                    for member in zf.namelist():
                        if not member.endswith(".json"):
                            continue
                        raw = zf.read(member)
                        if wanted is not None and not _mentions(raw, wanted):
                            continue
                        try:
                            mirror.add(json.loads(raw))
                        except ValueError:
                            continue
                mirror.sources.append(archive.stem)
            except (zipfile.BadZipFile, OSError):
                continue
    stamp = directory / "snapshot.json"
    if stamp.is_file():
        try:
            mirror.snapshot_date = json.loads(stamp.read_text("utf-8")).get("date")
        except (ValueError, OSError):
            pass
    return mirror


def _mentions(raw: bytes, wanted: set[tuple[str, str]]) -> bool:
    text = raw.decode("utf-8", "replace").lower().replace("_", "-")
    return any(name.lower().replace("_", "-") in text for _, name in wanted)


def _affected(ecosystem: str, version: str, affected: dict[str, Any]) -> tuple[bool, list[str]]:
    """Whether ``version`` is affected, and the fixed versions listed for this entry."""
    fixed: list[str] = []
    if version in (affected.get("versions") or []):
        hit = True
    else:
        hit = False
    for rng in affected.get("ranges", []):
        if rng.get("type") == "GIT":
            continue
        introduced: str | None = None
        for event in rng.get("events", []):
            if "introduced" in event:
                introduced = event["introduced"]
            elif "fixed" in event:
                fixed.append(event["fixed"])
                if _in(ecosystem, version, introduced, event["fixed"], False):
                    hit = True
                introduced = None
            elif "last_affected" in event:
                if _in(ecosystem, version, introduced, event["last_affected"], True):
                    hit = True
                introduced = None
        if introduced is not None and _in(ecosystem, version, introduced, None, False):
            hit = True
    return hit, fixed


def _in(eco: str, version: str, start: str | None, end: str | None, inclusive: bool) -> bool:
    if start not in (None, "0") and compare(eco, version, start) < 0:
        return False
    if end is None:
        return True
    cmp = compare(eco, version, end)
    return cmp <= 0 if inclusive else cmp < 0


def _severity(record: dict[str, Any]) -> str:
    word = str((record.get("database_specific") or {}).get("severity", "")).upper()
    return SEVERITY_WORDS.get(word, "medium")


def _cvss_vector(record: dict[str, Any], prefix: str = "CVSS:3") -> str | None:
    for entry in record.get("severity", []) or []:
        score = str(entry.get("score", ""))
        if score.startswith(prefix):
            return score
    return None


def _symbols(record: dict[str, Any], name: str, ecosystem: str) -> tuple[str, ...]:
    """Advisory-named symbols: OSV ``ecosystem_specific`` imports and ``affected_functions``."""
    found: list[str] = []
    for affected in record.get("affected", []):
        if normalise_name(ecosystem, (affected.get("package") or {}).get("name", "")) != (
            normalise_name(ecosystem, name)
        ):
            continue
        specific = affected.get("ecosystem_specific") or {}
        found.extend(str(f) for f in specific.get("affected_functions", []) or [])
        for entry in specific.get("imports", []) or []:
            found.extend(str(s) for s in entry.get("symbols", []) or [])
    return tuple(dict.fromkeys(f.rsplit(".", 1)[-1] for f in found))


def match(
    dependencies: tuple[Dependency, ...] | list[Dependency], mirror: Mirror
) -> list[AdvisoryMatch]:
    """Every advisory of ``mirror`` that affects a pinned component of ``dependencies``."""
    found: dict[tuple[str, str, str], AdvisoryMatch] = {}
    for dep in dependencies:
        if not dep.version or dep.is_internal:
            continue
        records = mirror.index.get((dep.ecosystem, normalise_name(dep.ecosystem, dep.name)), [])
        for record in records:
            fixed_all: list[str] = []
            hit = False
            for affected in record.get("affected", []):
                package = affected.get("package") or {}
                if normalise_name(dep.ecosystem, package.get("name", "")) != normalise_name(
                    dep.ecosystem, dep.name
                ):
                    continue
                ok, fixed = _affected(dep.ecosystem, dep.version, affected)
                hit = hit or ok
                fixed_all.extend(fixed)
            if not hit:
                continue
            cwes = tuple(
                int(m[1])
                for c in (record.get("database_specific") or {}).get("cwe_ids", [])
                if (m := _CWE.match(str(c)))
            )
            refs = tuple(str(r.get("url")) for r in record.get("references", []) if r.get("url"))
            # the fixed versions on the same major line first: the smallest that is above ours
            newer = sorted(
                {f for f in fixed_all if compare(dep.ecosystem, f, dep.version) > 0},
                key=lambda v: _sortable(dep.ecosystem, v),
            )
            found[(dep.purl, dep.resolved_from, record["id"])] = AdvisoryMatch(
                dependency=dep,
                advisory_id=record["id"],
                aliases=tuple(record.get("aliases", [])),
                summary=str(record.get("summary") or record.get("details", ""))[:300],
                severity=_severity(record),
                cwe=cwes,
                fixed=tuple(newer),
                references=refs[:6],
                cvss_vector=_cvss_vector(record),
                cvss4_vector=_cvss_vector(record, "CVSS:4.0/"),
                symbols=_symbols(record, dep.name, dep.ecosystem),
                modified=str(record.get("modified", "")),
            )
    return sorted(found.values(), key=lambda m: (m.dependency.purl, m.advisory_id))


def _sortable(ecosystem: str, version: str) -> Any:
    from codekavach.analysis.sca.versions import sort_key  # noqa: PLC0415

    return sort_key(ecosystem)(version)
