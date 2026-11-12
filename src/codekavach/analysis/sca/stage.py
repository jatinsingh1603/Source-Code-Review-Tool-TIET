"""``AnalyseScaStage``: inventory, SBOM and vulnerable-dependency candidates (E19-01, E19-02).

Reads manifests and lock files from the scanned tree, publishes the ``dependencies`` and ``sbom``
artefacts and one candidate per vulnerable component (all of its advisories listed, the worst
severity first) as this stage's part of ``candidates.raw``. It makes no network call: advisories
come from the local mirror (``codekavach sca update``) plus the seed bundled with the package.

A candidate carries ``engine="codekavach-sca"``, ``rule_id="sca.vulnerable-dependency"``, CWE-1395
(and the advisory CWEs) and the properties ``sca.package``, ``sca.version``, ``sca.ecosystem``,
``sca.advisory``, ``sca.advisories``, ``sca.cve``, ``sca.fixed``, ``sca.reachability``,
``sca.kev``, ``sca.epss`` and ``sca.sources``. The reachability hint lowers or raises
confidence but never removes a candidate.
"""

import os
from pathlib import Path
from typing import Final

from codekavach.analysis.sca import keys as sca_keys
from codekavach.analysis.sca.advisories import (
    AdvisoryMatch,
    default_mirror_dir,
    load_mirror,
    match,
    normalise_name,
)
from codekavach.analysis.sca.enrich import Enricher, cvss31_score
from codekavach.analysis.sca.manifests import build_graph, is_manifest_path
from codekavach.analysis.sca.model import DependencyGraph
from codekavach.analysis.sca.reach import ReachIndex
from codekavach.analysis.sca.sbom import to_cyclonedx
from codekavach.analysis.sca.versions import sort_key
from codekavach.core.log import get_logger
from codekavach.core.models import Candidate, Confidence, Language, Location, Severity
from codekavach.core.models.enums import CandidateKind
from codekavach.core.models.fingerprint import FingerprintParts, fingerprint_batch, snippet_hash
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory
from codekavach.ingest.models import SourceFile

SCA_ENGINE: Final = "codekavach-sca"
RULE_ID: Final = "sca.vulnerable-dependency"
MAX_MANIFEST_BYTES: Final = 5 * 1024 * 1024
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_LOG = get_logger("codekavach.analysis.sca.stage")


def mirror_dir() -> Path:
    """The advisory mirror directory (``CODEKAVACH_SCA_MIRROR`` overrides the default)."""
    override = os.environ.get("CODEKAVACH_SCA_MIRROR")
    return Path(override) if override else default_mirror_dir()


def read_manifests(root: Path, paths: list[str]) -> dict[str, str]:
    """Texts of the manifest files among ``paths`` (relative to ``root``)."""
    texts: dict[str, str] = {}
    for path in paths:
        if not is_manifest_path(path):
            continue
        file = root / path
        try:
            if file.stat().st_size <= MAX_MANIFEST_BYTES:
                texts[path] = file.read_text("utf-8", errors="replace")
        except OSError:
            continue
    return texts


def _fmt_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _message(
    first: AdvisoryMatch, matches: list[AdvisoryMatch], reach_note: str, signal_note: str
) -> str:
    dep = first.dependency
    cves = [m.cve or m.advisory_id for m in matches]
    head = f"Vulnerable dependency: {dep.name} {dep.version} ({', '.join(cves[:3])}{'...' if len(cves) > 3 else ''})"
    lines = [head]
    for m in matches[:6]:
        fixed = f" Fixed in {', '.join(m.fixed[:2])}." if m.fixed else ""
        lines.append(f"- {m.advisory_id} ({m.cve or 'no CVE'}), {m.severity}: {m.summary}.{fixed}")
    fixes = [m.fixed[0] for m in matches if m.fixed]
    if fixes:
        newest = max(fixes, key=sort_key(dep.ecosystem))
        lines.append(
            f"Remediation: upgrade {dep.name} to {newest} or later (resolves all listed advisories)."
        )
    lines.append(reach_note)
    lines.append(signal_note)
    return "\n".join(lines)[:2000]


def build_candidates(
    matches: list[AdvisoryMatch],
    reach: ReachIndex,
    enricher: Enricher,
    sources: list[str],
) -> list[Candidate]:
    """One candidate per vulnerable component."""
    grouped: dict[tuple[str, str], list[AdvisoryMatch]] = {}
    for m in matches:
        grouped.setdefault((m.dependency.purl, m.dependency.resolved_from), []).append(m)
    built: list[tuple[list[AdvisoryMatch], Location, str]] = []
    for group in grouped.values():
        group.sort(key=lambda m: (-_RANK[m.severity], m.advisory_id))
        dep = group[0].dependency
        built.append(
            (
                group,
                Location(
                    path=dep.resolved_from, start_line=dep.line, end_line=dep.line, symbol=dep.name
                ),
                dep.purl,
            )
        )
    parts = [
        FingerprintParts(
            engine=SCA_ENGINE,
            rule_id=RULE_ID,
            path=location.path,
            symbol=location.symbol,
            snippet_hash=snippet_hash([purl]),
            start_line=location.start_line,
        )
        for _, location, purl in built
    ]
    out: list[Candidate] = []
    for (group, location, _), fingerprint in zip(built, fingerprint_batch(parts), strict=True):
        first = group[0]
        dep = first.dependency
        hint = reach.reach(dep)
        if hint.status == "imported":
            reach_note = f"Reachability: the package is imported ({hint.path}:{hint.line})."
            confidence = Confidence.HIGH
        elif hint.status == "not_imported":
            reach_note = "Reachability: no import of the package was found in the scanned code; it may be a transitive or unused dependency."
            confidence = Confidence.LOW
        else:
            reach_note = "Reachability: unknown for this ecosystem."
            confidence = Confidence.MEDIUM
        cves = [m.cve for m in group if m.cve]
        signals = [enricher.signals(c) for c in cves]
        kev_hits = [c for c, s in zip(cves, signals, strict=True) if s.kev]
        epss_max = max((s.epss for s in signals if s.epss is not None), default=None)
        if enricher.kev_snapshot is None and enricher.epss_snapshot is None:
            signal_note = "Exploitation data: no KEV or EPSS snapshot installed (run `codekavach sca update`)."
        else:
            kev_text = f"KEV: {', '.join(kev_hits)} listed" if kev_hits else "KEV: none listed"
            epss_text = (
                f"EPSS max {_fmt_pct(epss_max)}" if epss_max is not None else "EPSS: no score"
            )
            signal_note = f"Exploitation data: {kev_text}; {epss_text} (KEV {enricher.kev_snapshot}, EPSS {enricher.epss_snapshot})."
        severity = Severity(group[0].severity)
        cwe = tuple(dict.fromkeys((1395, *[c for m in group for c in m.cwe])))
        props: list[tuple[str, str]] = [
            ("sca.package", dep.name),
            ("sca.version", dep.version),
            ("sca.ecosystem", dep.ecosystem),
            ("sca.advisory", first.advisory_id),
            ("sca.advisories", ",".join(m.advisory_id for m in group)[:480]),
            ("sca.reachability", hint.status),
            ("sca.sources", ",".join(sources)[:200] or "seed"),
        ]
        if cves:
            props.append(("sca.cve", ",".join(cves)[:480]))
        fixed = [m.fixed[0] for m in group if m.fixed]
        if fixed:
            props.append(("sca.fixed", max(fixed, key=sort_key(dep.ecosystem))))
        if kev_hits:
            props.append(("sca.kev", ",".join(kev_hits)[:200]))
        if epss_max is not None:
            props.append(("sca.epss", f"{epss_max:.5f}"))
        vector = next((m.cvss_vector for m in group if m.cvss_vector), None)
        score = cvss31_score(vector) if vector else None
        if score is not None:
            props.append(("cvss31_score", f"{score:.1f}"))
        out.append(
            Candidate.create(
                rule_id=RULE_ID,
                engine=SCA_ENGINE,
                cwe=cwe,
                locations=(location,),
                engine_severity=severity,
                engine_confidence=confidence,
                fingerprint=fingerprint,
                kind=CandidateKind.DEPENDENCY,
                language=Language.UNKNOWN,
                message=_message(first, group, reach_note, signal_note),
                properties=tuple(props),
            )
        )
    return out


class AnalyseScaStage:
    """Dependency inventory, SBOM and advisory matching, entirely offline (E19)."""

    name = "analyse-sca"
    version = "1"
    requires = frozenset({keys.FILES})
    optional_requires: frozenset[str] = frozenset()
    provides = frozenset({keys.CANDIDATES_RAW, sca_keys.DEPENDENCIES, sca_keys.SBOM})
    category = StageCategory.ANALYSE

    def run(self, ctx: RunContext) -> None:
        """Publish the inventory, the SBOM and this stage's part of ``candidates.raw``."""
        files = ctx.artefacts.get_list(keys.FILES, SourceFile)
        root = ctx.source_root
        texts = read_manifests(root, [f.path for f in files])
        graph, failed = build_graph(texts)
        for path in failed:
            ctx.fail_item(f"manifest:{path[:60]}", "sca_manifest_unparseable")
        ctx.artefacts.put(sca_keys.DEPENDENCIES, graph)
        project = root.name or "application"
        ctx.artefacts.put(sca_keys.SBOM, to_cyclonedx(graph, project))
        candidates = self._match(ctx, graph, files)
        ctx.artefacts.put_part(keys.CANDIDATES_RAW, self.name, candidates)

    @staticmethod
    def _match(ctx: RunContext, graph: DependencyGraph, files: list[SourceFile]) -> list[Candidate]:
        if not graph.dependencies:
            return []
        directory = mirror_dir()
        wanted = {(d.ecosystem, normalise_name(d.ecosystem, d.name)) for d in graph.dependencies}
        mirror = load_mirror(directory, wanted)
        matches = match(graph.dependencies, mirror)
        if not matches:
            return []
        reach = ReachIndex()
        for file in files:
            if file.language.value in {"python", "javascript", "typescript"}:
                try:
                    text = (ctx.source_root / file.path).read_text("utf-8", errors="replace")
                except OSError:
                    continue
                reach.add_file(file.path, file.language.value, text)
        return build_candidates(matches, reach, Enricher(directory), mirror.sources)
