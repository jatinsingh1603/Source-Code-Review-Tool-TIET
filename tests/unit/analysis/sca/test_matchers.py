"""Adapters, reconciliation, call-graph reachability and CVSS v4 handling (E19-02)."""

import hashlib
from pathlib import Path

import pytest

from codekavach.analysis.sca.adapters import osv_scanner, trivy_fs
from codekavach.analysis.sca.adapters.base import MatcherUnavailable
from codekavach.analysis.sca.advisories import AdvisoryMatch
from codekavach.analysis.sca.enrich import cvss4_valid
from codekavach.analysis.sca.model import Dependency, make_purl
from codekavach.analysis.sca.reach import Reach
from codekavach.analysis.sca.reachability import CALLED, IMPORTED, UNKNOWN, UNREACHABLE, classify
from codekavach.analysis.sca.reconcile import reconcile
from codekavach.parsing.callgraph import CallGraph


def _dep(name: str = "lodash", version: str = "4.17.15", eco: str = "npm") -> Dependency:
    return Dependency(
        purl=make_purl(eco, name, version),
        name=name,
        version=version,
        ecosystem=eco,
        resolved_from="package-lock.json",
    )


def _match(dep: Dependency, ident: str, aliases: tuple[str, ...], source: str) -> AdvisoryMatch:
    return AdvisoryMatch(
        dependency=dep,
        advisory_id=ident,
        aliases=aliases,
        summary="s",
        severity="high",
        cwe=(),
        fixed=(),
        references=(),
        source=source,
        sources=(source,),
    )


def test_osv_scanner_output_is_normalised() -> None:
    dep = _dep()
    output = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "lodash", "version": "4.17.15"},
                        "vulnerabilities": [
                            {"id": "GHSA-x", "aliases": ["CVE-1"], "summary": "bad"}
                        ],
                    }
                ]
            }
        ]
    }
    rows = osv_scanner.parse(output, [dep])
    assert [(r.advisory_id, r.aliases, r.sources) for r in rows] == [
        ("GHSA-x", ("CVE-1",), ("osv-scanner",))
    ]


def test_trivy_output_is_normalised() -> None:
    dep = _dep()
    output = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.15",
                        "FixedVersion": "4.17.21, 5.0.0",
                        "Severity": "CRITICAL",
                        "CweIDs": ["CWE-1321"],
                    }
                ]
            }
        ]
    }
    (row,) = trivy_fs.parse(output, [dep])
    assert row.severity == "critical" and row.cwe == (1321,) and row.fixed == ("4.17.21", "5.0.0")


def test_absent_matchers_are_skipped(tmp_path: Path) -> None:
    with pytest.raises(MatcherUnavailable):
        osv_scanner.scan(tmp_path, [], tmp_path, executable="no-such-osv-scanner-binary")
    with pytest.raises(MatcherUnavailable):
        trivy_fs.scan(tmp_path, [], tmp_path, executable="no-such-trivy-binary")


def test_trivy_refuses_an_unpinned_or_mismatched_binary(tmp_path: Path) -> None:
    binary = tmp_path / "trivy"
    binary.write_text("#!/bin/sh\necho {}\n")
    binary.chmod(0o755)
    with pytest.raises(MatcherUnavailable, match="pinned"):
        trivy_fs.verify_pinned(str(binary), None)
    with pytest.raises(MatcherUnavailable, match="does not match"):
        trivy_fs.verify_pinned(str(binary), "0" * 64)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert trivy_fs.verify_pinned(str(binary), digest) == str(binary)


def test_reconcile_merges_across_alias_sets_and_keeps_single_finds() -> None:
    dep = _dep()
    native = [_match(dep, "GHSA-x", ("CVE-1",), "codekavach-native")]
    other = [_match(dep, "CVE-1", (), "trivy"), _match(dep, "CVE-2", (), "trivy")]
    merged = reconcile(native, other)
    by_id = {m.advisory_id: m for m in merged}
    assert set(by_id) == {"GHSA-x", "CVE-2"}
    assert by_id["GHSA-x"].sources == ("codekavach-native", "trivy")
    assert by_id["CVE-2"].sources == ("trivy",)


def test_reachability_four_values() -> None:
    dep = _dep()
    graph = CallGraph(edges=(("app.handler", "lodash.template"),))
    assert classify(dep, Reach("unknown")).status == UNKNOWN
    assert classify(dep, Reach("not_imported")).status == UNREACHABLE
    assert classify(dep, Reach("imported", "a.js", 3)).status == IMPORTED
    assert classify(dep, Reach("imported", "a.js", 3), ("zipObjectDeep",), graph).status == IMPORTED
    called = classify(dep, Reach("imported", "a.js", 3), ("template",), graph)
    assert called.status == CALLED and called.evidence == "app.handler -> lodash.template"


def test_python_alias_in_call_graph() -> None:
    dep = _dep("PyYAML", "5.3", "PyPI")
    graph = CallGraph(edges=(("app.load", "yaml.full_load"),))
    verdict = classify(dep, Reach("imported", "a.py", 1), ("full_load",), graph)
    assert verdict.status == CALLED


def test_cvss4_vector_validation() -> None:
    good = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert cvss4_valid(good)
    assert not cvss4_valid(good.replace("VC:H", "VC:X"))
    assert not cvss4_valid("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert not cvss4_valid("CVSS:4.0/AV:N")
