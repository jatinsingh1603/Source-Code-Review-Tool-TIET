"""Inventory, version matching, SBOM and the SCA stage keys (E19-01, E19-02)."""

import json
from pathlib import Path

import pytest

from codekavach.analysis.sca import keys as sca_keys
from codekavach.analysis.sca.advisories import load_mirror, match
from codekavach.analysis.sca.enrich import Enricher, cvss31_score
from codekavach.analysis.sca.manifests import build_graph, parse_manifest
from codekavach.analysis.sca.sbom import to_cyclonedx, to_spdx
from codekavach.analysis.sca.update import OfflineError, _check_url, update_mirror
from codekavach.analysis.sca.versions import compare
from codekavach.core.pipeline import keys

KAVACHBANK = Path(__file__).resolve().parents[4] / "fixtures" / "kavachbank"


@pytest.mark.parametrize(
    ("eco", "a", "b", "expected"),
    [
        ("PyPI", "2.10", "2.10.1", -1),
        ("PyPI", "1.0rc1", "1.0", -1),
        ("PyPI", "1.0.post1", "1.0", 1),
        ("PyPI", "1!0.5", "2.0", 1),
        ("PyPI", "1.0.dev1", "1.0a1", -1),
        ("npm", "4.17.15", "4.17.21", -1),
        ("npm", "1.0.0-beta.2", "1.0.0", -1),
        ("npm", "1.0.0-alpha.2", "1.0.0-alpha.10", -1),
        ("Maven", "1.0-alpha", "1.0", -1),
        ("Maven", "1.0", "1.0.0", 0),
        ("Maven", "1.0-sp1", "1.0", 1),
        ("Go", "v0.0.0-20200101000000-abcdefabcdef", "v0.0.0-20210101000000-abcdefabcdef", -1),
    ],
)
def test_version_order(eco: str, a: str, b: str, expected: int) -> None:
    assert compare(eco, a, b) == expected


def test_requirements_includes_hashes_and_markers() -> None:
    files = {
        "app/requirements.txt": "-r base.txt\nflask==2.2.3 ; python_version>'3'\n"
        "-e git+https://example.test/x.git#egg=local-pkg\n",
        "app/base.txt": "requests==2.19.1 \\\n    --hash=sha256:abcd\n# comment\nurllib3>=1.0\n",
    }
    deps = parse_manifest("app/requirements.txt", files["app/requirements.txt"], files.get)
    by_name = {d.name: d for d in deps}
    assert by_name["flask"].version == "2.2.3"
    assert by_name["requests"].version == "2.19.1"
    assert by_name["requests"].integrity == "sha256:abcd"
    assert by_name["urllib3"].version == "" and by_name["urllib3"].declared_range == ">=1.0"
    assert "local-pkg" in by_name


def test_package_lock_v2_not_double_counted() -> None:
    lock = {
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/a/node_modules/lodash": {"version": "4.17.10"},
        },
        "dependencies": {"lodash": {"version": "4.17.15"}},
    }
    deps = parse_manifest("package-lock.json", json.dumps(lock))
    assert sorted(d.version for d in deps) == ["4.17.10", "4.17.15"]


def test_lock_preferred_and_manifest_marks_direct() -> None:
    files = {
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        "package-lock.json": json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": {"version": "4.17.15"},
                    "node_modules/other": {"version": "1.0.0"},
                },
            }
        ),
    }
    graph, failed = build_graph(files)
    assert not failed
    versions = {d.name: d for d in graph.dependencies}
    assert set(versions) == {"lodash", "other"}
    assert versions["lodash"].direct and versions["lodash"].declared_range == "^4.17.0"
    assert versions["lodash"].resolved_from == "package-lock.json"
    assert not versions["other"].direct


def test_other_ecosystems() -> None:
    pom = (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><v>2.9.0</v></properties>'
        "<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>"
        "<version>${v}</version></dependency></dependencies></project>"
    )
    assert parse_manifest("pom.xml", pom)[0].version == "2.9.0"
    gomod = "module m\nrequire (\n\tgithub.com/x/y v1.2.3\n\tgolang.org/z v0.1.0 // indirect\n)\n"
    go = {d.name: d for d in parse_manifest("go.mod", gomod)}
    assert go["github.com/x/y"].direct and not go["golang.org/z"].direct
    gem = "GEM\n  specs:\n    rack (2.0.1)\n      x (>= 1)\n\nPLATFORMS\n  ruby\n"
    assert parse_manifest("Gemfile.lock", gem)[0].version == "2.0.1"
    cargo = '[[package]]\nname = "serde"\nversion = "1.0.100"\n'
    assert parse_manifest("Cargo.lock", cargo)[0].ecosystem == "crates.io"
    yarn = 'lodash@^4.17.0:\n  version "4.17.15"\n  integrity sha512-aa\n'
    assert parse_manifest("yarn.lock", yarn)[0].version == "4.17.15"


def test_pom_with_dtd_is_refused() -> None:
    with pytest.raises(ValueError, match=r"pom\.xml"):
        parse_manifest("pom.xml", '<!DOCTYPE x [<!ENTITY e "x">]><project/>')


def test_kavachbank_matches_seed_advisories(tmp_path: Path) -> None:
    files = {
        p.relative_to(KAVACHBANK).as_posix(): p.read_text("utf-8")
        for p in KAVACHBANK.rglob("*")
        if p.name in {"requirements.txt", "package.json"}
    }
    graph, _ = build_graph(files)
    mirror = load_mirror(tmp_path)
    ids = {m.advisory_id for m in match(graph.dependencies, mirror)}
    assert {"GHSA-p6mc-m468-83gw", "GHSA-462w-v97r-4m45", "GHSA-8q59-q68h-6hv4"} <= ids
    flask = [m for m in match(graph.dependencies, mirror) if m.dependency.name == "Flask"]
    assert flask and flask[0].fixed[0] == "2.2.5"
    # a fixed version is not reported
    fixed_graph, _ = build_graph({"requirements.txt": "jinja2==3.1.4\nlodash==1\n"})
    assert not match(fixed_graph.dependencies, mirror)


def test_sbom_documents() -> None:
    graph, _ = build_graph({"requirements.txt": "flask==2.2.3\n"})
    cdx = to_cyclonedx(graph, "demo")
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5"
    assert cdx["components"][0]["purl"] == "pkg:pypi/flask@2.2.3"
    spdx = to_spdx(graph, "demo")
    assert spdx["spdxVersion"] == "SPDX-2.3" and spdx["packages"][0]["name"] == "flask"


def test_cvss31_score_known_vector() -> None:
    assert cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N") == 7.2
    assert cvss31_score("not a vector") is None


def test_enricher_reads_snapshots(tmp_path: Path) -> None:
    (tmp_path / "kev.json").write_text(
        json.dumps(
            {
                "dateReleased": "2026-01-02T00:00:00Z",
                "vulnerabilities": [{"cveID": "CVE-1-1", "dateAdded": "2025-01-01"}],
            }
        )
    )
    (tmp_path / "epss.csv").write_text(
        "#model_version:v1,score_date:2026-01-03T00:00:00Z\ncve,epss,percentile\nCVE-1-1,0.5,0.9\n"
    )
    signals = Enricher(tmp_path).signals("CVE-1-1")
    assert signals.kev and signals.epss == 0.5 and signals.epss_snapshot == "2026-01-03"
    assert Enricher(tmp_path / "none").signals("CVE-1-1").kev is None


def test_update_refuses_offline_and_unlisted_hosts(tmp_path: Path) -> None:
    with pytest.raises(OfflineError):
        update_mirror(tmp_path, offline=True)
    with pytest.raises(ValueError, match="allow-listed"):
        _check_url("https://example.com/x.zip")
    with pytest.raises(ValueError, match="allow-listed"):
        _check_url("http://www.cisa.gov/x")


def test_sca_keys_are_raw_and_not_required_by_llm_stages() -> None:
    from codekavach.analysis.sca.stage import AnalyseScaStage  # noqa: PLC0415
    from codekavach.llm.stages import LlmReviewStage  # noqa: PLC0415

    assert sca_keys.DEPENDENCIES == "dependencies" and sca_keys.SBOM == "sbom"
    declared = LlmReviewStage.requires | getattr(LlmReviewStage, "optional_requires", frozenset())
    assert not declared & sca_keys.SCA_KEYS
    assert AnalyseScaStage.requires == {keys.FILES}


def test_gradle_lockfile_and_verification_metadata() -> None:
    lock = (
        "# comment\n"
        "org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath\n"
        "junit:junit:4.13=testCompileClasspath\nempty=annotationProcessor\n"
    )
    deps = {d.name: d for d in parse_manifest("gradle.lockfile", lock)}
    assert deps["org.apache.logging.log4j:log4j-core"].version == "2.14.1"
    assert deps["junit:junit"].scope == "test"
    meta = (
        '<?xml version="1.0"?><verification-metadata '
        'xmlns="https://schema.gradle.org/dependency-verification">'
        '<components><component group="com.google.guava" name="guava" version="31.0">'
        '<artifact name="guava-31.0.jar"><sha256 value="abc123"/></artifact></component>'
        "</components></verification-metadata>"
    )
    got = parse_manifest("gradle/verification-metadata.xml", meta)
    assert got[0].name == "com.google.guava:guava" and got[0].integrity == "sha256:abc123"


def test_nuget_composer_and_cargo_manifests() -> None:
    nuget = json.dumps(
        {
            "version": 1,
            "dependencies": {
                "net6.0": {
                    "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1", "contentHash": "h"},
                    "Dep.Two": {"type": "Transitive", "resolved": "1.2.3"},
                    "My.Project": {"type": "Project"},
                }
            },
        }
    )
    deps = {d.name: d for d in parse_manifest("packages.lock.json", nuget)}
    assert deps["Newtonsoft.Json"].direct and deps["Newtonsoft.Json"].purl.startswith("pkg:nuget/")
    assert not deps["Dep.Two"].direct and "My.Project" not in deps
    composer = json.dumps(
        {
            "require": {"php": ">=8", "ext-json": "*", "monolog/monolog": "2.0.1"},
            "require-dev": {"phpunit/phpunit": "^9"},
        }
    )
    cdeps = {d.name: d for d in parse_manifest("composer.json", composer)}
    assert set(cdeps) == {"monolog/monolog", "phpunit/phpunit"}
    assert cdeps["monolog/monolog"].version == "2.0.1" and cdeps["phpunit/phpunit"].scope == "dev"
    cargo = '[dependencies]\nserde = "1.0"\nlocal = { path = "../local" }\nfoo = "=1.2.3"\n'
    kdeps = {d.name: d for d in parse_manifest("Cargo.toml", cargo)}
    assert kdeps["local"].is_internal and kdeps["foo"].version == "1.2.3"


def test_licences_and_internal_detection() -> None:
    from codekavach.analysis.sca.internal import private_hosts_from_config  # noqa: PLC0415

    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/a": {
                    "version": "1.0.0",
                    "license": "MIT OR Apache-2.0",
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                },
                "node_modules/b": {
                    "version": "2.0.0",
                    "resolved": "https://npm.bank.example/b/-/b-2.0.0.tgz",
                },
                "node_modules/c": {"version": "3.0.0", "resolved": "file:../c"},
                "node_modules/acme-core": {"version": "1.0.0"},
            },
        }
    )
    graph, _ = build_graph({"package-lock.json": lock}, private_prefixes=("acme-",))
    by = {d.name: d for d in graph.dependencies}
    assert by["a"].licence_ids == ("MIT", "Apache-2.0") and not by["a"].is_internal
    assert by["b"].is_internal and "not a known public host" in (by["b"].internal_reason or "")
    assert by["c"].internal_reason == "local path source"
    assert "private prefix" in (by["acme-core"].internal_reason or "")
    cfg = {".npmrc": "registry=https://npm.corp.example/\n"}
    assert "npm.corp.example" in private_hosts_from_config(cfg)
