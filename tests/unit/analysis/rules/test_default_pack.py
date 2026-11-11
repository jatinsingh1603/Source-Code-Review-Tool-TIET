"""The shipped default pack and catalogues (E16-03): fixtures, metadata, provenance, coverage."""

import re
from pathlib import Path

import pytest

from codekavach.analysis.rules import coverage
from codekavach.analysis.rules.loader import load_catalogue, load_pack, scan_pack
from codekavach.analysis.rules.pack import CatalogueKind, RulePack, public_names
from codekavach.analysis.rules.testing import run_rule_tests
from codekavach.analysis.rules.validate import validate_rules

ROOT = Path(__file__).resolve().parents[4]
RULES_ROOT = ROOT / "rules" / "mit"
PACK_DIR = RULES_ROOT / "packs" / "default"
FIXTURES = ROOT / "tests" / "fixtures" / "rules"
FORBIDDEN_SOURCES = re.compile(r"(?i)\b(agpl|gpl|sspl|busl|commons clause|proprietary|elastic)\b")


@pytest.fixture(scope="module")
def pack() -> RulePack:
    return load_pack(PACK_DIR)


@pytest.fixture(scope="module")
def catalogues() -> list[Path]:
    return sorted((RULES_ROOT / "catalogues").rglob("*.yaml"))


def test_the_pack_loads_clean_and_stays_small(pack: RulePack) -> None:
    scan = scan_pack(PACK_DIR, check_patterns=True)
    assert scan.issues == []
    assert scan.pack is not None
    assert pack.version == "1.0.0"
    assert pack.licence == "MIT"
    assert set(pack.languages) == {"python", "javascript", "c", "cpp"}
    assert 50 <= len(pack.rules) <= 250


def test_every_rule_passes_the_validator_with_patterns_parsed(pack: RulePack) -> None:
    known = {entry.id for catalogue in pack.catalogues for entry in catalogue.items()}
    issues = validate_rules(pack.rules, catalogue_ids=known, licence_dir="mit", check_patterns=True)
    assert [f"{issue.code} {issue.rule_id}" for issue in issues] == []


def test_every_rule_passes_its_own_fixtures(pack: RulePack) -> None:
    report = run_rule_tests([pack], FIXTURES)
    failed = [
        (r.rule_id, r.language, r.missing, r.unexpected, r.problem)
        for r in report.results
        if not r.passed
    ]
    assert failed == []
    assert report.known_gaps == 0


def test_every_rule_has_a_positive_and_a_negative_fixture(pack: RulePack) -> None:
    for rule in pack.rules:
        for language in rule.languages:
            suffix = {"python": "py", "javascript": "js", "c": "c", "cpp": "cpp"}[language]
            text = (FIXTURES / language / f"{rule.id}.{suffix}").read_text(encoding="utf-8")
            assert f"ruleid: {rule.id}" in text, rule.id
            assert f"ok: {rule.id}" in text, rule.id


def test_every_rule_carries_cwe_owasp_and_remediation(pack: RulePack) -> None:
    pillars_and_generic = {20, 664, 284, 693, 703, 707, 710}
    for rule in pack.rules:
        meta = rule.metadata
        assert meta.cwe, rule.id
        assert not set(meta.cwe) & pillars_and_generic, rule.id
        assert all(re.fullmatch(r"A(0[1-9]|10):2021", item) for item in meta.owasp), rule.id
        assert meta.owasp, rule.id
        assert len(meta.remediation) > 20, rule.id
        assert meta.added_in == "1.0.0", rule.id


def test_the_rule_ids_name_their_language_and_class(pack: RulePack) -> None:
    for rule in pack.rules:
        assert rule.id.split(".")[0] in {"python", "javascript", "c"}, rule.id
        assert set(rule.languages) <= {"python", "javascript", "c", "cpp"}
        directory = next(PACK_DIR.rglob(f"{rule.id}.yaml")).parent.name
        assert directory != "default", rule.id


def test_authorisation_hotspots_are_observations_with_low_confidence(pack: RulePack) -> None:
    hotspots = [rule for rule in pack.rules if rule.kind == "hotspot"]
    assert {rule.id for rule in hotspots} >= {
        "python.authz.route-without-auth-decorator",
        "python.authz.object-reference-unscoped",
        "javascript.authz.route-without-auth",
    }
    for rule in hotspots:
        assert rule.confidence.value == "low", rule.id
        assert re.search(r"worth checking|who may call|owns it", rule.message), rule.id
        assert {862, 863, 639} & set(rule.metadata.cwe), rule.id


def test_every_file_under_rules_mit_declares_the_mit_licence(pack: RulePack) -> None:
    assert pack.licence == "MIT"
    for rule in pack.rules:
        assert rule.metadata.licence == "MIT", rule.id
    for path in RULES_ROOT.rglob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        if path.parent.name in {"default"} and path.name == "pack.yaml":
            assert re.search(r"(?m)^licence: MIT$", text), path
        elif "catalogues" not in path.parts:
            assert re.search(r"(?m)^  licence: MIT$", text), path


def test_no_rule_provenance_names_a_source_that_forbids_redistribution(pack: RulePack) -> None:
    for rule in pack.rules:
        source = rule.metadata.source
        assert source, rule.id
        assert not FORBIDDEN_SOURCES.search(source), rule.id


def test_catalogues_load_and_cover_the_required_frameworks(catalogues: list[Path]) -> None:
    loaded = {item.id: item for item in map(load_catalogue, catalogues)}
    assert {
        "python.stdlib",
        "python.flask",
        "python.django",
        "python.fastapi",
        "javascript.node",
        "javascript.express",
        "javascript.koa",
    } <= set(loaded)
    for item in loaded.values():
        assert item.sources or item.sinks or item.sanitisers or item.entry_points, item.id
        assert item.id is not None and item.id.startswith(item.language), item.id


def test_every_catalogue_id_is_unique_across_the_catalogues(catalogues: list[Path]) -> None:
    ids = [entry.id for path in catalogues for entry in load_catalogue(path).items()]
    assert len(ids) == len(set(ids))


def test_public_names_are_dotted_api_names_of_languages_and_libraries(
    catalogues: list[Path],
) -> None:
    loaded = [load_catalogue(path) for path in catalogues]
    names = public_names(loaded)
    assert names == tuple(sorted(set(names)))
    assert "os.system" in names and "flask.request.args" in names
    shape = re.compile(r"^[A-Za-z_][\w$-]*(\.[A-Za-z_][\w$-]*)*$")
    known_roots = {
        "builtins",
        "os",
        "sys",
        "subprocess",
        "shlex",
        "html",
        "urllib",
        "pickle",
        "marshal",
        "shelve",
        "dill",
        "shutil",
        "requests",
        "httpx",
        "xml",
        "sqlite3",
        "hashlib",
        "yaml",
        "flask",
        "jinja2",
        "markupsafe",
        "werkzeug",
        "django",
        "fastapi",
        "bleach",
        "process",
        "child_process",
        "globalThis",
        "vm",
        "fs",
        "http",
        "https",
        "axios",
        "ejs",
        "pug",
        "handlebars",
        "nunjucks",
        "path",
        "escape-html",
        "shell-quote",
        "express",
        "validator",
        "koa",
    }
    for name in names:
        assert shape.match(name), name
        assert name.split(".")[0] in known_roots, name
    kinds = {entry.kind for catalogue in loaded for entry in catalogue.items() if entry.symbol}
    assert kinds <= {CatalogueKind.SOURCE, CatalogueKind.SINK, CatalogueKind.SANITISER}


def test_a_sanitiser_covers_only_contexts_in_the_vocabulary(catalogues: list[Path]) -> None:
    from codekavach.analysis.rules.pack import CONTEXTS  # noqa: PLC0415

    for path in catalogues:
        for entry in load_catalogue(path).items():
            assert set(entry.covers) <= set(CONTEXTS), entry.id
            if entry.context is not None:
                assert entry.context in CONTEXTS, entry.id


def test_the_coverage_document_matches_the_pack_byte_for_byte() -> None:
    assert coverage.check() == []


def test_the_coverage_document_states_what_is_not_covered() -> None:
    text = coverage.DOCUMENT.read_text(encoding="utf-8")
    assert "not covered" in text
    assert "A06:2021" in text
    assert "memory-safe language" in text
    assert "CWE-352" in text
