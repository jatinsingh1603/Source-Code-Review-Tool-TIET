"""The CWE knowledge base and compliance tables under data/ load and cover what we emit."""

import re
from pathlib import Path

import pytest
import yaml

from codekavach.risk.cvss.v4 import Cvss4Vector
from codekavach.risk.cvss.v31 import Cvss31Vector
from codekavach.risk.taxonomy.loader import (
    FALLBACK_FAMILY,
    KnowledgeBase,
    KnowledgeBaseError,
    default_data_dir,
    load_knowledge_base,
    parse_knowledge_base,
)

DATA = default_data_dir()
RULES = Path(__file__).resolve().parents[3] / "rules"

# CWE Top 25 (2024) and the CWEs our packs and the KavachBank ground truth emit.
TOP25_2024 = (79, 787, 89, 352, 22, 125, 78, 416, 862, 434, 94, 20, 77, 287, 269, 502, 200, 863,
              918, 119, 476, 798, 190, 400, 306)  # fmt: skip


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return parse_knowledge_base(DATA)


def _rule_cwes() -> set[int]:
    found: set[int] = set()
    for path in RULES.rglob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        for block in re.findall(r"cwe:\s*\n((?:\s+-\s*\S+\n)+)|cwe:\s*\[([^\]]*)\]", text):
            found.update(int(n) for n in re.findall(r"\d+", block[0] or block[1]))
    return found


def test_tables_load_and_cross_check(kb: KnowledgeBase) -> None:
    assert kb.catalogue_version
    assert FALLBACK_FAMILY in kb.families
    assert len(kb.weaknesses) >= 60
    for family in kb.families.values():
        assert Cvss4Vector.parse(family.cvss4).score() > 0
        assert Cvss31Vector.parse(family.cvss31).base_score() > 0
        assert family.remediation
        assert all(ref.url and ref.url.startswith("https://") for ref in family.references)


def test_top25_ranks_are_complete_and_unique(kb: KnowledgeBase) -> None:
    ranked = {entry.top25: entry.id for entry in kb.weaknesses.values() if entry.top25}
    assert sorted(ranked) == list(range(1, 26))
    assert tuple(ranked[rank] for rank in range(1, 26)) == TOP25_2024


def test_every_emitted_cwe_is_known(kb: KnowledgeBase) -> None:
    emitted = _rule_cwes() | {22, 78, 79, 89, 327, 329, 502, 639, 862, 918}
    missing = sorted(cwe for cwe in emitted if cwe not in kb.weaknesses)
    assert not missing, f"add these CWEs to data/cwe/catalogue.yaml: {missing}"


def test_every_owasp_category_has_a_cwe(kb: KnowledgeBase) -> None:
    used = {entry.owasp for entry in kb.weaknesses.values() if entry.owasp}
    assert used == set(kb.owasp)


def test_every_table_has_sources_and_frameworks_cite_them(kb: KnowledgeBase) -> None:
    sources = yaml.safe_load((DATA / "SOURCES.yaml").read_text(encoding="utf-8"))
    tables = set(sources["tables"])
    on_disk = {
        str(path.relative_to(DATA.parent))
        for path in DATA.rglob("*.yaml")
        if path.name != "SOURCES.yaml" and "risk" not in path.parts
    }
    assert on_disk <= tables
    for cited in sources["tables"].values():
        assert set(cited) <= set(kb.sources)
    assert {"pci-dss", "iso27001", "nist-ssdf", "rbi", "sebi", "cert-in"} <= set(kb.frameworks)


def test_controls_include_baseline_and_family(kb: KnowledgeBase) -> None:
    controls = kb.controls_for(kb.family_for((89,)))
    pairs = {(c.framework, c.id) for c in controls}
    assert ("pci-dss", "6.2.4") in pairs
    assert ("iso27001", "A.8.28") in pairs
    assert len(pairs) == len(controls)
    secrets = {(c.framework, c.id) for c in kb.controls_for(kb.family_for((798,)))}
    assert ("pci-dss", "8.6.2") in secrets


def test_unknown_cwe_falls_back(kb: KnowledgeBase) -> None:
    assert kb.family_for((99999,)).key == FALLBACK_FAMILY
    assert kb.primary((99999, 89)) is not None


def test_broken_table_is_reported(tmp_path: Path) -> None:
    with pytest.raises(KnowledgeBaseError):
        parse_knowledge_base(tmp_path)
    assert load_knowledge_base(tmp_path) is None
