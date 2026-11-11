"""The taint stage over the KavachBank sample (E17-02).

Intraprocedural taint finds the planted flows whose source is a catalogue source inside the same
function: the path traversal in the exporter (CWE-22) and the reflected output in the renderer
(CWE-79). The other planted flows start at a handler parameter or cross a function or file
boundary, which is E17-03. The two deliberately safe variants are not certain findings: one
escapes with the application's own helper and one guards with a prefix check, and the engine,
which models neither, reports at most an *uncertain* flow with the guard line recorded.
"""

from pathlib import Path

import pytest

from codekavach.analysis.rules.loader import load_pack
from codekavach.core.models import Candidate, Language
from tests.support.kavachbank import FIXTURE_ROOT, load_manifest
from tests.support.taint import candidates_of

ROOT = Path(__file__).resolve().parents[3]
LANGUAGES = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT}
TOLERANCE = 1


@pytest.fixture(scope="module")
def found() -> dict[str, list[Candidate]]:
    load_pack(ROOT / "rules" / "mit" / "packs" / "default")
    result: dict[str, list[Candidate]] = {}
    for path in sorted((FIXTURE_ROOT / "services").rglob("*")):
        language = LANGUAGES.get(path.suffix)
        if language is None or "node_modules" in path.parts:
            continue
        relative = path.relative_to(FIXTURE_ROOT).as_posix()
        result[relative] = candidates_of(path.read_text(encoding="utf-8"), language, path=relative)
    return result


def near(found: dict[str, list[Candidate]], file: str, line: int, cwe: int) -> list[Candidate]:
    return [
        c
        for c in found.get(file, [])
        if cwe in c.cwe and abs(c.primary_location.start_line - line) <= TOLERANCE
    ]


def test_the_planted_intraprocedural_flows_are_found_with_a_valid_path(
    found: dict[str, list[Candidate]],
) -> None:
    planted = {p.id: p for p in load_manifest().planted_vulnerabilities}
    for ident in ("KB-VULN-003", "KB-VULN-010"):
        item = planted[ident]
        hits = near(found, item.file, item.line, item.cwe)
        assert hits, ident
        for candidate in hits:
            assert candidate.taint_path is not None
            assert candidate.taint_path.source.location.path == item.file
            assert candidate.taint_path.sink.location.path == candidate.primary_location.path


def test_the_safe_variants_are_never_certain_findings(found: dict[str, list[Candidate]]) -> None:
    safe_lines = {
        "services/web/exporter.js": range(12, 21),
        "services/web/renderer.js": range(21, 24),
    }
    for file, lines in safe_lines.items():
        for candidate in found[file]:
            if candidate.primary_location.start_line in lines:
                assert dict(candidate.properties).get("taint.uncertain") == "true", candidate
                assert candidate.engine_confidence is not None


def test_no_candidate_leaves_the_sample_without_a_cwe(found: dict[str, list[Candidate]]) -> None:
    assert all(c.cwe for items in found.values() for c in items)
