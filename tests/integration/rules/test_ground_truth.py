"""The default pack against the KavachBank ground truth and a deliberately safe set (E16-03).

Every planted weakness of a class the pack covers is found by a shipped rule within the line
tolerance of the manifest; no negative control is reported; and a clean set of handlers produces
nothing, which is the false-positive guard.
"""

from pathlib import Path

import pytest

from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.loader import load_pack
from codekavach.analysis.rules.matcher import Matcher
from codekavach.core.models import Language
from codekavach.parsing import parse
from tests.support.kavachbank import FIXTURE_ROOT, load_manifest, load_negative_controls

ROOT = Path(__file__).resolve().parents[3]
PACK_DIR = ROOT / "rules" / "mit" / "packs" / "default"
SAFE = ROOT / "tests" / "fixtures" / "rules" / "safe"
LANGUAGES = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT}
TOLERANCE = 2

# The rule ids that answer each planted CWE of the sample application.
EXPECTED = {
    89: {"python.sqli.cursor-execute-concat"},
    78: {"python.injection.subprocess-shell", "python.injection.os-command"},
    22: {"javascript.path.fs-from-input", "python.path.file-from-dynamic-path"},
    918: {"javascript.ssrf.request-derived-url", "python.ssrf.request-derived-url"},
    502: {"python.deser.untrusted-load"},
    327: {"python.crypto.weak-hash"},
    329: {"python.crypto.static-iv"},
    862: {"python.authz.route-without-auth-decorator"},
    639: {"python.authz.object-reference-unscoped"},
    79: {"javascript.xss.response-html-from-input"},
}


@pytest.fixture(scope="module")
def hits() -> dict[str, list[tuple[int, str]]]:
    pack = load_pack(PACK_DIR)
    matcher, rules = Matcher.for_packs([pack])
    return scan(matcher, rules, FIXTURE_ROOT / "services")


def scan(matcher: Matcher, rules: list[RuleDef], base: Path) -> dict[str, list[tuple[int, str]]]:
    found: dict[str, list[tuple[int, str]]] = {}
    for path in sorted(base.rglob("*")):
        language = LANGUAGES.get(path.suffix)
        if language is None or "node_modules" in path.parts:
            continue
        data = path.read_bytes()
        parsed = parse(path.name, language, data.decode("utf-8"))
        relative = path.relative_to(base.parent if base.name == "services" else base).as_posix()
        for match in matcher.match_file(parsed, rules):
            line = data[: match.start_byte].count(10) + 1
            found.setdefault(relative, []).append((line, match.rule.id))
    return found


def test_every_planted_weakness_is_found_by_a_shipped_rule(
    hits: dict[str, list[tuple[int, str]]],
) -> None:
    missing = []
    for planted in load_manifest().planted_vulnerabilities:
        wanted = EXPECTED[planted.cwe]
        near = [
            rule
            for line, rule in hits.get(planted.file, [])
            if abs(line - planted.line) <= TOLERANCE and rule in wanted
        ]
        if not near:
            missing.append(planted.id)
    assert missing == []


def test_no_negative_control_is_reported(hits: dict[str, list[tuple[int, str]]]) -> None:
    reported: list[tuple[str, str]] = []
    for control in load_negative_controls():
        reported.extend(
            (control.id, rule)
            for line, rule in hits.get(control.file, [])
            if abs(line - control.line) <= 1
        )
    assert reported == []


def test_the_authorisation_findings_are_hotspots(hits: dict[str, list[tuple[int, str]]]) -> None:
    pack = load_pack(PACK_DIR)
    kinds = {rule.id: rule.kind for rule in pack.rules}
    for items in hits.values():
        for _, rule in items:
            if rule.startswith("python.authz."):
                assert kinds[rule] == "hotspot"


def test_a_clean_set_of_handlers_produces_no_finding() -> None:
    pack = load_pack(PACK_DIR)
    matcher, rules = Matcher.for_packs([pack])
    found = scan(matcher, rules, SAFE)
    assert found == {}
    assert {path.name for path in SAFE.iterdir()} == {"safe_api.py", "safe_web.js"}
