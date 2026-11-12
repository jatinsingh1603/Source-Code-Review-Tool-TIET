"""Precision and recall of the taint engine against the KavachBank ground truth (E17-03).

The whole sample is analysed as a project (summaries first, then every function), exactly as the
stage does it. A candidate is matched to a planted weakness when its CWE equals the planted CWE
and its primary location lies within ``TOLERANCE`` lines of the planted line in the same file.

Scored classes are the ones a taint engine can see (a source reaching a sink): SQL injection,
command injection, path traversal, SSRF, insecure deserialisation and reflected XSS. Weak
cryptography, missing authorisation and IDOR are rule or semantic findings, not taint flows, and
are outside this measurement.

* recall    = planted weaknesses matched / planted weaknesses in scope,
* precision = candidates matched to a planted weakness / all certain candidates of the scored
  classes (a candidate marked ``taint.uncertain`` is reported separately: it is the engine saying
  it is not sure, and is counted against precision only when it sits on a negative control),
* control hits = candidates on a documented safe variant (negative control).

The numbers are written to ``docs/research/results`` by ``tools/`` or by running this module with
``CODEKAVACH_RECORD_TAINT=1``, and the test asserts floors so a regression is visible.
"""

import json
import os
from collections import defaultdict
from pathlib import Path

import pytest

from codekavach.analysis.rules.loader import load_pack
from codekavach.analysis.taint.catalogue import Binding
from codekavach.analysis.taint.frameworks import entry_seeds
from codekavach.analysis.taint.interproc import ProjectIndex, compute_summaries, make_lookup
from codekavach.analysis.taint.propagate import Budget, propagate_bound
from codekavach.analysis.taint.stage import candidates_for
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Candidate, Language
from codekavach.core.models.text import split_lines
from tests.support.kavachbank import FIXTURE_ROOT, load_manifest, load_negative_controls
from tests.support.taint import lower_source

ROOT = Path(__file__).resolve().parents[3]
RESULTS = ROOT / "docs" / "research" / "results" / "taint-precision-recall-kavachbank.json"
LANGUAGES = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT}
SCORED = {22: "path_traversal", 78: "command_injection", 79: "reflected_xss",
          89: "sql_injection", 502: "insecure_deserialisation", 918: "ssrf"}  # fmt: skip
TOLERANCE = 1
SETTINGS = TaintSettings()


def analyse_project() -> list[Candidate]:
    """Every candidate of the services tree, with interprocedural summaries."""
    catalogues = load_pack(ROOT / "rules" / "mit" / "packs" / "default").catalogues
    index = ProjectIndex()
    bindings: dict[str, Binding] = {}
    lines: dict[str, list[str]] = {}
    languages: dict[str, Language] = {}
    for path in sorted((FIXTURE_ROOT / "services").rglob("*")):
        language = LANGUAGES.get(path.suffix)
        if language is None or "node_modules" in path.parts:
            continue
        relative = path.relative_to(FIXTURE_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        module = lower_source(text, language, path=relative)
        index.add(module)
        bindings[relative] = Binding(catalogues, module.aliases, language.value)
        lines[relative] = split_lines(text)
        languages[relative] = language
    summaries = compute_summaries(index, lambda p: bindings[p], SETTINGS)
    found: list[Candidate] = []
    for relative, module in index.modules.items():
        lookup = make_lookup(index, summaries, relative)
        for function in module.functions:
            flows = propagate_bound(
                function,
                bindings[relative],
                budget=Budget.of(10),
                settings=SETTINGS,
                seeds=entry_seeds(function),
                lookup=lookup,
            )
            found.extend(
                candidates_for(
                    flows, function, lines[relative], languages[relative], relative,
                    SETTINGS.max_path_steps, lines,
                )
            )  # fmt: skip
    return found


def score(found: list[Candidate]) -> dict[str, object]:
    """Per-class and overall counts."""
    manifest = load_manifest()
    planted = [p for p in manifest.planted_vulnerabilities if p.cwe in SCORED]
    controls = [c for c in load_negative_controls() if c.vuln_class in SCORED.values()]

    def near(c: Candidate, file: str, line: int) -> bool:
        loc = c.primary_location
        return loc.path == file and abs(loc.start_line - line) <= TOLERANCE

    scored = [c for c in found if set(c.cwe) & set(SCORED)]
    certain = [c for c in scored if dict(c.properties).get("taint.uncertain") != "true"]
    matched: set[str] = set()
    true_positive: set[int] = set()
    per_class: dict[str, dict[str, int]] = defaultdict(
        lambda: {"planted": 0, "found": 0, "control_hits": 0}
    )
    for item in planted:
        per_class[item.vuln_class]["planted"] += 1
        hits = [c for c in scored if item.cwe in c.cwe and near(c, item.file, item.line)]
        if hits:
            matched.add(item.id)
            per_class[item.vuln_class]["found"] += 1
            true_positive.update(id(c) for c in hits)
    control_hits = 0
    for control in controls:
        hits = [c for c in certain if near(c, control.file, control.line)]
        if hits:
            control_hits += 1
            per_class[control.vuln_class]["control_hits"] += 1
    certain_tp = [c for c in certain if id(c) in true_positive]
    return {
        "planted_in_scope": len(planted),
        "planted_found": len(matched),
        "recall": len(matched) / len(planted),
        "certain_candidates": len(certain),
        "certain_matched": len(certain_tp),
        "precision": len(certain_tp) / len(certain) if certain else 1.0,
        "uncertain_candidates": len(scored) - len(certain),
        "negative_controls": len(controls),
        "negative_control_hits": control_hits,
        "unmatched_certain": sorted(
            f"{c.primary_location.path}:{c.primary_location.start_line}"
            for c in certain
            if id(c) not in true_positive
        ),
        "missed": sorted(p.id for p in planted if p.id not in matched),
        "per_class": {k: per_class[k] for k in sorted(per_class)},
    }


@pytest.fixture(scope="module")
def result() -> dict[str, object]:
    value = score(analyse_project())
    if os.environ.get("CODEKAVACH_RECORD_TAINT") == "1":
        RESULTS.parent.mkdir(parents=True, exist_ok=True)
        RESULTS.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value


def test_recall_floor(result: dict[str, object]) -> None:
    recall = result["recall"]
    assert isinstance(recall, float | int)
    assert recall >= 0.5, result["missed"]


def test_precision_floor(result: dict[str, object]) -> None:
    precision = result["precision"]
    assert isinstance(precision, float | int)
    assert precision >= 0.5, result["unmatched_certain"]
