"""The L1 versus L3 differential: minimisation must not quietly cost reviewed findings (E28-03).

The sample application is scanned at L1 (whole files, names kept) and at L3 (the minimal slice)
with the deterministic offline mock provider, so a change in the result means the privacy layer
changed, not a model. Findings are compared by their stable fingerprint, per CWE bucket: reviewed
at both levels, reviewed at L1 only, reviewed at L3 only. The expected counts and a tolerance band
live in ``tests/golden/privacy/level_differential.json``; a count outside the band fails and the
message names the fingerprints that appeared or disappeared.

This is a canary for refactors inside the repository, not a published result: the scientific
comparison across levels and models belongs to the detection harness.
"""

import json
import os
from collections import Counter
from pathlib import Path

import pytest

from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.select import StrategySelector
from tests.integration.test_privacy_pipeline import (  # noqa: F401 - fixtures used by name
    Run,
    copy_fixture,
    no_sockets,
    run_and_capture,
    vault_passphrase,
)

pytestmark = [pytest.mark.privacy, pytest.mark.integration, pytest.mark.slow]

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "privacy" / "level_differential.json"


def _reviewed(run: Run) -> dict[str, str]:
    """Fingerprint to CWE bucket of every finding the model reviewed."""
    out: dict[str, str] = {}
    for finding in run.findings:
        if finding.provenance.llm_reviews:
            out[finding.fingerprint] = f"CWE-{finding.primary_cwe}" if finding.cwe else "none"
    return out


def _level(level: str) -> dict[str, object]:
    return {"privacy": {"level": level, "min_level": "L1"}}


def differential(l1: dict[str, str], l3: dict[str, str]) -> dict[str, dict[str, int]]:
    """Per CWE bucket: ``both``, ``l1_only`` and ``l3_only`` counts."""
    buckets: dict[str, Counter[str]] = {}
    for fingerprint in set(l1) | set(l3):
        cwe = l1.get(fingerprint) or l3[fingerprint]
        side = (
            "both"
            if fingerprint in l1 and fingerprint in l3
            else ("l1_only" if fingerprint in l1 else "l3_only")
        )
        buckets.setdefault(cwe, Counter())[side] += 1
    return {
        cwe: {k: counts[k] for k in ("both", "l1_only", "l3_only")}
        for cwe, counts in sorted(buckets.items())
    }


def check_band(
    observed: dict[str, dict[str, int]], golden: dict[str, object], moved: list[str]
) -> list[str]:
    """Problems: every bucket count must be within ``tolerance`` of the golden value."""
    tolerance = int(golden["tolerance"])  # type: ignore[call-overload]
    expected: dict[str, dict[str, int]] = golden["buckets"]  # type: ignore[assignment]
    problems = []
    for cwe in sorted(set(expected) | set(observed)):
        for side in ("both", "l1_only", "l3_only"):
            want = expected.get(cwe, {}).get(side, 0)
            got = observed.get(cwe, {}).get(side, 0)
            if abs(want - got) > tolerance:
                problems.append(f"{cwe} {side}: expected {want}±{tolerance}, observed {got}")
    if problems:
        problems.append("fingerprints reviewed at one level only: " + ", ".join(sorted(moved)))
    return problems


def _scan_both(tmp_path: Path) -> tuple[dict[str, str], dict[str, str]]:
    l1 = run_and_capture(copy_fixture(tmp_path / "l1"), overrides=_level("L1"))
    l3 = run_and_capture(copy_fixture(tmp_path / "l3"), overrides=_level("L3"))
    return _reviewed(l1), _reviewed(l3)


def test_l1_and_l3_review_the_same_findings_within_the_band(tmp_path: Path) -> None:
    l1, l3 = _scan_both(tmp_path)
    observed = differential(l1, l3)
    if os.environ.get("CODEKAVACH_UPDATE_GOLDEN") == "1" and not os.environ.get("CI"):
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        body = {"tolerance": 0, "buckets": observed}  # the mock is deterministic
        GOLDEN.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    moved = sorted(set(l1) ^ set(l3))
    assert check_band(observed, golden, moved) == []


def test_an_over_aggressive_slice_setting_breaks_the_band_and_names_the_fingerprints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slicer that refuses every L3 slice removes the L3 reviews; the check must say so."""
    l1 = _reviewed(run_and_capture(copy_fixture(tmp_path / "l1"), overrides=_level("L1")))
    real_build = StrategySelector.build

    def starved(self: StrategySelector, candidate: object, index: object, *, budget: SliceBudget):  # type: ignore[no-untyped-def]
        return real_build(self, candidate, index, budget=SliceBudget(1))  # type: ignore[arg-type]

    monkeypatch.setattr(StrategySelector, "build", starved)
    l3 = _reviewed(run_and_capture(copy_fixture(tmp_path / "l3"), overrides=_level("L3")))
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    moved = sorted(set(l1) ^ set(l3))
    problems = check_band(differential(l1, l3), golden, moved)
    assert problems
    assert moved
    assert all(fingerprint in problems[-1] for fingerprint in moved)
