"""Performance budgets of the egress leak scanners (E12-02).

The four matching scanners (vault originals, domain terms, size and rate, aggregation) run over a
256 KB body, with a vault automaton of 50 000 originals, in under 40 ms; building that automaton
takes under 2 s and happens once, before the first request.

The two scanners that run the E08 detectors again (residual secrets and personal data) are
bounded by those detectors: they are 17 regular-expression passes over the body, about 125 ms
here for 256 KB, so the issue's 40 ms for all six is not reachable without a faster detector
engine (follow-up issue). They get their own budget, stated here so that a regression shows.
Budgets are scaled by the performance factor.
"""

import json
import random
import string
from collections.abc import Iterator

import pytest

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel
from codekavach.privacy.egress.guard import ScannerRegistry
from codekavach.privacy.egress.models import EgressMeta
from codekavach.privacy.egress.scanners import (
    VaultOriginalScanner,
    register_default_scanners,
    release,
    warm,
)
from codekavach.privacy.slicing.metrics import ScanDisclosure
from tests.support.perf import assert_within_budget, measure

SCAN_BUDGET_SECONDS = 0.040
DETECTOR_BUDGET_SECONDS = 0.300
DETECTOR_IDS = frozenset({"residual_pii", "residual_secret"})
BUILD_BUDGET_SECONDS = 2.0
ORIGINALS = 50_000
BODY_BYTES = 256 * 1024
META = EgressMeta(provider="hosted", model="m", level=PrivacyLevel.L3, payload_hash="0" * 64)


class Vault:
    def __init__(self, originals: list[str]) -> None:
        self.originals = originals

    def iter_originals(self, *, min_len: int = 4) -> Iterator[str]:
        yield from (item for item in self.originals if len(item) >= min_len)

    def original_count(self, min_len: int = 4) -> int:
        return len(self.originals)


def originals() -> list[str]:
    rng = random.Random(7)  # noqa: S311 - a reproducible test corpus
    return [
        "zq" + "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(6, 22)))
        for _ in range(ORIGINALS)
    ]


def body() -> bytes:
    unit = 'def fn_1(var_1):\n    cur.execute("SELECT * FROM t_1 WHERE a = " + var_2)\n'
    text = (unit * (BODY_BYTES // len(unit) + 1))[: BODY_BYTES * 9 // 10]
    return json.dumps({"payload": text}).encode("utf-8")


@pytest.fixture(scope="module")
def names() -> list[str]:
    return originals()


@pytest.mark.perf
def test_building_the_automaton_for_50000_originals_stays_within_budget(names: list[str]) -> None:
    vault, config = Vault(names), Settings()

    def build() -> None:
        scanner = VaultOriginalScanner()
        scanner.warm(vault, config)
        scanner.release()

    assert_within_budget(
        measure(build, repeat=1), BUILD_BUDGET_SECONDS, label="vault automaton build, 50000"
    )


def run(names: list[str], *, detectors: bool) -> tuple[float, int]:
    config = Settings.model_validate({"privacy": {"domain_terms": ["Phoenix Ledger"]}})
    registry = register_default_scanners(ScannerRegistry(), ScanDisclosure(repo_lines=1000))
    warm(registry, Vault(names), config)
    data = body()
    assert len(data) <= BODY_BYTES
    chosen = [item for item in registry if (item.id in DETECTOR_IDS) is detectors]

    def scan_all() -> None:
        for scanner in chosen:
            hits = scanner.scan(data, META)
            assert not hits or scanner.id == "budget"

    try:
        return measure(scan_all), len(chosen)
    finally:
        release(registry)


@pytest.mark.perf
def test_the_four_matching_scanners_scan_a_256_kb_body_within_budget(names: list[str]) -> None:
    seconds, count = run(names, detectors=False)
    assert count == 4
    assert_within_budget(seconds, SCAN_BUDGET_SECONDS, label="matching scanners, 50000 originals")


@pytest.mark.perf
def test_the_two_detector_scanners_scan_a_256_kb_body_within_budget(names: list[str]) -> None:
    seconds, count = run(names, detectors=True)
    assert count == 2
    assert_within_budget(seconds, DETECTOR_BUDGET_SECONDS, label="detector scanners")
