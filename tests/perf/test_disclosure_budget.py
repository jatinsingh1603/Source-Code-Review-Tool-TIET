"""Performance budgets of the disclosure measurement and the context resolver (E11-04).

``measure`` runs for every candidate and stays under 1 ms; ``resolve`` is dominated by slice
construction (E11-01's 15 ms) plus one vault lookup. Both are scaled by the performance factor.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest

from codekavach.core.models import ContextKind, ContextRequest
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.restore.engine import RestoreEngine
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.context import AggregationBudget, ContextResolver
from codekavach.privacy.slicing.metrics import ScanDisclosure, measure
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault
from tests.support.perf import assert_within_budget
from tests.support.perf import measure as time_best
from tests.support.slicing import candidate_at
from tests.unit.privacy.slicing.test_context import SPEC, index_for, settings_for

MEASURE_BUDGET_SECONDS = 0.001
RESOLVE_BUDGET_SECONDS = 0.030  # E11-01's 15 ms for the slice, one vault lookup, headroom
SCAN = "scan_perf"


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[RestoreEngine]:
    with Vault(tmp_path / "vault.db", KeySource.EPHEMERAL, SecretBytes(b"\x3e" * 32)) as vault:
        vault.put(
            MappingBatch(
                SCAN,
                tuple(
                    MappingEntry(token, original, PseudonymKind.FN, "accounts")
                    for token, original in SPEC["mapping"].items()
                ),
            )
        )
        yield RestoreEngine(vault, scan_id=SCAN)


@pytest.mark.perf
def test_measure_stays_under_a_millisecond() -> None:
    settings = settings_for()
    index = index_for(settings)
    sliced = EnclosingFunctionStrategy().build(
        candidate_at("app/views.py", 7), index, budget=SliceBudget(2048)
    )
    measure(sliced, index)  # warm the function-range cache
    assert_within_budget(
        time_best(lambda: measure(sliced, index), repeat=50), MEASURE_BUDGET_SECONDS
    )


@pytest.mark.perf
def test_resolve_stays_within_the_slice_budget_plus_one_lookup(engine: RestoreEngine) -> None:
    settings = settings_for({"privacy": {"slice": {"max_needs_context_rounds": 10}}})
    index = index_for(settings)
    ask = ContextRequest(kind=ContextKind.CALLEE_BODY, symbol="fn_3", reason="needed")

    def once() -> None:
        resolver = ContextResolver(
            candidate=candidate_at("app/views.py", 7),
            index=index,
            disclosure=ScanDisclosure.for_index(index),
            settings=settings,
        )
        assert resolver.resolve(ask, vault=engine, budget=AggregationBudget(100.0)) is not None

    once()
    assert_within_budget(time_best(once, repeat=20), RESOLVE_BUDGET_SECONDS)
