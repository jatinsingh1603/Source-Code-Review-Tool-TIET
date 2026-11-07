"""The disclosure record of a full run over the fixture project (E11-04).

A change that increases what a scan discloses shows up as a diff of the golden file in review.
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
from codekavach.privacy.slicing.metrics import ScanDisclosure
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault
from tests.support.golden import assert_matches_golden
from tests.support.slicing import candidate_at, candidate_id_n
from tests.unit.privacy.slicing.test_context import SPEC, index_for, settings_for

GOLDEN = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "slicing"
    / "context"
    / "disclosure.golden.txt"
)
SCAN = "scan_golden"
# (candidate id, file, line, the symbols the model asks for in turn)
RUN = (
    (candidate_id_n(0), "app/views.py", 7, ("fn_3", "fn_9", "fn_2")),
    (candidate_id_n(1), "app/views.py", 15, ("fn_2",)),
    (candidate_id_n(2), "app/rates.py", 2, ()),
)


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[RestoreEngine]:
    with Vault(tmp_path / "vault.db", KeySource.EPHEMERAL, SecretBytes(b"\x4d" * 32)) as vault:
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


def run(engine: RestoreEngine) -> str:
    settings = settings_for()
    index = index_for(settings)
    disclosure = ScanDisclosure.for_index(index)
    budget = AggregationBudget(100.0)
    lines = []
    for candidate_id, path, line, asks in RUN:
        candidate = candidate_at(path, line, id=candidate_id)
        disclosure.record(
            EnclosingFunctionStrategy().build(candidate, index, budget=SliceBudget(2048)), index
        )
        resolver = ContextResolver(
            candidate=candidate, index=index, disclosure=disclosure, settings=settings
        )
        outcomes = []
        for symbol in asks:
            ask = ContextRequest(kind=ContextKind.CALLEE_BODY, symbol=symbol, reason="needed")
            resolver.resolve(ask, vault=engine, budget=budget)
            outcomes.append(resolver.last_refusal.value if resolver.last_refusal else "expanded")
        lines.append(
            f"candidate {line_label(path, line)}: rounds={resolver.rounds_used} {outcomes}"
        )
    lines.append("")
    lines.extend(f"{label} = {value}" for label, value in disclosure.as_attestation_rows())
    return "\n".join(lines) + "\n"


def line_label(path: str, line: int) -> str:
    return f"{path}:{line}"


def test_the_disclosure_of_the_fixture_run_matches_the_golden_file(engine: RestoreEngine) -> None:
    assert_matches_golden(run(engine), GOLDEN)
