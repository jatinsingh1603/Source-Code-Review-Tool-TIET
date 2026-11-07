"""Performance budget of restoration (E10-02).

Restoring a verdict of about 2 000 characters with 30 distinct tokens takes under 5 ms, excluding
vault lookups, which are batched into one query. The vault is replaced by an in-memory stub here,
so the measurement is the engine alone. The budget is scaled by the performance factor.
"""

from typing import cast

import pytest

from codekavach.privacy.restore.engine import RestoreEngine
from codekavach.privacy.vault.store import Vault
from tests.support.factories import make_payload, make_slice, make_verdict
from tests.support.perf import assert_within_budget, measure

BUDGET_SECONDS = 0.005
TOKENS = 30


class StubVault:
    """Answers every lookup from a dict, so only the engine's own work is timed."""

    def __init__(self, names: dict[str, str]) -> None:
        self._names = names

    def lookup_many(self, pseudonyms: list[str], *, scan_id: str | None = None) -> dict[str, str]:
        return {name: self._names[name] for name in pseudonyms if name in self._names}


def long_reasoning() -> str:
    return " ".join(
        f"Line {number} hands var_{number} to the helper, which is not parameterised here."
        for number in range(1, TOKENS + 1)
    )


@pytest.mark.perf
def test_restoring_a_long_verdict_stays_within_budget() -> None:
    names = {f"var_{number}": f"invoice_total_{number}" for number in range(1, TOKENS + 1)}
    verdict = make_verdict(reasoning=long_reasoning(), impact="", remediation="", cited_lines=(3,))
    assert len(verdict.reasoning) >= 2000
    engine = RestoreEngine(cast(Vault, StubVault(names)), scan_id="scan_perf")
    payload = make_payload()
    slice_ = make_slice()
    engine.restore(verdict, payload, slice_)  # warm the compiled patterns

    def restore() -> None:
        engine.restore(verdict, payload, slice_)

    assert_within_budget(measure(restore, repeat=20), BUDGET_SECONDS, label="restore")


@pytest.mark.perf
def test_thirty_tokens_are_looked_up_in_one_call() -> None:
    calls: list[int] = []

    class CountingVault(StubVault):
        def lookup_many(
            self, pseudonyms: list[str], *, scan_id: str | None = None
        ) -> dict[str, str]:
            calls.append(len(pseudonyms))
            return super().lookup_many(pseudonyms, scan_id=scan_id)

    names = {f"var_{number}": "x" for number in range(1, TOKENS + 1)}
    verdict = make_verdict(
        reasoning=" ".join(f"var_{number}." for number in range(1, TOKENS + 1)),
        impact="",
        remediation="",
        cited_lines=(),
    )
    RestoreEngine(cast(Vault, CountingVault(names)), scan_id="scan_perf").restore(
        verdict, make_payload(), make_slice()
    )
    assert calls == [TOKENS]
