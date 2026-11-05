"""Performance budget of the pseudonym generator (E09-01).

Generation happens per candidate and a scan may have thousands, so a call stays under 5
microseconds after warm-up and a slice of 200 distinct identifiers under 2 milliseconds. The
budgets are scaled by the performance factor.
"""

import pytest

from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator, PseudonymKind
from tests.support.perf import assert_within_budget, measure

SALT = ScanSalt(b"\x5a" * 32)
CALLS = 10_000
PER_CALL_BUDGET_SECONDS = 0.000_005
SLICE_BUDGET_SECONDS = 0.002
NAMES = [f"identifier_{index}" for index in range(200)]


@pytest.mark.perf
def test_a_warm_token_stays_within_budget() -> None:
    generator = PseudonymGenerator(SALT)
    generator.prepare(PseudonymKind.VAR, NAMES)

    def many() -> None:
        for _ in range(CALLS // len(NAMES)):
            for name in NAMES:
                generator.token(PseudonymKind.VAR, name)

    assert_within_budget(measure(many, repeat=5) / CALLS, PER_CALL_BUDGET_SECONDS)


@pytest.mark.perf
def test_a_slice_of_200_identifiers_stays_within_budget() -> None:
    def one_slice() -> None:
        generator = PseudonymGenerator(SALT)
        generator.prepare(PseudonymKind.VAR, NAMES)
        for name in NAMES:
            generator.token(PseudonymKind.VAR, name)

    assert_within_budget(measure(one_slice, repeat=10), SLICE_BUDGET_SECONDS)
