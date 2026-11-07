"""Performance budget of stub generation (E11-02).

Building the stubs of a slice that calls 20 out-of-slice functions takes under 10 ms with a warm
parse index, because a scan may slice thousands of candidates. The budget is scaled by the
performance factor.
"""

import pytest

from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.slicing.stubs import build_stubs
from tests.support.perf import assert_within_budget, measure
from tests.support.slicing import candidate_at, make_index

BUDGET_SECONDS = 0.010
CALLEES = 20

HELPERS = "\n".join(
    f"def helper_{n}(value, scale=2):\n    total = value * scale\n    return total + {n}\n\n"
    for n in range(CALLEES)
)
CALLER = (
    "from app.helpers import *\n\n\nclass Worker:\n    limit: int = 5\n\n"
    "    def run(self, item):\n"
    + "".join(f"        value_{n} = helper_{n}(item)\n" for n in range(CALLEES))
    + "        return self.limit\n"
)
LAST_LINE = CALLER.count("\n")


@pytest.mark.perf
def test_twenty_callees_stay_within_budget() -> None:
    index = make_index({"app/work.py": CALLER, "app/helpers.py": HELPERS})
    strategy = EnclosingFunctionStrategy()
    found = strategy.build(
        candidate_at("app/work.py", LAST_LINE), index, budget=SliceBudget(100_000)
    )
    segments = found.segments
    warm = build_stubs(segments, index, candidate_path="app/work.py", candidate_line=LAST_LINE)
    assert len(warm.stubs) >= CALLEES  # the callees and the class context

    def build() -> None:
        build_stubs(segments, index, candidate_path="app/work.py", candidate_line=LAST_LINE)

    assert_within_budget(measure(build, repeat=20), BUDGET_SECONDS, label="stubs")
