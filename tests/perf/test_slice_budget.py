"""Performance budget of slicing (E11-01).

Building the slice of one candidate takes under 15 ms with a warm parse index, because a scan may
produce thousands of candidates. The budget is scaled by the performance factor.
"""

import pytest

from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from tests.support.perf import assert_within_budget, measure
from tests.support.slicing import candidate_at, make_index

BUDGET_SECONDS = 0.015

SOURCE = "\n".join(
    ["import os", "import json", "", "", "class Service:", "    def __init__(self, db):"]
    + ["        self.db = db", ""]
    + [
        line
        for number in range(30)
        for line in (
            f"    def method_{number}(self, account_id):",
            "        rate = os.environ.get('RATE')",
            "        if account_id:",
            "            cur = self.db.cursor()",
            f"            cur.run('QUERY {number}', account_id)",
            "            return json.dumps(cur.fetchall())",
            "        return rate",
            "",
        )
    ]
)


@pytest.mark.perf
def test_one_slice_stays_within_budget() -> None:
    index = make_index({"svc.py": SOURCE})
    strategy = EnclosingFunctionStrategy()
    candidate = candidate_at("svc.py", 8 + 8 * 15 + 5)
    budget = SliceBudget(2048)
    strategy.build(candidate, index, budget=budget)  # warm the per-file caches

    def build() -> None:
        strategy.build(candidate, index, budget=budget)

    assert_within_budget(measure(build, repeat=20), BUDGET_SECONDS, label="slice")
