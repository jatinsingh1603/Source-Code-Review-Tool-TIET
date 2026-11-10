"""Performance budget of the path slices (E11-03).

A backward slice of depth 20 over a function of about 500 lines takes under 30 ms with a warm
parse index (the def-use index of the file is built once). The budget is scaled by the
performance factor.
"""

import pytest

from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.strategies.backward import BackwardSliceStrategy
from codekavach.privacy.slicing.strategies.taintpath import TaintPathStrategy
from tests.support.perf import assert_within_budget, measure
from tests.support.slicing import candidate_at, make_index, taint_candidate

BUDGET_SECONDS = 0.030

BODY = ["def big(req, db):", '    v0 = req.args["x"]']
for number in range(1, 249):
    BODY.append(f"    v{number} = v{number - 1} + 'a'")
    BODY.append(f"    w{number} = v{number} if v{number} else 'b'")
BODY.append("    db.execute(v248)")
SOURCE = "\n".join(BODY) + "\n"


@pytest.mark.perf
def test_a_backward_slice_of_depth_twenty_over_five_hundred_lines() -> None:
    assert len(BODY) >= 495
    index = make_index({"big.py": SOURCE})
    strategy = BackwardSliceStrategy(depth=20)
    candidate = candidate_at("big.py", len(BODY))
    budget = SliceBudget(4096)
    strategy.build(candidate, index, budget=budget)  # warm the per-file caches

    def build() -> None:
        strategy.build(candidate, index, budget=budget)

    assert_within_budget(measure(build, repeat=10), BUDGET_SECONDS, label="backward slice")


@pytest.mark.perf
def test_a_taint_path_slice_over_five_hundred_lines() -> None:
    index = make_index({"big.py": SOURCE})
    strategy = TaintPathStrategy()
    candidate = taint_candidate(("big.py", 2), ("big.py", len(BODY)))
    budget = SliceBudget(4096)
    strategy.build(candidate, index, budget=budget)

    def build() -> None:
        strategy.build(candidate, index, budget=budget)

    assert_within_budget(measure(build, repeat=10), BUDGET_SECONDS, label="taint path slice")
