"""The whole-file unit of levels L1 and L2 (E25-02): whole files, and the budget fallback."""

import pytest

from codekavach.core.models import PrivacyLevel, SegmentRole, SliceStrategy
from codekavach.privacy.levels import plan_for
from codekavach.privacy.slicing.base import SlicingError
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.select import UNIT_CHAIN, StrategySelector
from codekavach.privacy.slicing.strategies.wholefile import WholeFileStrategy
from tests.support.slicing import candidate_at, make_index

BIG = SliceBudget(100_000)
SERVICE = '''"""Accounts."""

import os


def helper(value):
    # normalise the value before it is used
    return value.strip()


def accrue(db, account_id):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM t WHERE id = '%s'" % account_id)
    return cursor.fetchone()
'''
OTHER = "def unused():\n    return 1\n"


def test_the_whole_file_is_one_primary_segment() -> None:
    index = make_index({"svc.py": SERVICE, "other.py": OTHER})
    slice_ = WholeFileStrategy().build(candidate_at("svc.py", 13), index, budget=BIG)
    assert slice_.strategy is SliceStrategy.WHOLE_FILE
    assert len(slice_.segments) == 1
    segment = slice_.segments[0]
    assert segment.role is SegmentRole.PRIMARY
    assert segment.text.expose() == SERVICE.strip("\n")
    assert "# normalise the value" in segment.text.expose()
    assert not slice_.truncated


def test_every_file_of_the_candidate_is_taken_once() -> None:
    index = make_index({"svc.py": SERVICE, "other.py": OTHER})
    candidate = candidate_at("svc.py", 13, ("other.py", 2), ("svc.py", 7))
    slice_ = WholeFileStrategy().build(candidate, index, budget=BIG)
    assert [s.path for s in slice_.segments] == ["svc.py", "other.py"]
    assert [s.role for s in slice_.segments] == [SegmentRole.PRIMARY, SegmentRole.CONTEXT]


def test_a_file_over_the_budget_is_refused_as_curable() -> None:
    index = make_index({"svc.py": SERVICE})
    with pytest.raises(SlicingError) as refused:
        WholeFileStrategy().build(candidate_at("svc.py", 13), index, budget=SliceBudget(40))
    assert refused.value.reason == "over_budget"


def test_never_send_is_refused_at_once() -> None:
    index = make_index({"svc.py": SERVICE}, never_send=lambda path: path == "svc.py")
    with pytest.raises(SlicingError) as refused:
        WholeFileStrategy().build(candidate_at("svc.py", 13), index, budget=BIG)
    assert refused.value.reason != "over_budget"


def test_l1_and_l2_select_the_whole_file_and_fall_back_with_a_reason() -> None:
    for level in (PrivacyLevel.L1, PrivacyLevel.L2):
        assert plan_for(level).strategy_ceiling is SliceStrategy.WHOLE_FILE
    assert plan_for(PrivacyLevel.L3).strategy_ceiling is None
    assert UNIT_CHAIN[0] is SliceStrategy.WHOLE_FILE
    index = make_index({"svc.py": SERVICE})
    selector = StrategySelector(ceiling=SliceStrategy.WHOLE_FILE)
    whole = selector.build(candidate_at("svc.py", 13), index, budget=BIG)
    assert whole.strategy is SliceStrategy.WHOLE_FILE
    assert whole.fallback_reason is None
    small = selector.build(candidate_at("svc.py", 13), index, budget=SliceBudget(60))
    assert small.strategy is not SliceStrategy.WHOLE_FILE
    assert small.fallback_reason == "over_budget"
    assert "helper" not in "".join(s.text.expose() for s in small.segments)


def test_the_whole_file_is_deterministic() -> None:
    index = make_index({"svc.py": SERVICE})
    first = WholeFileStrategy().build(candidate_at("svc.py", 13), index, budget=BIG)
    second = WholeFileStrategy().build(candidate_at("svc.py", 13), index, budget=BIG)
    assert first == second
