"""``AggregateStage``: exact-fingerprint deduplication and a stable order (E13-01, ruling O-6)."""

import random

from codekavach.analysis.aggregate.stage import AggregateStage, aggregate
from codekavach.core.models import Candidate
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from tests.support.factories import make_candidate, make_location

FP_A = "ckfp1:" + "a" * 32
FP_B = "ckfp1:" + "b" * 32
FP_C = "ckfp1:" + "c" * 32
FP_D = "ckfp1:" + "d" * 32


def candidate(path: str, line: int, rule: str, fingerprint: str, engine: str = "x") -> Candidate:
    return make_candidate(
        rule_id=rule,
        engine=engine,
        fingerprint=fingerprint,
        taint_path=None,
        locations=(make_location(path=path, start_line=line, end_line=line),),
    )


def test_the_stage_declares_the_contract_of_the_pipeline_table() -> None:
    info = describe_stage(AggregateStage())
    assert info.name == "aggregate"
    assert info.requires == {keys.CANDIDATES_RAW}
    assert info.provides == {keys.CANDIDATES}
    assert info.optional_requires == frozenset()
    assert info.category is StageCategory.AGGREGATE
    assert info.failure_policy is FailurePolicy.ABORT_SCAN


def test_the_order_is_path_then_line_then_rule() -> None:
    items = [
        candidate("b.py", 1, "r", FP_A),
        candidate("a.py", 9, "r", FP_B),
        candidate("a.py", 2, "z", FP_C),
        candidate("a.py", 2, "a", FP_D),
    ]
    ordered = aggregate(items)
    assert [
        (c.primary_location.path, c.primary_location.start_line, c.rule_id) for c in ordered
    ] == [
        ("a.py", 2, "a"),
        ("a.py", 2, "z"),
        ("a.py", 9, "r"),
        ("b.py", 1, "r"),
    ]


def test_the_order_does_not_depend_on_the_input_order() -> None:
    items = [candidate(f"f{i % 3}.py", i, "r", "ckfp1:" + f"{i:032x}") for i in range(1, 13)]
    expected = [c.fingerprint for c in aggregate(items)]
    for seed in range(5):
        shuffled = list(items)
        random.Random(seed).shuffle(shuffled)  # noqa: S311 - a seeded shuffle in a test
        assert [c.fingerprint for c in aggregate(shuffled)] == expected


def test_same_fingerprint_from_different_matchers_is_kept_once() -> None:
    first = candidate("a.py", 3, "py.sql-injection", FP_A, engine="codekavach.rules")
    second = candidate("a.py", 3, "other.sql", FP_A, engine="other-engine")
    kept = aggregate([first, second])
    assert kept == [first]
    assert aggregate([second, first]) == [second]  # the first one seen wins, nothing is merged


def test_distinct_fingerprints_are_all_kept() -> None:
    items = [candidate("a.py", n, "r", "ckfp1:" + f"{n:032x}") for n in range(1, 5)]
    assert len(aggregate(items)) == 4
    assert aggregate([]) == []
