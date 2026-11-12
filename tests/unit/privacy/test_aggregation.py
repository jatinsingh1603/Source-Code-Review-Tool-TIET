"""Exposure account and budget (E26-01)."""

from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from codekavach.privacy.egress.aggregation import AggregationBudget, ExposureAccount
from tests.support.payload import segment, slice_of


def _slice(path: str, start: int, count: int):  # type: ignore[no-untyped-def]
    return slice_of(segment(path, start, ["x = 1"] * count))


def test_union_not_sum() -> None:
    account = ExposureAccount(1000)
    account.record("s1", "p", _slice("a.py", 1, 10))
    account.record("s1", "p", _slice("a.py", 5, 10))
    snap = account.snapshot("p", scope="scan", scan_id="s1")
    assert (snap.files, snap.lines) == (1, 14)
    assert abs(snap.pct - 1.4) < 1e-9


def test_engagement_spans_scans_and_providers_are_separate() -> None:
    account = ExposureAccount(100)
    account.record("s1", "p", _slice("a.py", 1, 10))
    account.record("s2", "p", _slice("b.py", 1, 10))
    account.record("s2", "q", _slice("c.py", 1, 5))
    assert account.snapshot("p", scope="engagement").lines == 20
    assert account.snapshot("p", scope="scan", scan_id="s2").lines == 10
    assert account.snapshot("q", scope="engagement").lines == 5


def test_budget_refuses_before_disclosure() -> None:
    account = ExposureAccount(100)
    account.record("s1", "p", _slice("a.py", 1, 10))
    budget = AggregationBudget(scan_pct=15.0)
    assert not account.would_exceed(budget, "s1", "p", _slice("a.py", 1, 10))  # already covered
    assert account.would_exceed(budget, "s1", "p", _slice("b.py", 1, 10))
    assert not account.would_exceed(AggregationBudget(), "s1", "p", _slice("b.py", 1, 90))


def test_engagement_ceiling_counts_earlier_scans() -> None:
    account = ExposureAccount(100)
    account.record("s1", "p", _slice("a.py", 1, 10))
    budget = AggregationBudget(engagement_pct=15.0)
    assert account.would_exceed(budget, "s2", "p", _slice("b.py", 1, 10))
    assert not account.would_exceed(budget, "s2", "p", _slice("b.py", 1, 3))


def test_persisted_account_is_path_free(tmp_path: Path) -> None:
    file = tmp_path / "exposure.json"
    account = ExposureAccount(100, path=file)
    account.record("s1", "p", _slice("secret/payments/card.py", 1, 10))
    account.save()
    assert "payments" not in file.read_text()
    assert oct(file.stat().st_mode & 0o777) == "0o600"
    again = ExposureAccount(100, path=file)
    assert again.snapshot("p", scope="engagement").lines == 10


@given(st.lists(st.tuples(st.integers(1, 50), st.integers(1, 20)), max_size=8))
def test_lines_never_exceed_distinct_lines(spans: list[tuple[int, int]]) -> None:
    account = ExposureAccount(10_000)
    for start, count in spans:
        account.record("s", "p", _slice("a.py", start, count))
    assert account.snapshot("p", scope="scan", scan_id="s").lines <= 70
