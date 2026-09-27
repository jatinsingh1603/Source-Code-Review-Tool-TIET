import time
from collections.abc import Iterator

import pytest

from tests.support import perf


@pytest.mark.parametrize(("raw", "expected"), [(None, 1.0), ("2.5", 2.5)])
def test_perf_factor_valid(
    raw: str | None, expected: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    if raw is None:
        monkeypatch.delenv("CODEKAVACH_PERF_FACTOR", raising=False)
    else:
        monkeypatch.setenv("CODEKAVACH_PERF_FACTOR", raw)
    assert perf.perf_factor() == expected


@pytest.mark.parametrize("raw", ["abc", "0", "-1"])
def test_perf_factor_invalid(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEKAVACH_PERF_FACTOR", raw)
    with pytest.raises(ValueError, match="CODEKAVACH_PERF_FACTOR"):
        perf.perf_factor()


def test_budget_multiplies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEKAVACH_PERF_FACTOR", "3")
    assert perf.budget(0.5) == 1.5


def test_measure_returns_minimum(monkeypatch: pytest.MonkeyPatch) -> None:
    # start/end pairs: durations 5, 2 and 4 seconds.
    ticks: Iterator[float] = iter([0.0, 5.0, 10.0, 12.0, 20.0, 24.0])
    monkeypatch.setattr(time, "perf_counter", lambda: next(ticks))
    calls: list[int] = []
    assert perf.measure(lambda: calls.append(1), repeat=3) == 2.0
    assert len(calls) == 3
