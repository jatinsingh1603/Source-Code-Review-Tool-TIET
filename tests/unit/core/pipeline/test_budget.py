import threading

import pytest

from codekavach.core.pipeline.budget import LLM_REQUESTS, Budget, BudgetExceededError


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_limit_refuses_without_recording() -> None:
    budget = Budget({LLM_REQUESTS: 10})
    assert budget.charge(LLM_REQUESTS, 6) == 6
    with pytest.raises(BudgetExceededError) as error:
        budget.charge(LLM_REQUESTS, 5)
    assert (error.value.name, error.value.limit) == (LLM_REQUESTS, 10)
    assert budget.used(LLM_REQUESTS) == 6
    assert budget.remaining(LLM_REQUESTS) == 4
    assert budget.try_charge(LLM_REQUESTS, 4) is True
    assert budget.try_charge(LLM_REQUESTS, 1) is False
    assert budget.snapshot() == {LLM_REQUESTS: 10}


def test_unlimited_names_are_counted() -> None:
    budget = Budget()
    budget.charge("llm.input_tokens", 7)
    assert budget.remaining("llm.input_tokens") is None
    assert budget.used("never") == 0


def test_invalid_amounts() -> None:
    with pytest.raises(ValueError, match="negative"):
        Budget().charge("x", -1)
    with pytest.raises(ValueError, match="negative"):
        Budget({"x": -1})
    with pytest.raises(ValueError, match="negative"):
        Budget(wall_seconds=-1)


def test_wall_clock() -> None:
    clock = Clock()
    budget = Budget(wall_seconds=30, monotonic=clock)
    assert budget.remaining_seconds() is None
    assert not budget.deadline_exceeded()
    budget.start()
    clock.now += 10
    budget.start()
    assert budget.remaining_seconds() == 20
    clock.now += 20
    assert budget.deadline_exceeded()
    assert Budget().remaining_seconds() is None


def test_concurrent_charges() -> None:
    budget = Budget()

    def charge() -> None:
        for _ in range(1000):
            budget.charge("counter", 1)

    threads = [threading.Thread(target=charge) for _ in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert budget.used("counter") == 32000


def test_concurrent_limit_is_never_exceeded() -> None:
    budget = Budget({"counter": 500})
    accepted: list[bool] = []
    lock = threading.Lock()

    def charge() -> None:
        for _ in range(100):
            ok = budget.try_charge("counter", 1)
            with lock:
                accepted.append(ok)

    threads = [threading.Thread(target=charge) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert budget.used("counter") == 500
    assert accepted.count(True) == 500
