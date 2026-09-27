"""Helpers for performance budget tests (marker ``perf``)."""

import os
import time
from collections.abc import Callable

FACTOR_VARIABLE = "CODEKAVACH_PERF_FACTOR"


def perf_factor() -> float:
    """Return the budget multiplier from CODEKAVACH_PERF_FACTOR (default 1.0)."""
    raw = os.environ.get(FACTOR_VARIABLE)
    if raw is None or raw.strip() == "":
        return 1.0
    try:
        factor = float(raw)
    except ValueError:
        raise ValueError(f"{FACTOR_VARIABLE} must be a positive number, got {raw!r}") from None
    if not factor > 0:
        raise ValueError(f"{FACTOR_VARIABLE} must be a positive number, got {raw!r}")
    return factor


def budget(seconds: float) -> float:
    """Return a time budget scaled by the performance factor."""
    return seconds * perf_factor()


def measure(fn: Callable[[], object], *, repeat: int = 3) -> float:
    """Return the best wall-clock time in seconds of ``repeat`` calls to ``fn``."""
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best
