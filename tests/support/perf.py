"""Helpers for performance budget tests (marker ``perf``)."""

import os
import statistics
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


def assert_within_budget(
    measured: float, seconds: float, *, factor: float | None = None, label: str = "measurement"
) -> None:
    """Fail when ``measured`` exceeds ``seconds`` times the factor (by default the environment's).

    The message shows the measured time, the budget and the factor, so a CI log says by how much
    a budget was missed.
    """
    scale = perf_factor() if factor is None else factor
    limit = seconds * scale
    if measured > limit:
        raise AssertionError(
            f"{label}: measured {measured:.3f} s; budget {seconds:.3f} s x factor {scale:g} "
            f"= {limit:.3f} s"
        )


def median_seconds(fn: Callable[[], object], *, repeat: int = 5) -> float:
    """Return the median wall-clock time in seconds of ``repeat`` calls to ``fn``."""
    times: list[float] = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def measurement_line(name: str, median_s: float, target_ms: float, limit_ms: float) -> str:
    """One log line per measurement: ``name median_ms target_ms limit_ms``."""
    return f"{name} {median_s * 1000:.1f} {target_ms:g} {limit_ms:g}"
