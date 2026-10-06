"""Start-up time of informational invocations (E05-31).

Median of five runs in fresh interpreters (one discarded warm-up run), scaled by
``CODEKAVACH_PERF_FACTOR`` through ``budget()``. Skipped with ``CODEKAVACH_SKIP_PERF=1``. The
deny-list test (``tests/unit/cli/test_startup_imports.py``) is the precise guard; this one
catches gross regressions.
"""

import os
import statistics
import subprocess
import sys
import time

import pytest

from tests.support.perf import budget

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(
        os.environ.get("CODEKAVACH_SKIP_PERF") == "1", reason="CODEKAVACH_SKIP_PERF"
    ),
]
RUNS = 5


def median_seconds(*argv: str) -> float:
    times = []
    for _ in range(RUNS + 1):
        started = time.perf_counter()
        subprocess.run([sys.executable, "-m", "codekavach", *argv], capture_output=True, check=True)
        times.append(time.perf_counter() - started)
    return statistics.median(times[1:])  # the first run warms the file cache


@pytest.mark.parametrize(("argv", "seconds"), [(("--version",), 0.4), (("--help",), 0.6)])
def test_startup_within_budget(argv: tuple[str, ...], seconds: float) -> None:
    measured = median_seconds(*argv)
    print(f"codekavach {' '.join(argv)}: median {measured * 1000:.0f} ms")  # noqa: T201
    assert measured <= budget(seconds)
