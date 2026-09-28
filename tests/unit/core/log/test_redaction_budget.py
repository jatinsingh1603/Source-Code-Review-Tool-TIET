import statistics
import time

import pytest

from codekavach.core.log.redaction import RedactionProcessor
from tests.support.perf import budget

PROCESSOR = RedactionProcessor()
TYPICAL = {
    "event": "stage_finished",
    "level": "info",
    "logger": "codekavach.pipeline",
    "timestamp": "2026-09-24T10:00:00Z",
    "stage": "parse",
    "outcome": "succeeded",
    "duration_ms": 842,
    "files": 128,
    "payload_hash": "3f" * 32,
    "scan_id": "scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P",  # pragma: allowlist secret
}
ADVERSARIAL = ["a" * 100_000, "eyJ" + "A." * 50_000, "password=" + "x" * 100_000]


@pytest.mark.perf
def test_typical_event_budget() -> None:
    costs = []
    for _ in range(2_000):
        started = time.perf_counter()
        PROCESSOR(None, "info", TYPICAL)
        costs.append(time.perf_counter() - started)
    median = statistics.median(costs)
    print(f"median redaction cost: {median * 1e6:.1f} microseconds")  # noqa: T201
    assert median <= budget(0.0005)


@pytest.mark.perf
@pytest.mark.parametrize("text", ADVERSARIAL, ids=["long", "jwt_like", "assignment"])
def test_adversarial_inputs_budget(text: str) -> None:
    started = time.perf_counter()
    PROCESSOR(None, "info", {"event": "e", "note": text, "exception": text})
    elapsed = time.perf_counter() - started
    print(f"adversarial input: {elapsed * 1000:.1f} ms")  # noqa: T201
    assert elapsed <= budget(0.05)
