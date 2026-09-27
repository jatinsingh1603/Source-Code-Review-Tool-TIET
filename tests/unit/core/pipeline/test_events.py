import dataclasses
import io
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.pipeline.events import (
    EVENT_TYPES,
    TOKEN_PATTERN,
    Event,
    EventBus,
    InMemoryEventBus,
    ItemFailed,
    NullEventBus,
    PlanResolved,
    ScanCancelled,
    ScanFinished,
    ScanStarted,
    StageFailed,
    StageFinished,
    StageProgress,
    StageSkipped,
    StageStarted,
    WarningRaised,
)
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).parent / "golden" / "events.json"
AT = datetime(2026, 9, 24, 10, 0, tzinfo=UTC)
SCAN = "scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P"


def samples() -> list[Event]:
    return [
        ScanStarted(scan_id=SCAN, at=AT, stage_count=10),
        PlanResolved(scan_id=SCAN, at=AT, stages=("ingest", "parse"), wave_sizes=(1, 1)),
        StageStarted(scan_id=SCAN, at=AT, stage="parse", index=2, total=10),
        StageProgress(scan_id=SCAN, at=AT, stage="parse", current=3, total=None, unit="files"),
        StageFinished(
            scan_id=SCAN,
            at=AT,
            stage="parse",
            outcome="succeeded",
            duration_ms=842,
            items_in=128,
            items_out=128,
        ),
        StageFailed(
            scan_id=SCAN,
            at=AT,
            stage="llm-review",
            policy="fail_closed",
            error_code="egress_refused",
            error_type="TimeoutError",
            duration_ms=5,
        ),
        StageSkipped(
            scan_id=SCAN, at=AT, stage="restore", reason_code="blocked", blocked_by="llm-review"
        ),
        ItemFailed(
            scan_id=SCAN, at=AT, stage="llm-review", item_id="cand_01ARYZ6S41", error_code="timeout"
        ),
        WarningRaised(scan_id=SCAN, at=AT, code="mock_provider_in_use"),
        ScanCancelled(scan_id=SCAN, at=AT, stages_completed=3),
        ScanFinished(scan_id=SCAN, at=AT, status="succeeded", duration_ms=9000, findings_total=4),
    ]


def test_every_class_is_registered_and_frozen() -> None:
    events = samples()
    assert {type(event) for event in events} == set(EVENT_TYPES.values())
    for event in events:
        assert EVENT_TYPES[event.kind] is type(event)
        with pytest.raises(dataclasses.FrozenInstanceError):
            event.seq = 5  # type: ignore[misc]


def test_to_dict_golden() -> None:
    dumped = [event.to_dict() for event in samples()]
    text = json.dumps(dumped, indent=2) + "\n"
    assert_matches_golden(text, GOLDEN)


def is_plain(value: Any) -> bool:
    if isinstance(value, list):
        return all(isinstance(item, (str, int)) and not isinstance(item, bool) for item in value)
    return value is None or isinstance(value, (str, int, bool))


def test_to_dict_is_json_safe() -> None:
    for event in samples():
        dumped = event.to_dict()
        json.dumps(dumped)
        assert all(is_plain(value) for value in dumped.values())
        assert dumped["event"] == event.kind
        assert dumped["at"] == "2026-09-24T10:00:00Z"
    assert "total" not in samples()[3].to_dict()


def test_example() -> None:
    bus = InMemoryEventBus()
    seen: list[dict[str, Any]] = []
    bus.subscribe(lambda event: seen.append(event.to_dict()))
    bus.publish(
        StageFinished(
            scan_id=SCAN,
            at=AT,
            stage="parse",
            outcome="succeeded",
            duration_ms=842,
            items_in=128,
            items_out=128,
        )
    )
    assert seen == [
        {
            "event": "stage.finished",
            "seq": 1,
            "scan_id": SCAN,
            "at": "2026-09-24T10:00:00Z",
            "stage": "parse",
            "outcome": "succeeded",
            "duration_ms": 842,
            "items_in": 128,
            "items_out": 128,
        }
    ]


@pytest.mark.parametrize(
    "bad", ["src/app.py", "two words", 'quo"te', "it's", "line\nbreak", "x" * 65, ""]
)
def test_bad_strings_rejected_without_echo(bad: str) -> None:
    with pytest.raises(ValueError, match="'unit'") as error:
        StageProgress(scan_id="scan_x", stage="parse", current=1, total=None, unit=bad)
    if bad:
        assert bad not in str(error.value)


def test_other_invalid_fields() -> None:
    with pytest.raises(ValueError, match="duration_ms"):
        StageFinished(scan_id=SCAN, stage="parse", outcome="cached", duration_ms=-1)
    with pytest.raises(ValueError, match="outcome"):
        StageFinished(scan_id=SCAN, stage="parse", outcome="failed", duration_ms=1)
    with pytest.raises(ValueError, match="stages"):
        PlanResolved(scan_id=SCAN, stages=("ok", "not ok"), wave_sizes=(1,))
    with pytest.raises(ValueError, match="'at'"):
        ScanStarted(scan_id=SCAN, at=datetime(2026, 1, 1), stage_count=1)  # noqa: DTZ001
    with pytest.raises(ValueError, match="stage_count"):
        ScanStarted(scan_id=SCAN, stage_count=True)


def string_fields(cls: type[Event]) -> list[str]:
    return [item.name for item in dataclasses.fields(cls) if "str" in str(item.type)]


@given(st.text(min_size=1, max_size=80).filter(lambda text: not TOKEN_PATTERN.match(text)))
def test_property_every_string_field_rejects_bad_text(bad: str) -> None:
    for event in samples():
        for name in string_fields(type(event)):
            with pytest.raises(ValueError, match=repr(name)):
                target: Any = event
                dataclasses.replace(target, **{name: bad})


def test_subscribe_unsubscribe() -> None:
    bus = InMemoryEventBus()
    first: list[int] = []
    second: list[int] = []
    stop_first = bus.subscribe(lambda event: first.append(event.seq))
    bus.subscribe(lambda event: second.append(event.seq))
    bus.publish(ScanCancelled(scan_id=SCAN, stages_completed=0))
    stop_first()
    stop_first()
    bus.publish(ScanCancelled(scan_id=SCAN, stages_completed=0))
    assert (first, second) == ([1], [1, 2])


def test_handler_unsubscribing_itself() -> None:
    bus = InMemoryEventBus()
    calls: list[str] = []
    holder: list[Any] = []

    def once(event: Event) -> None:
        calls.append("once")
        holder[0]()

    holder.append(bus.subscribe(once))
    bus.subscribe(lambda event: calls.append("after"))
    bus.publish(ScanCancelled(scan_id=SCAN, stages_completed=0))
    bus.publish(ScanCancelled(scan_id=SCAN, stages_completed=0))
    assert calls == ["once", "after", "after"]


def test_raising_handler_is_isolated(log_output: io.StringIO) -> None:
    bus = InMemoryEventBus()
    seen: list[int] = []

    def broken(event: Event) -> None:
        raise RuntimeError("SECRETMESSAGE from client code")

    bus.subscribe(broken)
    bus.subscribe(lambda event: seen.append(event.seq))
    bus.publish(ScanCancelled(scan_id=SCAN, stages_completed=0))
    assert seen == [1]
    output = log_output.getvalue()
    assert "event_handler_failed" in output
    assert "RuntimeError" in output
    assert "SECRETMESSAGE" not in output


def test_null_bus() -> None:
    bus: EventBus = NullEventBus()
    unsubscribe = bus.subscribe(lambda event: None)
    bus.publish(ScanCancelled(scan_id=SCAN, stages_completed=0))
    unsubscribe()


def test_concurrent_publishers() -> None:
    bus = InMemoryEventBus()
    received: list[int] = []
    lock = threading.Lock()

    def count(event: Event) -> None:
        with lock:
            received.append(event.seq)

    bus.subscribe(count)
    event = StageProgress(scan_id=SCAN, stage="parse", current=1, unit="files")

    def publish() -> None:
        for _ in range(1000):
            bus.publish(event)

    threads = [threading.Thread(target=publish) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(received) == list(range(1, 8001))
