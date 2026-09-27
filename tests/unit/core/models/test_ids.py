import os
import re
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from itertools import pairwise

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError

from codekavach.core.models import ModelError, ids
from codekavach.core.models.ids import (
    UlidFactory,
    decode_ulid,
    encode_ulid,
    id_prefix,
    is_ulid,
    strip_prefix,
    ulid_datetime,
)

VECTORS = [
    (1469918176385, "00" * 10, "01ARYZ6S410000000000000000"),
    (1469918176385, "ff" * 10, "01ARYZ6S41ZZZZZZZZZZZZZZZZ"),
    (0, "00" * 10, "00000000000000000000000000"),
]


@pytest.mark.parametrize(("ts", "rand", "ulid"), VECTORS)
def test_vectors(ts: int, rand: str, ulid: str) -> None:
    assert encode_ulid(ts, bytes.fromhex(rand)) == ulid
    assert decode_ulid(ulid) == (ts, bytes.fromhex(rand))


@pytest.mark.parametrize(
    "value",
    [
        "01ARYZ6S41000000000000000",  # 25 characters
        "01ARYZ6S4100000000000000000",  # 27 characters
        "01aryz6s410000000000000000",  # lower case
        "01ARYZ6S41I000000000000000",  # alias I
        "01ARYZ6S41L000000000000000",  # alias L
        "01ARYZ6S41O000000000000000",  # alias O
        "01ARYZ6S41U000000000000000",  # U is not in the alphabet
        "81ARYZ6S410000000000000000",  # first character above 7
        "",
    ],
)
def test_decode_rejects_invalid(value: str) -> None:
    assert not is_ulid(value)
    with pytest.raises(ModelError):
        decode_ulid(value)


def test_encode_rejects_out_of_range() -> None:
    with pytest.raises(ModelError):
        encode_ulid(1 << 48, bytes(10))
    with pytest.raises(ModelError):
        encode_ulid(-1, bytes(10))
    with pytest.raises(ModelError):
        encode_ulid(0, bytes(9))


def test_ulid_datetime() -> None:
    assert ulid_datetime("01ARYZ6S410000000000000000") == datetime(
        2016, 7, 30, 22, 36, 16, 385000, tzinfo=UTC
    )


@given(st.integers(0, 2**48 - 1), st.binary(min_size=10, max_size=10))
def test_round_trip(ts: int, rand: bytes) -> None:
    assert decode_ulid(encode_ulid(ts, rand)) == (ts, rand)


@given(
    st.tuples(st.integers(0, 2**48 - 1), st.binary(min_size=10, max_size=10)),
    st.tuples(st.integers(0, 2**48 - 1), st.binary(min_size=10, max_size=10)),
)
def test_string_order_matches_value_order(a: tuple[int, bytes], b: tuple[int, bytes]) -> None:
    assert (encode_ulid(*a) < encode_ulid(*b)) == (a < b)


def _frozen(ms: int = 1_700_000_000_000) -> Callable[[], int]:
    return lambda: ms


def test_monotonic_with_frozen_clock() -> None:
    factory = UlidFactory(clock_ms=_frozen())
    values = [factory.new() for _ in range(10_000)]
    assert len(set(values)) == len(values)
    assert all(a < b for a, b in pairwise(values))


def test_monotonic_when_clock_steps_backwards() -> None:
    ticks = iter([2000, 1000, 1500, 3000])
    factory = UlidFactory(clock_ms=lambda: next(ticks))
    values = [factory.new() for _ in range(4)]
    assert values == sorted(values)
    assert len(set(values)) == 4
    assert decode_ulid(values[1])[0] == 2000
    assert decode_ulid(values[3])[0] == 3000


def test_overflow_raises() -> None:
    factory = UlidFactory(clock_ms=_frozen(), entropy=lambda n: b"\xff" * n)
    factory.new()
    with pytest.raises(ModelError, match="overflow"):
        factory.new()


def test_threads_produce_no_duplicates() -> None:
    factory = UlidFactory(clock_ms=_frozen())
    results: list[list[str]] = [[] for _ in range(8)]

    def work(index: int) -> None:
        results[index].extend(factory.new() for _ in range(2000))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    everything = [value for chunk in results for value in chunk]
    assert len(everything) == 16_000
    assert len(set(everything)) == 16_000


CONSTRUCTORS = {
    "proj_": (ids.new_project_id, ids.ProjectIdField),
    "scan_": (ids.new_scan_id, ids.ScanIdField),
    "cand_": (ids.new_candidate_id, ids.CandidateIdField),
    "slice_": (ids.new_slice_id, ids.SliceIdField),
    "pay_": (ids.new_payload_id, ids.PayloadIdField),
    "find_": (ids.new_finding_id, ids.FindingIdField),
}


@pytest.mark.parametrize("prefix", list(CONSTRUCTORS))
def test_constructor_matches_only_its_own_field(prefix: str) -> None:
    make, _ = CONSTRUCTORS[prefix]
    value = make()
    assert id_prefix(value) == prefix
    assert is_ulid(strip_prefix(value))
    for other, (_, field) in CONSTRUCTORS.items():
        adapter: TypeAdapter[str] = TypeAdapter(field)
        if other == prefix:
            assert adapter.validate_python(value) == value
        else:
            with pytest.raises(ValidationError):
                adapter.validate_python(value)


@pytest.mark.parametrize(
    "value",
    [
        "cand_01ARYZ6S410000000000000000",
        "scan_01aryz6s410000000000000000",
        "scan_01ARYZ6S41000000000000000",
        "scan_01ARYZ6S4100000000000000000",
        "scan_81ARYZ6S410000000000000000",
    ],
)
def test_scan_field_rejects(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ids.ScanIdField).validate_python(value)


def test_field_schema_is_string_with_pattern() -> None:
    schema = TypeAdapter(ids.ScanIdField).json_schema()
    assert schema["type"] == "string"
    assert re.fullmatch(schema["pattern"], "scan_01ARYZ6S410000000000000000")


def test_prefix_helpers_reject_unprefixed() -> None:
    with pytest.raises(ModelError):
        id_prefix("01ARYZ6S410000000000000000")


if sys.platform != "win32":  # os.fork does not exist on Windows

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="os.fork is not available on this platform")
    def test_fork_gives_disjoint_ids(monkeypatch: pytest.MonkeyPatch) -> None:  # pragma: no cover
        monkeypatch.setattr(ids._default_factory, "_clock_ms", _frozen())
        ids.new_ulid()
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            child = "\n".join(ids.new_ulid() for _ in range(100))
            os.write(write_fd, child.encode())
            os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        parent = {ids.new_ulid() for _ in range(100)}
        chunks = []
        while chunk := os.read(read_fd, 65536):
            chunks.append(chunk)
        os.close(read_fd)
        os.waitpid(pid, 0)
        child_ids = set(b"".join(chunks).decode().split("\n"))
        assert len(child_ids) == 100
        assert parent.isdisjoint(child_ids)
