"""The per-item memo (E04-22): keys, hits and misses, damage, salt separation, threads."""

import hashlib
import json
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import BaseModel, JsonValue

from codekavach.core.pipeline import memo as memo_module
from codekavach.core.pipeline.memo import (
    KEY_PATTERN,
    NAMESPACE_PATTERN,
    DiskItemMemo,
    MemoStats,
    NullMemo,
    check_arguments,
    memo_key,
)
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.base import ArtefactForbiddenError, ArtefactTypeError
from codekavach.core.store.layout import StateLayout, StateLayoutError, atomic_write_bytes

NAMESPACE = "parse.symbols.v1"
KEY = memo_key("file-hash", "python", "grammar-1")
POSIX = sys.platform != "win32"


class Table(BaseModel):
    names: list[str]


class Other(BaseModel):
    count: int


class Counter:
    """A ``compute`` that counts its calls."""

    def __init__(self, value: Any) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> Any:
        self.calls += 1
        return self.value


@pytest.fixture
def layout(tmp_path: Path) -> StateLayout:
    return StateLayout(tmp_path / ".codekavach")


@pytest.fixture
def memo(layout: StateLayout) -> DiskItemMemo:
    return DiskItemMemo(layout)


def entries(layout: StateLayout) -> list[Path]:
    root = layout.root / "cache" / "items"
    return sorted(path for path in root.rglob("*.json")) if root.exists() else []


# --- memo_key -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("parts", "digest"),
    [
        # pragma: allowlist nextline secret
        (("a",), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
        # pragma: allowlist nextline secret
        (("a", "b"), "f04cdced9736a69da6103f08a4daaf8c485dd481217d218a1b4993c8c3968e13"),
        # pragma: allowlist nextline secret
        (("",), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        # pragma: allowlist nextline secret
        (("", ""), "ffe679bb831c95b67dc17819c63c5090d221aac6f4c7bf530f594ab43d21fa1e"),
        # pragma: allowlist nextline secret
        (("héllo", "wörld"), "a96e6d395ffae90c5ca827394f6d8c273aa7c9159efddca75262826d22c46768"),
    ],
)
def test_memo_key_vectors(parts: tuple[str, ...], digest: str) -> None:
    assert memo_key(*parts) == digest


def test_memo_key_is_a_sha256_of_the_parts_joined_by_the_unit_separator() -> None:
    assert memo_key("a", "b") == memo_key("a", "b")
    assert memo_key("a", "b") != memo_key("a\x1e", "b")
    assert KEY_PATTERN.match(memo_key("x"))


def test_the_separator_makes_the_parts_unambiguous() -> None:
    assert memo_key("ab", "c") != memo_key("a", "bc")
    assert memo_key("a", "b", "c") != memo_key("a", "b\x1ec")


def test_a_part_may_not_contain_the_separator() -> None:
    with pytest.raises(ValueError, match="separator"):
        memo_key("a\x1fb", "c")
    with pytest.raises(ValueError, match="separator"):
        memo_key("a", "b\x1fc")


def test_a_key_needs_a_part_and_parts_are_strings() -> None:
    with pytest.raises(ValueError, match="at least one"):
        memo_key()
    with pytest.raises(TypeError, match="string"):
        memo_key("a", 1)  # type: ignore[arg-type]


# --- namespace and key validation ---------------------------------------------------------------

VALID_NAMESPACES = ["parse.symbols.v1", "a", "a" * 64, "x-y_z.1"]
INVALID_NAMESPACES = ["", "A", "1abc", "a/b", "a\\b", "a" * 65, "a b", "..", "a..b", "café", "a\n"]


@pytest.mark.parametrize("namespace", VALID_NAMESPACES)
def test_valid_namespaces(namespace: str, layout: StateLayout) -> None:
    check_arguments(namespace, KEY)
    assert layout.item_path(namespace, KEY).name == f"{KEY}.json"  # the layout agrees


@pytest.mark.parametrize("namespace", INVALID_NAMESPACES)
def test_invalid_namespaces(namespace: str, layout: StateLayout) -> None:
    with pytest.raises(ValueError, match="namespace"):
        check_arguments(namespace, KEY)
    with pytest.raises(StateLayoutError):
        layout.item_path(namespace, KEY)  # the two checks stay in step


@pytest.mark.parametrize(
    "item_key", ["", "abc", "A" * 64, "g" * 64, KEY + "0", KEY[:-1], KEY.upper()]
)
def test_invalid_item_keys(item_key: str, memo: DiskItemMemo, layout: StateLayout) -> None:
    compute = Counter(Table(names=[]))
    with pytest.raises(ValueError, match="item key"):
        memo.get_or_compute(NAMESPACE, item_key, compute, Table)
    assert compute.calls == 0
    assert entries(layout) == []


def test_the_patterns_are_the_documented_ones() -> None:
    assert NAMESPACE_PATTERN.pattern == r"^[a-z][a-z0-9_.-]{0,63}$"
    assert KEY_PATTERN.pattern == r"^[0-9a-f]{64}$"


# --- hits and misses ----------------------------------------------------------------------------


def test_first_call_computes_and_second_returns_an_equal_object(memo: DiskItemMemo) -> None:
    compute = Counter(Table(names=["f", "g"]))
    first = memo.get_or_compute(NAMESPACE, KEY, compute, Table)
    second = memo.get_or_compute(NAMESPACE, KEY, compute, Table)
    assert compute.calls == 1
    assert first == second == Table(names=["f", "g"])
    assert second is not first
    assert memo.stats() == MemoStats(hits=1, misses=1, errors=0)


def test_a_different_namespace_key_or_salt_is_a_miss(layout: StateLayout) -> None:
    memo = DiskItemMemo(layout)
    compute = Counter(Table(names=["x"]))
    memo.get_or_compute(NAMESPACE, KEY, compute, Table)
    memo.get_or_compute("parse.symbols.v2", KEY, compute, Table)
    memo.get_or_compute(NAMESPACE, memo_key("another"), compute, Table)
    assert compute.calls == 3
    salted = DiskItemMemo(layout, salt_fp="0123456789abcdef")
    salted.get_or_compute(NAMESPACE, KEY, compute, Table)
    assert compute.calls == 4
    other_salt = DiskItemMemo(layout, salt_fp="fedcba9876543210")
    other_salt.get_or_compute(NAMESPACE, KEY, compute, Table)
    assert compute.calls == 5
    again = DiskItemMemo(layout, salt_fp="0123456789abcdef")
    again.get_or_compute(NAMESPACE, KEY, compute, Table)
    assert compute.calls == 5  # the same salt finds its entry
    assert again.stats() == MemoStats(hits=1)
    assert len(entries(layout)) == 5


def test_a_second_memo_instance_sees_the_entries_of_the_first(layout: StateLayout) -> None:
    compute = Counter(Table(names=["x"]))
    DiskItemMemo(layout).get_or_compute(NAMESPACE, KEY, compute, Table)
    DiskItemMemo(layout).get_or_compute(NAMESPACE, KEY, compute, Table)
    assert compute.calls == 1


def test_a_stored_entry_is_an_artefact_envelope(memo: DiskItemMemo, layout: StateLayout) -> None:
    memo.get_or_compute(NAMESPACE, KEY, Counter(Table(names=["x"])), Table)
    (path,) = entries(layout)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert envelope["ck_artefact"] == 1
    assert envelope["shape"] == "model"
    assert envelope["type"].endswith(".Table")
    assert path.is_relative_to(layout.root / "cache" / "items" / NAMESPACE)
    assert path.parent.name == KEY[:2]


def test_the_salt_is_in_no_path_and_no_entry(layout: StateLayout) -> None:
    salt = ScanSalt.from_hex("ab" * 32)
    fingerprint = salt.fingerprint()
    memo = DiskItemMemo(layout, salt_fp=fingerprint)
    memo.get_or_compute(NAMESPACE, KEY, Counter(Table(names=["x"])), Table)
    (path,) = entries(layout)
    assert fingerprint not in str(path)
    assert fingerprint not in path.read_text(encoding="utf-8")
    assert "ab" * 32 not in str(path) + path.read_text(encoding="utf-8")


# --- damaged entries ----------------------------------------------------------------------------


def stored_path(memo: DiskItemMemo, layout: StateLayout, value: Any = None) -> Path:
    memo.get_or_compute(NAMESPACE, KEY, Counter(value or Table(names=["x"])), Table)
    (path,) = entries(layout)
    return path


def test_a_truncated_entry_is_a_miss_counted_and_replaced(
    memo: DiskItemMemo, layout: StateLayout
) -> None:
    path = stored_path(memo, layout)
    good = path.read_bytes()
    path.write_bytes(good[: len(good) // 2])
    compute = Counter(Table(names=["x"]))
    assert memo.get_or_compute(NAMESPACE, KEY, compute, Table) == Table(names=["x"])
    assert compute.calls == 1
    assert memo.stats() == MemoStats(hits=0, misses=2, errors=1)
    assert path.read_bytes() == good  # replaced by a valid entry
    assert memo.get_or_compute(NAMESPACE, KEY, compute, Table) == Table(names=["x"])
    assert compute.calls == 1  # and it hits again


DAMAGE = [
    b"",
    b"\x00\xff\xfe",
    b"not json",
    b"[]",
    b"42",
    b'{"ck_artefact": 1}',
    b'{"ck_artefact": 2}',
    b'{"ck_artefact": 1, "shape": "model", "type": "x", "data": 5}',
    b'{"ck_artefact": 1, "shape": "weird", "type": "", "data": {}}',
]


@pytest.mark.parametrize("damage", DAMAGE)
def test_any_damage_is_a_miss_and_an_error(
    damage: bytes, memo: DiskItemMemo, layout: StateLayout
) -> None:
    path = stored_path(memo, layout)
    path.write_bytes(damage)
    compute = Counter(Table(names=["y"]))
    assert memo.get_or_compute(NAMESPACE, KEY, compute, Table) == Table(names=["y"])
    assert compute.calls == 1
    assert memo.stats().errors == 1
    assert json.loads(path.read_text(encoding="utf-8"))["data"] == {"names": ["y"]}


def test_a_tampered_entry_that_no_longer_validates_is_a_miss(
    memo: DiskItemMemo, layout: StateLayout
) -> None:
    path = stored_path(memo, layout)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["data"] = {"names": "not a list"}
    path.write_text(json.dumps(envelope), encoding="utf-8")
    assert memo.get_or_compute(NAMESPACE, KEY, Counter(Table(names=["z"])), Table).names == ["z"]
    assert memo.stats().errors == 1


def test_a_different_model_class_is_a_miss_not_an_exception(
    memo: DiskItemMemo, layout: StateLayout
) -> None:
    stored_path(memo, layout)
    compute = Counter(Other(count=3))
    assert memo.get_or_compute(NAMESPACE, KEY, compute, Other) == Other(count=3)
    assert compute.calls == 1
    assert memo.stats().errors == 1
    assert memo.get_or_compute(NAMESPACE, KEY, compute, Other) == Other(count=3)  # now stored
    assert compute.calls == 1


def test_a_list_entry_is_not_a_model_entry(memo: DiskItemMemo, layout: StateLayout) -> None:
    memo.get_or_compute_list(NAMESPACE, KEY, lambda: [Table(names=["a"])], Table)
    compute = Counter(Table(names=["b"]))
    assert memo.get_or_compute(NAMESPACE, KEY, compute, Table) == Table(names=["b"])
    assert compute.calls == 1


def test_an_unreadable_entry_does_not_fail_the_stage(
    memo: DiskItemMemo, layout: StateLayout
) -> None:
    path = stored_path(memo, layout)
    path.unlink()
    path.mkdir()  # a directory where the entry file belongs
    compute = Counter(Table(names=["q"]))
    assert memo.get_or_compute(NAMESPACE, KEY, compute, Table) == Table(names=["q"])
    assert compute.calls == 1
    assert memo.stats().errors >= 1


# --- failed writes ------------------------------------------------------------------------------


def test_a_failed_write_is_counted_and_the_value_is_returned(
    memo: DiskItemMemo, layout: StateLayout, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(path: Path, data: bytes) -> None:
        raise PermissionError("disk is read-only")

    monkeypatch.setattr(memo_module, "atomic_write_bytes", refuse)
    monkeypatch.setattr(memo_module, "RETRY_SECONDS", 0)
    assert memo.get_or_compute(NAMESPACE, KEY, Counter(Table(names=["w"])), Table).names == ["w"]
    assert memo.stats() == MemoStats(hits=0, misses=1, errors=1)
    assert entries(layout) == []


def test_a_write_is_retried(memo: DiskItemMemo, monkeypatch: pytest.MonkeyPatch) -> None:
    real = atomic_write_bytes
    attempts: list[int] = []

    def flaky(path: Path, data: bytes) -> None:
        attempts.append(1)
        if len(attempts) < 3:
            raise PermissionError("busy")
        real(path, data)

    monkeypatch.setattr(memo_module, "atomic_write_bytes", flaky)
    monkeypatch.setattr(memo_module, "RETRY_SECONDS", 0)
    memo.get_or_compute(NAMESPACE, KEY, Counter(Table(names=["r"])), Table)
    assert len(attempts) == 3
    assert memo.stats().errors == 0


def test_a_layout_violation_is_not_swallowed(
    memo: DiskItemMemo, layout: StateLayout, tmp_path: Path
) -> None:
    # A symbolic link in the way of the entry directory is a containment problem, not an I/O blip.
    if not POSIX:
        pytest.skip("needs symbolic links")
    target = tmp_path / "elsewhere"
    target.mkdir()
    namespace_dir = layout.items_dir(NAMESPACE)
    namespace_dir.parent.mkdir(parents=True)
    namespace_dir.symlink_to(target, target_is_directory=True)
    with pytest.raises(StateLayoutError):
        memo.get_or_compute(NAMESPACE, KEY, Counter(Table(names=["s"])), Table)
    assert list(target.rglob("*")) == []


# --- what compute may return --------------------------------------------------------------------


def test_compute_must_return_the_requested_model(memo: DiskItemMemo, layout: StateLayout) -> None:
    with pytest.raises(ArtefactTypeError, match="Other"):
        memo.get_or_compute(NAMESPACE, KEY, Counter(Other(count=1)), Table)
    assert entries(layout) == []


def test_a_list_must_hold_the_requested_model_only(memo: DiskItemMemo, layout: StateLayout) -> None:
    with pytest.raises(ArtefactTypeError):
        memo.get_or_compute_list(NAMESPACE, KEY, lambda: [Table(names=[]), Other(count=1)], Table)  # type: ignore[list-item]
    assert entries(layout) == []


def test_lists_hit_and_the_empty_list_matches_any_item_type(memo: DiskItemMemo) -> None:
    compute = Counter([Table(names=["a"]), Table(names=["b"])])
    assert memo.get_or_compute_list(NAMESPACE, KEY, compute, Table) == compute.value
    assert memo.get_or_compute_list(NAMESPACE, KEY, compute, Table) == compute.value
    assert compute.calls == 1
    empty = Counter([])
    key = memo_key("empty")
    assert memo.get_or_compute_list(NAMESPACE, key, empty, Table) == []
    assert memo.get_or_compute_list(NAMESPACE, key, empty, Other) == []
    assert empty.calls == 1


def test_a_tuple_result_is_stored_as_a_list(memo: DiskItemMemo) -> None:
    result = memo.get_or_compute_list(NAMESPACE, KEY, lambda: (Table(names=["t"]),), Table)
    assert result == [Table(names=["t"])]
    assert isinstance(result, list)


@pytest.mark.parametrize(
    "value",
    [None, True, 0, -1, 2**70, 1.5, "text", "café ☃", [], {}, [1, "a", None],
     {"a": {"b": [1, 2, {"c": None}]}}],
)  # fmt: skip
def test_json_values_round_trip(value: JsonValue, memo: DiskItemMemo) -> None:
    compute = Counter(value)
    assert memo.get_or_compute_json(NAMESPACE, KEY, compute) == value
    assert memo.get_or_compute_json(NAMESPACE, KEY, compute) == value
    assert compute.calls == 1


def test_a_json_request_does_not_read_a_model_entry(
    memo: DiskItemMemo, layout: StateLayout
) -> None:
    stored_path(memo, layout)
    compute = Counter({"other": 1})
    assert memo.get_or_compute_json(NAMESPACE, KEY, compute) == {"other": 1}
    assert compute.calls == 1
    assert memo.stats().errors == 1


def test_a_value_that_is_not_json_is_refused(memo: DiskItemMemo, layout: StateLayout) -> None:
    from codekavach.core.store.base import ArtefactSerialisationError  # noqa: PLC0415

    with pytest.raises(ArtefactSerialisationError):
        memo.get_or_compute_json(NAMESPACE, KEY, lambda: {"x": object()})  # type: ignore[dict-item]
    with pytest.raises(ArtefactSerialisationError):
        memo.get_or_compute_json(NAMESPACE, KEY, lambda: float("nan"))
    assert entries(layout) == []


def test_the_scan_salt_cannot_be_stored(memo: DiskItemMemo, layout: StateLayout) -> None:
    salt = ScanSalt.from_hex("cd" * 32)
    with pytest.raises(ArtefactForbiddenError):
        memo.get_or_compute_json(NAMESPACE, KEY, lambda: salt)  # type: ignore[arg-type,return-value]
    assert entries(layout) == []


def test_a_compute_that_raises_stores_nothing_and_is_not_swallowed(
    memo: DiskItemMemo, layout: StateLayout
) -> None:
    def explode() -> Table:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        memo.get_or_compute(NAMESPACE, KEY, explode, Table)
    assert entries(layout) == []
    assert memo.stats() == MemoStats(hits=0, misses=1, errors=0)


# --- NullMemo -----------------------------------------------------------------------------------


def test_the_null_memo_always_computes_and_touches_no_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    null = NullMemo()
    compute = Counter(Table(names=["n"]))
    for _ in range(3):
        assert null.get_or_compute(NAMESPACE, KEY, compute, Table) == Table(names=["n"])
    assert compute.calls == 3
    assert null.get_or_compute_list(NAMESPACE, KEY, lambda: (Table(names=["n"]),), Table) == [
        Table(names=["n"])
    ]
    assert null.get_or_compute_json(NAMESPACE, KEY, lambda: [1]) == [1]
    assert null.stats() == MemoStats()
    assert list(tmp_path.iterdir()) == []


def test_the_null_memo_checks_its_arguments_too() -> None:
    with pytest.raises(ValueError, match="namespace"):
        NullMemo().get_or_compute("Bad", KEY, Counter(Table(names=[])), Table)
    with pytest.raises(ValueError, match="item key"):
        NullMemo().get_or_compute_json(NAMESPACE, "short", lambda: 1)


def test_stats_add() -> None:
    assert MemoStats(1, 2, 3) + MemoStats(4, 5, 6) == MemoStats(5, 7, 9)


# --- permissions and containment ------------------------------------------------------------------


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_entries_are_private_and_inside_the_state_directory(
    memo: DiskItemMemo, layout: StateLayout
) -> None:
    memo.get_or_compute(NAMESPACE, KEY, Counter(Table(names=["m"])), Table)
    for path in entries(layout):
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.is_relative_to(layout.root)
        assert path.parent.stat().st_mode & 0o777 == 0o700


# --- threads ------------------------------------------------------------------------------------


def test_eight_threads_over_the_same_hundred_keys(layout: StateLayout) -> None:
    memo = DiskItemMemo(layout)
    keys = [memo_key("file", str(index)) for index in range(100)]
    failures: list[BaseException] = []
    barrier = threading.Barrier(8)

    def table_for(index: int) -> Callable[[], Table]:
        return lambda: Table(names=[str(index)])

    def work() -> None:
        try:
            barrier.wait()
            for index, item_key in enumerate(keys):
                value = memo.get_or_compute(NAMESPACE, item_key, table_for(index), Table)
                assert value == Table(names=[str(index)])
        except BaseException as error:  # noqa: BLE001 - reported to the main thread
            failures.append(error)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    stats = memo.stats()
    assert stats.hits + stats.misses == 800
    assert 100 <= stats.misses <= 800
    files = entries(layout)
    assert len(files) == 100
    for path in files:
        assert json.loads(path.read_text(encoding="utf-8"))["shape"] == "model"
    assert not list(layout.root.rglob("*.tmp"))  # no temporary file is left behind
    fresh = DiskItemMemo(layout)
    for index, item_key in enumerate(keys):
        assert fresh.get_or_compute(NAMESPACE, item_key, Counter(None), Table) == Table(
            names=[str(index)]
        )
    assert fresh.stats() == MemoStats(hits=100)


# --- property: JSON values ------------------------------------------------------------------------

JSON_LEAVES = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text()
)
JSON_VALUES = st.recursive(
    JSON_LEAVES,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=12,
)


@given(value=JSON_VALUES, label=st.text(min_size=1, max_size=8))
@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_json_values_are_returned_on_a_miss_and_equal_on_the_next_hit(
    value: JsonValue, label: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    layout = StateLayout(tmp_path_factory.mktemp("memo") / ".codekavach")
    memo = DiskItemMemo(layout)
    key = hashlib.sha256(label.encode("utf-8")).hexdigest()  # any text, even a separator
    compute = Counter(value)
    first = memo.get_or_compute_json(NAMESPACE, key, compute)
    second = memo.get_or_compute_json(NAMESPACE, key, compute)
    assert first is value
    assert second == value
    assert compute.calls == 1
    assert layout.item_path(NAMESPACE, key).exists()
