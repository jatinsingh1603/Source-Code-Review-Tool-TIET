import itertools
import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.base import (
    ArtefactForbiddenError,
    ArtefactKeyError,
    ArtefactMissingError,
    ArtefactRef,
    ArtefactSerialisationError,
    ArtefactStore,
    ArtefactTypeError,
    encode_artefact,
)
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.memory import InMemoryArtefactStore
from tests.support.strategies import nested_json

Factory = Callable[[], ArtefactStore]
_counter = itertools.count()


@pytest.fixture(params=["memory", "disk"])
def new_store(request: pytest.FixtureRequest, tmp_path: Path) -> Factory:
    """A factory of empty stores of one implementation (each disk store gets its own scan)."""
    if request.param == "memory":
        return InMemoryArtefactStore

    def disk() -> ArtefactStore:
        scan_id = f"scan_{next(_counter):026d}"
        return OnDiskArtefactStore(StateLayout(tmp_path / ".codekavach"), scan_id)

    return disk


class FileRecord(BaseModel):
    path: str
    sha256: str
    size: int


class Candidate(BaseModel):
    rule: str


class Salt:
    __ck_never_persist__ = True


def record(path: str = "app/main.py") -> FileRecord:
    return FileRecord(path=path, sha256="ab" * 32, size=120)


def test_satisfies_protocol(new_store: Factory) -> None:
    store: ArtefactStore = new_store()
    assert store.keys() == ()


def test_example(new_store: Factory) -> None:
    store = new_store()
    ref = store.put("files", [record()])
    assert ref.digest is not None
    assert ref.size > 0
    assert store.get_list("files", FileRecord)[0].path == "app/main.py"
    store.put_part("candidates.raw", "analyse-taint", [Candidate(rule="b"), Candidate(rule="c")])
    store.put_part("candidates.raw", "analyse-rules", [Candidate(rule="a")])
    parts = store.get_parts("candidates.raw", Candidate)
    assert list(parts) == ["analyse-rules", "analyse-taint"]
    assert [item.rule for item in parts["analyse-taint"]] == ["b", "c"]
    assert store.keys() == ("candidates.raw", "files")


@pytest.mark.parametrize(
    "value", [record(), [record(), record("b.py")], [], {"a": [1, 2.5, None, True, {"b": "c"}]}]
)
def test_round_trip(new_store: Factory, value: Any) -> None:
    store = new_store()
    store.put("scan.summary", value)
    if isinstance(value, BaseModel):
        assert store.get("scan.summary", FileRecord) == value
    elif isinstance(value, list):
        assert store.get_list("scan.summary", FileRecord) == value
    else:
        assert store.get_json("scan.summary") == value


def test_reads_decode_fresh_objects(new_store: Factory) -> None:
    store = new_store()
    store.put("scan.summary", {"a": [1]})
    first = store.get_json("scan.summary")
    assert isinstance(first, dict)
    first["a"] = []
    assert store.get_json("scan.summary") == {"a": [1]}


def test_errors(new_store: Factory) -> None:
    store = new_store()
    with pytest.raises(ArtefactMissingError):
        store.get("files", FileRecord)
    store.put("files", record())
    with pytest.raises(ArtefactTypeError):
        store.get("files", Candidate)
    with pytest.raises(ArtefactSerialisationError):
        store.put("files", float("nan"))
    for key in ("Files", "a/b", "../x", ""):
        with pytest.raises(ArtefactKeyError):
            store.put(key, 1)
    with pytest.raises(ArtefactKeyError):
        store.put("candidates.raw", [])
    with pytest.raises(ArtefactKeyError):
        store.put_part("files", "analyse-rules", [])
    with pytest.raises(ArtefactKeyError):
        store.put_part("candidates.raw", "Bad Part", [])
    with pytest.raises(ArtefactMissingError):
        store.get_parts("candidates.raw", Candidate)


@pytest.mark.parametrize("value", [Salt(), [record(), Salt()]])
def test_never_persist_everywhere(new_store: Factory, value: object) -> None:
    store = new_store()
    with pytest.raises(ArtefactForbiddenError):
        store.put("scan.target", value)
    with pytest.raises(ArtefactForbiddenError):
        store.put("scan.target", value, persist=False)
    with pytest.raises(ArtefactForbiddenError):
        store.put_part("candidates.raw", "analyse-rules", value)
    assert store.keys() == ()


def test_transient_values(new_store: Factory) -> None:
    store = new_store()
    tree = object()
    ref = store.put("ast", tree, persist=False)
    assert ref == ArtefactRef(key="ast", digest=None, size=0)
    assert store.get_object("ast") is tree
    assert store.has("ast")
    for getter in (lambda: store.get("ast", FileRecord), lambda: store.get_json("ast"),
                   lambda: store.get_list("ast", FileRecord)):  # fmt: skip
        with pytest.raises(ArtefactTypeError):
            getter()
    store.put("files", [])
    with pytest.raises(ArtefactTypeError):
        store.get_object("files")
    with pytest.raises(ArtefactMissingError):
        store.get_object("symbols")
    store.put("ast", {"now": "persisted"})
    assert store.get_json("ast") == {"now": "persisted"}


def test_parts_discard_and_has(new_store: Factory) -> None:
    store = new_store()
    store.put_part("candidates.raw", "analyse-rules", [Candidate(rule="a")])
    store.put_part("candidates.raw", "analyse-taint", Candidate(rule="b"))
    ref = store.ref("candidates.raw")
    assert ref is not None
    assert [name for name, _ in ref.parts] == ["analyse-rules", "analyse-taint"]
    store.discard("candidates.raw", part="analyse-rules")
    assert list(store.get_parts("candidates.raw", Candidate)) == ["analyse-taint"]
    store.discard("candidates.raw", part="analyse-taint")
    assert not store.has("candidates.raw")
    assert store.ref("candidates.raw") is None
    store.discard("candidates.raw", part="analyse-taint")
    store.discard("files")


def test_bind(new_store: Factory) -> None:
    store = new_store()
    ref = store.put("files", [record()])
    store.bind("candidates", ArtefactRef("candidates", ref.digest, ref.size))
    assert store.get_list("candidates", FileRecord) == [record()]
    with pytest.raises(ArtefactMissingError):
        store.bind("findings", ArtefactRef("findings", "0" * 64, 1))
    with pytest.raises(ArtefactMissingError):
        store.bind("findings", ArtefactRef("findings", None, 0))
    store.put_part("candidates.raw", "analyse-rules", [Candidate(rule="a")])
    multi = store.ref("candidates.raw")
    assert multi is not None
    store.discard("candidates.raw")
    store.bind("candidates.raw", multi)
    assert store.ref("candidates.raw") == multi
    with pytest.raises(ArtefactMissingError):
        store.bind("x.parts", ArtefactRef("x.parts", None, 0, (("analyse-a", "1" * 64),)))


def test_last_write_wins(new_store: Factory) -> None:
    store = new_store()
    store.put("files", [record("a")])
    store.put("files", [record("b")])
    assert store.get_list("files", FileRecord)[0].path == "b"


def normalise(value: object) -> object:
    return json.loads(json.dumps(value))


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(nested_json(st.none() | st.booleans() | st.integers() | st.text(max_size=5)
                   | st.floats(allow_nan=False, allow_infinity=False)))  # fmt: skip
def test_property_json_round_trip(new_store: Factory, value: object) -> None:
    store = new_store()
    ref = store.put("scan.summary", value)
    assert store.get_json("scan.summary") == normalise(value)
    assert ref.digest == encode_artefact(value).digest
    if isinstance(value, dict):
        reordered = dict(reversed(list(value.items())))
        assert encode_artefact(reordered).digest == ref.digest


def test_concurrent_writers(new_store: Factory) -> None:
    store = new_store()

    def work(index: int) -> None:
        store.put_part("candidates.raw", f"analyse-{index:02d}", [Candidate(rule=str(index))])
        store.put(f"key{index:02d}", {"index": index})

    threads = [threading.Thread(target=work, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    parts = store.get_parts("candidates.raw", Candidate)
    assert list(parts) == [f"analyse-{index:02d}" for index in range(16)]
    assert store.keys() == ("candidates.raw", *(f"key{index:02d}" for index in range(16)))
    assert all(store.get_json(f"key{index:02d}") == {"index": index} for index in range(16))


def test_same_digest_in_both_implementations(tmp_path: Path) -> None:
    value = [record(), record("b.py")]
    memory = InMemoryArtefactStore().put("files", value)
    disk = OnDiskArtefactStore(StateLayout(tmp_path), "scan_" + "0" * 26).put("files", value)
    assert memory == disk
