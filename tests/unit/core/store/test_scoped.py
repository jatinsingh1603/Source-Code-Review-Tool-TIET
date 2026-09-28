import contextlib
import threading
from typing import Any

import pytest

from codekavach.core.pipeline.stage import StageCategory, StageInfo, describe_stage
from codekavach.core.store.base import ArtefactError, ArtefactRef, ArtefactTypeError
from codekavach.core.store.memory import InMemoryArtefactStore
from codekavach.core.store.scoped import StageRevokedError, StageScopedStore, UndeclaredAccessError
from tests.support.pipeline import FakeStage

INFO = StageInfo(
    name="analyse-rules",
    requires=frozenset({"files"}),
    optional_requires=frozenset({"symbols"}),
    provides=frozenset({"candidates.raw", "scan.summary", "ast"}),
    transient_provides=frozenset({"ast"}),
)


def view() -> tuple[InMemoryArtefactStore, StageScopedStore]:
    inner = InMemoryArtefactStore()
    for key in ("files", "symbols", "findings", "scan.summary"):
        inner.put(key, {"k": key})
    return inner, StageScopedStore(inner, INFO)


def test_issue_example() -> None:
    info = describe_stage(
        FakeStage(
            "llm-review",
            category=StageCategory.LLM,
            requires={"payloads.sanitised"},
            provides={"verdicts.raw"},
        )
    )
    scoped = StageScopedStore(InMemoryArtefactStore(), info)
    with pytest.raises(UndeclaredAccessError, match="stage 'llm-review' may not read 'files'"):
        scoped.get_json("files")
    with pytest.raises(UndeclaredAccessError, match="stage 'llm-review' may not write 'findings'"):
        scoped.put("findings", [])
    scoped.revoke()
    with pytest.raises(StageRevokedError):
        scoped.put("verdicts.raw", [])


@pytest.mark.parametrize(
    ("key", "readable"),
    [
        ("files", True),
        ("symbols", True),
        ("scan.summary", True),
        ("findings", False),
        ("candidates", False),
    ],
)
def test_read_rule(key: str, readable: bool) -> None:
    _, scoped = view()
    readers = (
        lambda: scoped.get_json(key),
        lambda: scoped.has(key),
        lambda: scoped.ref(key),
    )
    for read in readers:
        if readable:
            read()
        else:
            with pytest.raises(UndeclaredAccessError):
                read()


def test_undeclared_access_is_an_artefact_error() -> None:
    assert issubclass(UndeclaredAccessError, ArtefactError)
    assert issubclass(StageRevokedError, ArtefactError)


def test_write_rule_and_forced_part() -> None:
    inner, scoped = view()
    scoped.put("scan.summary", {"n": 1})
    scoped.put_part("candidates.raw", "analyse-rules", [])
    with pytest.raises(UndeclaredAccessError):
        scoped.put("files", {"n": 1})
    with pytest.raises(UndeclaredAccessError):
        scoped.put_part("candidates.raw", "analyse-taint", [])
    with pytest.raises(UndeclaredAccessError):
        scoped.bind("scan.summary", ArtefactRef("scan.summary", None, 0))
    assert inner.get_json("files") == {"k": "files"}


def test_transient_rule() -> None:
    _, scoped = view()
    tree = object()
    scoped.put("ast", tree, persist=False)
    assert scoped.get_object("ast") is tree
    with pytest.raises(ArtefactTypeError):
        scoped.put("ast", {"x": 1})
    with pytest.raises(ArtefactTypeError):
        scoped.put("scan.summary", object(), persist=False)


def test_discard_only_own_part() -> None:
    inner, scoped = view()
    inner.put_part("candidates.raw", "analyse-taint", [])
    scoped.put_part("candidates.raw", "analyse-rules", [])
    scoped.discard("candidates.raw")
    ref = inner.ref("candidates.raw")
    assert ref is not None
    assert [part for part, _ in ref.parts] == ["analyse-taint"]
    with pytest.raises(UndeclaredAccessError):
        scoped.discard("candidates.raw", part="analyse-taint")
    with pytest.raises(UndeclaredAccessError):
        scoped.discard("findings")


def test_keys_are_filtered() -> None:
    _, scoped = view()
    assert scoped.keys() == ("files", "scan.summary", "symbols")


def test_revocation_blocks_everything() -> None:
    inner, scoped = view()
    scoped.revoke()
    assert scoped.revoked
    calls: list[Any] = [
        lambda: scoped.get_json("files"),
        lambda: scoped.has("files"),
        scoped.keys,
        lambda: scoped.put("scan.summary", {}),
        lambda: scoped.put_part("candidates.raw", "analyse-rules", []),
        lambda: scoped.discard("scan.summary"),
        lambda: scoped.bind("scan.summary", ArtefactRef("scan.summary", None, 0)),
    ]
    for call in calls:
        with pytest.raises(StageRevokedError):
            call()
    assert inner.get_json("scan.summary") == {"k": "scan.summary"}


def _race_once() -> bool:
    """Eight writers race one revoke; True when a write landed after ``revoke()`` returned."""
    inner = InMemoryArtefactStore()
    scoped = StageScopedStore(inner, INFO)
    start = threading.Barrier(9)

    def writer(index: int) -> None:
        start.wait()
        with contextlib.suppress(StageRevokedError):
            scoped.put("scan.summary", {"writer": index})

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    start.wait()
    scoped.revoke()
    snapshot = inner.get_json("scan.summary") if inner.has("scan.summary") else None
    for thread in threads:
        thread.join()
    final = inner.get_json("scan.summary") if inner.has("scan.summary") else None
    return final != snapshot


def test_no_write_after_revoke_returns() -> None:
    assert not any(_race_once() for _ in range(200))
