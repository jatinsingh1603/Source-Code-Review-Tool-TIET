"""``IngestStage`` metadata, behaviour and progress throttling (E06-02)."""

from pathlib import Path

import pytest

from codekavach.config.models.ingest import IngestSettings
from codekavach.config.models.root import Settings
from codekavach.core.models import Language
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.cancel import ScanCancelledError
from codekavach.core.pipeline.events import StageProgress, WarningRaised
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from codekavach.core.store.memory import InMemoryArtefactStore
from codekavach.ingest.limits import LimitExceededError
from codekavach.ingest.models import SourceFile
from codekavach.ingest.sources.base import UnsupportedSource
from codekavach.ingest.stage import IngestStage, ProgressThrottle
from tests.support.pipeline import CollectingBus, make_run_context
from tests.support.synthetic import make_tree


def _run(
    target: str, *, settings: Settings | None = None, state_dir: Path | None = None
) -> tuple[InMemoryArtefactStore, CollectingBus]:
    store = InMemoryArtefactStore()
    store.put(keys.TARGET, {"target": target})
    bus = CollectingBus()
    ctx = make_run_context(store=store, bus=bus, settings=settings, state_dir=state_dir)
    IngestStage().run(ctx.for_stage("ingest"))
    return store, bus


def test_stage_metadata_matches_the_m1_pipeline_table() -> None:
    info = describe_stage(IngestStage())
    assert info.name == "ingest"
    assert info.requires == frozenset({keys.TARGET})
    assert info.provides == frozenset({keys.FILES, keys.LANGUAGES})
    assert info.category is StageCategory.INGEST
    assert info.failure_policy is FailurePolicy.ABORT_SCAN
    assert info.cacheable is False


def test_stage_publishes_files_and_distinct_sorted_languages() -> None:
    root = make_tree(
        {
            "b.py": "x = 1\n",
            "a.py": "y = 2\n",
            "web/app.ts": "const x = 1;\n",
            "web/app.js": "var x;\n",
            "run": "#!/bin/bash\necho hi\n",
            "LICENSE": "MIT\n",
        }
    )
    store, _ = _run(str(root))
    files = store.get_list(keys.FILES, SourceFile)
    assert [f.path for f in files] == ["LICENSE", "a.py", "b.py", "run", "web/app.js", "web/app.ts"]
    assert store.get_json(keys.LANGUAGES) == ["javascript", "python", "shell", "typescript"]
    by_path = {f.path: f.language for f in files}
    assert by_path["LICENSE"] is Language.UNKNOWN
    assert by_path["run"] is Language.SHELL


def test_languages_do_not_depend_on_file_order() -> None:
    first = make_tree({"a.py": "x\n", "b.go": "package b\n"})
    second = make_tree({"z.go": "package z\n", "y.py": "y\n"})
    assert (
        _run(str(first))[0].get_json(keys.LANGUAGES)
        == _run(str(second))[0].get_json(keys.LANGUAGES)
        == ["go", "python"]
    )


def test_a_single_file_target_is_ingested() -> None:
    root = make_tree({"only.py": "x = 1\n"})
    store, _ = _run(str(root / "only.py"))
    assert [f.path for f in store.get_list(keys.FILES, SourceFile)] == ["only.py"]


def test_a_single_file_target_is_copied_under_the_scan_state_directory(tmp_path: Path) -> None:
    root = make_tree({"only.py": "x = 1\n"})
    state = tmp_path / "state"
    state.mkdir()
    _run(str(root / "only.py"), state_dir=state)
    copies = list(state.rglob("only.py"))
    assert len(copies) == 1
    assert copies[0].parent.name == "source"


def test_an_empty_tree_warns_and_writes_empty_artefacts() -> None:
    store, bus = _run(str(make_tree({})))
    assert store.get_json(keys.FILES) == []
    assert store.get_json(keys.LANGUAGES) == []
    codes = [e.code for e in bus.events if isinstance(e, WarningRaised)]
    assert codes == ["no_files_found"]


def test_progress_ends_with_the_final_count_and_carries_no_path() -> None:
    root = make_tree({f"file{n}.py": "x = 1\n" for n in range(3)})
    _, bus = _run(str(root))
    progress = [e for e in bus.events if isinstance(e, StageProgress)]
    assert (progress[-1].current, progress[-1].total, progress[-1].unit) == (3, 3, "files")
    assert all("file0" not in str(event.to_dict()) for event in progress)


def test_a_target_that_no_source_handles_fails_the_stage() -> None:
    with pytest.raises(UnsupportedSource):
        _run("https://example.invalid/x.git")


def test_a_malformed_target_artefact_fails_the_stage() -> None:
    store = InMemoryArtefactStore()
    store.put(keys.TARGET, {"not-target": 1})
    ctx = make_run_context(store=store).for_stage("ingest")
    with pytest.raises(ValueError, match="no target"):
        IngestStage().run(ctx)


def test_the_stage_honours_the_ingest_limits() -> None:
    root = make_tree({"a.py": "x = 1\n", "b.py": "y = 2\n"})
    with pytest.raises(LimitExceededError):
        _run(str(root), settings=Settings(ingest=IngestSettings(max_files=1)))


def test_cancellation_stops_the_walk() -> None:
    root = make_tree({"a.py": "x = 1\n"})
    store = InMemoryArtefactStore()
    store.put(keys.TARGET, {"target": str(root)})
    ctx = make_run_context(store=store).for_stage("ingest")
    ctx.cancellation.cancel("test")
    with pytest.raises(ScanCancelledError):
        IngestStage().run(ctx)


# --- ProgressThrottle -------------------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_throttle_needs_both_the_time_and_the_file_spacing() -> None:
    clock = _Clock()
    throttle = ProgressThrottle(min_seconds=0.25, min_items=500, clock=clock)
    clock.now = 1.0
    assert not throttle.ready(10)  # time passed, too few files
    clock.now = 1.1
    assert throttle.ready(600)  # both satisfied
    clock.now = 1.2
    assert not throttle.ready(1200)  # files enough, too soon
    clock.now = 1.4
    assert throttle.ready(1200)
    assert not throttle.ready(1300)
