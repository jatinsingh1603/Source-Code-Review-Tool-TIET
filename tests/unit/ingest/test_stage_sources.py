"""``IngestStage`` with archive and stdin targets, narrowing and the working root (E06-03)."""

import io
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from codekavach.config.models.root import Settings
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.events import WarningRaised
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.memory import InMemoryArtefactStore
from codekavach.ingest.limits import LimitExceededError
from codekavach.ingest.models import SourceFile
from codekavach.ingest.options import IngestOptions
from codekavach.ingest.sources.base import UnsafeArchiveEntry, UnsupportedSource
from codekavach.ingest.stage import IngestStage
from codekavach.ingest.subprojects import SubprojectSelectionError
from tests.support.hostile import tar_of, zip_of
from tests.support.pipeline import FIXED_SCAN_ID, CollectingBus, make_run_context
from tests.support.synthetic import make_tree

PROJECT = {
    "pyproject.toml": "[project]\nname = 'p'\n",
    "src/app.py": "print(1)\n",
    "web/package.json": "{}\n",
    "web/index.js": "var x;\n",
    "docs/guide.md": "# g\n",
}


def run_stage(
    target: str, state_dir: Path, **options: Any
) -> tuple[InMemoryArtefactStore, CollectingBus, RunContext]:
    store = InMemoryArtefactStore()
    payload: dict[str, Any] = {"target": target}
    mapping = IngestOptions(**options).to_mapping()
    if mapping:
        payload["options"] = mapping
    store.put(keys.TARGET, payload)
    bus = CollectingBus()
    ctx = make_run_context(store=store, bus=bus, state_dir=state_dir)
    IngestStage().run(ctx.for_stage("ingest"))
    return store, bus, ctx


def paths_of(store: InMemoryArtefactStore) -> list[str]:
    return [f.path for f in store.get_list(keys.FILES, SourceFile)]


def warnings_of(bus: CollectingBus) -> list[str]:
    return [e.code for e in bus.events if isinstance(e, WarningRaised)]


# --- sources that own their root -----------------------------------------------------------------


def test_an_archive_is_extracted_into_the_working_root_and_published(tmp_path: Path) -> None:
    archive = zip_of(tmp_path / "app.zip", PROJECT)
    state = tmp_path / "state"
    store, _, ctx = run_stage(str(archive), state)
    assert paths_of(store) == sorted(PROJECT)
    work = StateLayout(state).work_dir(FIXED_SCAN_ID)
    assert ctx.scan_root.path == work
    assert ctx.for_stage("parse").source_root == work
    assert (work / "src" / "app.py").read_text(encoding="utf-8") == "print(1)\n"
    ctx.scan_root.close()
    assert not work.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_the_working_root_is_private(tmp_path: Path) -> None:
    _, _, ctx = run_stage(str(zip_of(tmp_path / "a.zip", PROJECT)), tmp_path / "state")
    assert ctx.scan_root.path is not None
    assert stat.S_IMODE(ctx.scan_root.path.stat().st_mode) == 0o700
    ctx.scan_root.close()


def test_keeping_the_working_root_leaves_it_in_place(tmp_path: Path) -> None:
    _, _, ctx = run_stage(str(zip_of(tmp_path / "a.zip", PROJECT)), tmp_path / "state")
    ctx.scan_root.close(keep=True)
    assert ctx.scan_root.path is not None and ctx.scan_root.path.is_dir()
    shutil.rmtree(ctx.scan_root.path)


def test_a_local_directory_leaves_the_source_root_at_the_project(tmp_path: Path) -> None:
    root = make_tree(PROJECT)
    _, _, ctx = run_stage(str(root), tmp_path / "state")
    assert ctx.scan_root.path is None
    assert ctx.source_root == ctx.project_root


def test_a_hostile_archive_fails_the_stage_and_leaves_no_working_root(tmp_path: Path) -> None:
    archive = tar_of(tmp_path / "evil.tar", {"../../escape.txt": "x"})
    state = tmp_path / "state"
    with pytest.raises(UnsafeArchiveEntry):
        run_stage(str(archive), state)
    assert not StateLayout(state).work_dir(FIXED_SCAN_ID).exists()
    assert not (tmp_path.parent / "escape.txt").exists()


def test_an_archive_over_the_budgets_fails_with_the_limit(tmp_path: Path) -> None:
    archive = zip_of(tmp_path / "big.zip", {f"f{i}.py": "x" for i in range(20)})
    store = InMemoryArtefactStore()
    store.put(keys.TARGET, {"target": str(archive)})
    ctx = make_run_context(
        store=store,
        state_dir=tmp_path / "state",
        settings=make_settings(max_files=5),
    )
    with pytest.raises(LimitExceededError):
        IngestStage().run(ctx.for_stage("ingest"))


def test_standard_input_becomes_one_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"import os\nos.system(x)\n")))
    store, _, ctx = run_stage("-", tmp_path / "state", stdin_filename="hook.py")
    assert paths_of(store) == ["hook.py"]
    assert store.get_json(keys.LANGUAGES) == ["python"]
    ctx.scan_root.close()


def test_standard_input_without_a_filename_fails(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedSource, match="stdin-filename"):
        run_stage("-", tmp_path / "state")


def test_a_resumed_scan_starts_from_an_empty_working_root(tmp_path: Path) -> None:
    state = tmp_path / "state"
    stale = StateLayout(state).work_dir(FIXED_SCAN_ID)
    stale.mkdir(parents=True)
    (stale / "left-over.txt").write_text("old", encoding="utf-8")
    store, _, ctx = run_stage(str(zip_of(tmp_path / "a.zip", PROJECT)), state)
    assert "left-over.txt" not in paths_of(store)
    ctx.scan_root.close()


# --- narrowing -----------------------------------------------------------------------------------


def test_a_subproject_selection_keeps_its_files_and_records_the_rest(tmp_path: Path) -> None:
    root = make_tree(PROJECT)
    store, _, _ = run_stage(str(root), tmp_path / "state", subprojects=("web",))
    assert paths_of(store) == ["web/index.js", "web/package.json"]
    coverage: Any = store.get_json(keys.INGEST_COVERAGE)
    assert coverage["subproject_excluded"] == len(PROJECT) - 2
    assert ["web", "node"] in coverage["subprojects"]
    assert [".", "python"] in coverage["subprojects"]


def test_a_selection_that_matches_nothing_fails_the_stage(tmp_path: Path) -> None:
    root = make_tree(PROJECT)
    with pytest.raises(SubprojectSelectionError):
        run_stage(str(root), tmp_path / "state", subprojects=("nope",))


def test_the_coverage_record_is_written_even_when_nothing_was_narrowed(tmp_path: Path) -> None:
    root = make_tree(PROJECT)
    store, _, _ = run_stage(str(root), tmp_path / "state")
    coverage: Any = store.get_json(keys.INGEST_COVERAGE)
    assert coverage["diff_base"] is None
    assert coverage["diff_excluded"] == 0
    assert coverage["diff_unresolved"] is False
    assert coverage["subproject_excluded"] == 0
    assert coverage["submodules_not_scanned"] == []


def previous_scan(state: Path, scan_id: str, files: list[SourceFile]) -> None:
    OnDiskArtefactStore(StateLayout(state), scan_id).put(keys.FILES, files)


def test_diff_since_a_previous_scan_keeps_only_the_changed_files(tmp_path: Path) -> None:
    root = make_tree(PROJECT)
    state = tmp_path / "state"
    first, _, _ = run_stage(str(root), state)
    before_id = "scan_" + "0" * 25 + "1"
    previous_scan(state, before_id, first.get_list(keys.FILES, SourceFile))
    (root / "src" / "app.py").write_text("print(2)\n", encoding="utf-8")
    (root / "src" / "new.py").write_text("print(3)\n", encoding="utf-8")
    (root / "docs" / "guide.md").unlink()
    store, _, _ = run_stage(str(root), state, diff_since=before_id, include_deleted=True)
    assert paths_of(store) == ["src/app.py", "src/new.py"]
    coverage: Any = store.get_json(keys.INGEST_COVERAGE)
    assert coverage["diff_base"] == before_id
    assert coverage["diff_excluded"] == len(PROJECT) - 2
    assert coverage["diff_deleted"] == 1


def test_deleted_files_are_counted_only_when_asked(tmp_path: Path) -> None:
    root = make_tree(PROJECT)
    state = tmp_path / "state"
    first, _, _ = run_stage(str(root), state)
    before_id = "scan_" + "0" * 25 + "2"
    previous_scan(state, before_id, first.get_list(keys.FILES, SourceFile))
    (root / "docs" / "guide.md").unlink()
    store, _, _ = run_stage(str(root), state, diff_since=before_id)
    coverage: Any = store.get_json(keys.INGEST_COVERAGE)
    assert coverage["diff_deleted"] == 0
    assert paths_of(store) == []


@pytest.mark.parametrize("since", ["no-such-ref", "scan_" + "0" * 25 + "9", "--evil"])
def test_an_unresolvable_base_warns_and_scans_everything(tmp_path: Path, since: str) -> None:
    root = make_tree(PROJECT)
    store, bus, _ = run_stage(str(root), tmp_path / "state", diff_since=since)
    assert paths_of(store) == sorted(PROJECT)  # a full scan, never an empty one
    assert "diff_base_unresolved" in warnings_of(bus)
    coverage: Any = store.get_json(keys.INGEST_COVERAGE)
    assert coverage["diff_unresolved"] is True
    assert coverage["diff_base"] is None


def test_subprojects_and_diff_compose(tmp_path: Path) -> None:
    root = make_tree(PROJECT)
    state = tmp_path / "state"
    first, _, _ = run_stage(str(root), state)
    before_id = "scan_" + "0" * 25 + "3"
    previous_scan(state, before_id, first.get_list(keys.FILES, SourceFile))
    (root / "web" / "index.js").write_text("var y;\n", encoding="utf-8")
    (root / "src" / "app.py").write_text("print(9)\n", encoding="utf-8")
    store, _, _ = run_stage(str(root), state, diff_since=before_id, subprojects=("web",))
    assert paths_of(store) == ["web/index.js"]


def test_a_submodule_that_is_not_checked_out_is_recorded(tmp_path: Path) -> None:
    root = make_tree(
        {
            "app.py": "x = 1\n",
            ".gitmodules": '[submodule "lib"]\n\tpath = vendor/lib\n\turl = ../lib\n',
        }
    )
    (root / "vendor" / "lib").mkdir(parents=True)
    store, bus, _ = run_stage(str(root), tmp_path / "state")
    coverage: Any = store.get_json(keys.INGEST_COVERAGE)
    assert coverage["submodules_not_scanned"] == ["vendor/lib"]
    assert "submodules_not_scanned" in warnings_of(bus)


def make_settings(**ingest: object) -> Settings:
    return Settings.model_validate({"ingest": ingest})
