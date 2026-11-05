"""``run_scan`` with only the real ``IngestStage`` registered (E06-02)."""

from pathlib import Path

import pytest

from codekavach.config import load_settings
from codekavach.core.models import Language, ScanStatus
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.ingest.models import SourceFile
from tests.support.ingest import SALT_HEX, ingest_registry
from tests.support.pipeline import CollectingBus


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "web").mkdir(parents=True)
    (root / "app.py").write_text("import os\nprint(os.getcwd())\n", encoding="utf-8")
    (root / "web" / "index.ts").write_text("export const a = 1;\n", encoding="utf-8")
    (root / "deploy").write_text("#!/usr/bin/env bash\necho deploy\n", encoding="utf-8")
    return root


def scan(repo: Path, bus: CollectingBus | None = None) -> ScanOutcome:
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})
    return run_scan(
        loaded,
        str(repo),
        salt=ScanSalt.from_hex(SALT_HEX),
        registry=ingest_registry(),
        bus=bus,
    )


def test_the_entry_point_resolves_into_the_default_order_without_manual_ordering() -> None:
    registry = ingest_registry()
    info = registry.stage_infos()["ingest"]
    assert info.requires == frozenset({keys.TARGET})
    assert info.provides == frozenset({keys.FILES, keys.LANGUAGES})


def test_a_scan_with_only_the_ingest_stage_completes(repo: Path) -> None:
    outcome = scan(repo)
    assert outcome.scan.status is ScanStatus.COMPLETED
    assert {run.stage: run.outcome for run in outcome.result.stage_runs} == {
        "ingest": StageOutcome.SUCCEEDED
    }
    assert outcome.scan.languages == (
        Language.PYTHON,
        Language.SHELL,
        Language.TYPESCRIPT,
    )


def test_the_files_artefact_round_trips_through_the_on_disk_store(repo: Path) -> None:
    outcome = scan(repo)
    store = OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)
    files = store.get_list(keys.FILES, SourceFile)
    assert [f.path for f in files] == ["app.py", "deploy", "web/index.ts"]
    assert [f.language for f in files] == [Language.PYTHON, Language.SHELL, Language.TYPESCRIPT]
    assert store.get_json(keys.LANGUAGES) == ["python", "shell", "typescript"]
    assert outcome.scan.summary is not None
    assert outcome.scan.summary.files_scanned == 3


def test_languages_are_stable_across_runs(repo: Path) -> None:
    first = scan(repo).scan.languages
    (repo / "extra.py").write_text("x = 1\n", encoding="utf-8")
    assert scan(repo).scan.languages == first


def test_events_arrive_in_order_and_carry_counts_only(repo: Path) -> None:
    bus = CollectingBus()
    scan(repo, bus)
    kinds = bus.kinds()
    started = kinds.index("stage.started")
    progress = kinds.index("stage.progress")
    finished = kinds.index("stage.finished")
    assert started < progress < finished
    for event in bus.of("stage.progress"):
        assert "app.py" not in str(event.to_dict())
