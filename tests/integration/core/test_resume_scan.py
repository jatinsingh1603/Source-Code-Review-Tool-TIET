import os
import stat
import tempfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import select

from codekavach.config import LoadedConfig, load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline import runner
from codekavach.core.pipeline.cancel import CancellationToken
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.events import Event, InMemoryEventBus
from codekavach.core.pipeline.manifest import ScanManifest
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.resume import (
    ResumeMismatchError,
    load_checkpoint,
    write_checkpoint,
)
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.base import ArtefactRef
from codekavach.core.store.db import init_db, make_session_factory, session_scope
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.orm import ScanRow
from codekavach.core.store.repositories import ScanRepository
from tests.support.pipeline import FakeStage

SALT_HEX = "9d" * 32  # pragma: allowlist secret
HERE = "tests.integration.core.test_resume_scan"
ORDER = ("ingest", "analyse-fake", "aggregate", "rate")
PRODUCED = ("files", "languages", "candidates.raw", "candidates", "findings")
CALLS: Counter[str] = Counter()


class CountingStage(FakeStage):
    """A fake stage that counts its runs across scans in ``CALLS``."""

    def run(self, ctx: RunContext) -> None:
        CALLS[self.name] += 1
        super().run(ctx)


def ingest() -> FakeStage:
    return CountingStage(
        "ingest",
        requires={"scan.target"},
        provides={"files", "languages"},
        category=StageCategory.INGEST,
        writes={"files": [{"path": "a.py"}], "languages": ["python"]},
    )


def analyse() -> FakeStage:
    return CountingStage(
        "analyse-fake",
        requires={"files"},
        provides={"candidates.raw"},
        category=StageCategory.ANALYSE,
        parts={"candidates.raw": [{"rule": "r1"}]},
    )


def aggregate() -> FakeStage:
    return CountingStage(
        "aggregate",
        requires={"candidates.raw"},
        provides={"candidates"},
        category=StageCategory.AGGREGATE,
        writes={"candidates": [{"id": "c1"}]},
    )


def rate() -> FakeStage:
    return CountingStage(
        "rate",
        requires={"candidates"},
        provides={"findings"},
        category=StageCategory.RATE,
        writes={"findings": []},
    )


def registry() -> PluginRegistry:
    targets = {"ingest": "ingest", "analyse-fake": "analyse", "aggregate": "aggregate"}
    targets["rate"] = "rate"
    group = "codekavach.stages"
    return PluginRegistry(
        [PluginSpec(group, name, f"{HERE}:{attr}", "p", "1") for name, attr in targets.items()]
    )


def make_repo(parent: Path) -> Path:
    root = parent / "repo"
    (root / ".git").mkdir(parents=True)
    return root


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[Path]:
    CALLS.clear()
    yield make_repo(tmp_path)
    CALLS.clear()


def loaded(repo: Path) -> LoadedConfig:
    return load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})


def scan(repo: Path, *, cut: int | None = None, **options: object) -> ScanOutcome:
    """Run a scan; ``cut`` cancels it after that many stages have finished."""
    if cut is not None:
        token = CancellationToken()
        bus = InMemoryEventBus()
        finished = [0]

        def cancel_after_cut(event: Event) -> None:
            if event.kind == "stage.finished":
                finished[0] += 1
                if finished[0] >= cut:
                    token.cancel()

        bus.subscribe(cancel_after_cut)
        if cut == 0:
            token.cancel()
        options.update(cancellation=token, bus=bus)
    options.setdefault("salt", ScanSalt.from_hex(SALT_HEX))
    options.setdefault("registry", registry())
    target = str(options.pop("target", repo))
    return run_scan(loaded(repo), target, **options)  # type: ignore[arg-type]


def refs(outcome: ScanOutcome) -> dict[str, ArtefactRef | None]:
    store = OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)
    return {key: store.ref(key) for key in PRODUCED}


def checkpoint_text(outcome: ScanOutcome) -> str:
    path = StateLayout(outcome.state_dir).checkpoint_path(outcome.scan.id)
    return path.read_text(encoding="utf-8")


def test_cancelled_scan_leaves_a_checkpoint(repo: Path) -> None:
    cancelled = scan(repo, cut=2)
    assert cancelled.result.status is ScanStatus.CANCELLED
    layout = StateLayout(cancelled.state_dir)
    checkpoint = load_checkpoint(layout, cancelled.scan.id)
    assert checkpoint is not None
    assert checkpoint.status == "cancelled"
    assert checkpoint.order == list(ORDER)
    assert [(entry.stage, entry.outcome) for entry in checkpoint.completed] == [
        ("ingest", "succeeded"),
        ("analyse-fake", "succeeded"),
    ]
    if os.name != "nt":
        mode = stat.S_IMODE(layout.checkpoint_path(cancelled.scan.id).stat().st_mode)
        assert mode == 0o600
    text = checkpoint_text(cancelled)
    assert SALT_HEX not in text
    assert str(repo) not in text
    assert repo.as_posix() not in text
    assert repo.parent.name not in text


def test_resume_latest_continues_the_same_scan(repo: Path, tmp_path: Path) -> None:
    cancelled = scan(repo, cut=2)
    assert dict(CALLS) == {"ingest": 1, "analyse-fake": 1}
    resumed = scan(repo, resume="latest", use_cache=False)
    assert resumed.scan.id == cancelled.scan.id
    assert resumed.result.status is ScanStatus.COMPLETED
    assert resumed.result.resumed_from_checkpoint
    assert resumed.result.cache_hits == 1
    assert dict(CALLS) == {"ingest": 2, "analyse-fake": 1, "aggregate": 1, "rate": 1}
    outcomes = {run.stage: run.outcome for run in resumed.result.stage_runs}
    assert outcomes["analyse-fake"] is StageOutcome.CACHED
    assert outcomes["ingest"] is StageOutcome.SUCCEEDED
    assert resumed.manifest_path is not None
    manifest = ScanManifest.model_validate_json(resumed.manifest_path.read_text(encoding="utf-8"))
    assert manifest.counters.resumed_from_checkpoint
    checkpoint = load_checkpoint(StateLayout(resumed.state_dir), resumed.scan.id)
    assert checkpoint is not None
    assert checkpoint.status == "completed"
    reference = scan(make_repo(tmp_path / "reference"))
    assert not reference.result.resumed_from_checkpoint
    assert refs(resumed) == refs(reference)
    with pytest.raises(ResumeMismatchError) as info:
        scan(repo, resume="latest")
    assert info.value.field == "checkpoint"


def test_persisted_scan_keeps_one_row_and_its_first_start(repo: Path) -> None:
    cancelled = scan(repo, cut=1)
    resumed = scan(repo, resume=cancelled.scan.id)
    assert resumed.scan.started_at == cancelled.scan.started_at
    assert resumed.scan.project_id == cancelled.scan.project_id
    engine = init_db(StateLayout(resumed.state_dir))
    try:
        with session_scope(make_session_factory(engine)) as session:
            rows = session.execute(select(ScanRow)).scalars().all()
            assert [(row.id, row.status) for row in rows] == [(resumed.scan.id, "completed")]
            assert ScanRepository(session).get(resumed.scan.id) == resumed.scan
    finally:
        engine.dispose()


def test_each_mismatch_is_refused_before_any_stage_runs(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cancelled = scan(repo, cut=2)
    before = dict(CALLS)

    def refused(**options: object) -> str:
        with pytest.raises(ResumeMismatchError) as info:
            scan(repo, cut=None, resume=cancelled.scan.id, **options)
        assert dict(CALLS) == before
        assert SALT_HEX not in str(info.value)
        return info.value.field

    assert refused(target="other-target") == "target_digest"
    assert refused(salt=ScanSalt.from_hex("11" * 32)) == "salt_fingerprint"
    (repo / "codekavach.toml").write_text('[privacy]\nlevel = "L4"\n', encoding="utf-8")
    assert refused() == "settings_fingerprint"
    with monkeypatch.context() as patched:
        patched.setattr(runner, "codekavach_version", lambda: "999.0.0")
        assert refused() == "codekavach_version"
    (repo / "codekavach.toml").unlink()
    with pytest.raises(ResumeMismatchError) as unknown:
        scan(repo, resume="scan_00000000000000000000000000")
    assert unknown.value.field == "checkpoint"
    completed = scan(repo, resume=cancelled.scan.id)
    assert completed.result.status is ScanStatus.COMPLETED
    with pytest.raises(ResumeMismatchError) as done:
        scan(repo, resume=cancelled.scan.id)
    assert done.value.field == "status"


def test_nothing_to_resume_in_a_fresh_state_directory(repo: Path) -> None:
    with pytest.raises(ResumeMismatchError) as info:
        scan(repo, resume="latest")
    assert info.value.field == "checkpoint"
    assert dict(CALLS) == {}


def test_partial_output_of_an_unfinished_stage_is_discarded(repo: Path) -> None:
    cancelled = scan(repo, cut=2)
    layout = StateLayout(cancelled.state_dir)
    store = OnDiskArtefactStore(layout, cancelled.scan.id)
    store.put("candidates", [{"id": "half-written"}])
    assert store.has("candidates")
    stopped = CancellationToken()
    stopped.cancel()
    again = scan(repo, resume="latest", cancellation=stopped)
    assert again.result.status is ScanStatus.CANCELLED
    assert again.scan.id == cancelled.scan.id
    after = OnDiskArtefactStore.open_existing(layout, cancelled.scan.id)
    assert not after.has("candidates")
    assert after.has("files")  # ingest finished, so its outputs are kept
    assert dict(CALLS) == {"ingest": 1, "analyse-fake": 1}


def test_hard_killed_scan_is_resumable(repo: Path) -> None:
    cancelled = scan(repo, cut=3)
    layout = StateLayout(cancelled.state_dir)
    checkpoint = load_checkpoint(layout, cancelled.scan.id)
    assert checkpoint is not None
    killed = checkpoint.model_copy(update={"status": "running"})
    write_checkpoint(layout, killed)
    resumed = scan(repo, resume="latest")
    assert resumed.scan.id == cancelled.scan.id
    assert resumed.result.status is ScanStatus.COMPLETED
    assert CALLS["analyse-fake"] == CALLS["aggregate"] == 1
    assert CALLS["rate"] == 1


@settings(max_examples=8, deadline=None)
@given(cut=st.integers(min_value=0, max_value=len(ORDER) - 1))
def test_resume_after_any_cut_matches_an_uninterrupted_run(cut: int) -> None:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
        root = Path(directory)
        reference = scan(make_repo(root / "reference"), persist=False)
        interrupted = make_repo(root / "interrupted")
        cancelled = scan(interrupted, cut=cut, persist=False)
        assert cancelled.result.status is ScanStatus.CANCELLED
        resumed = scan(interrupted, resume="latest", persist=False)
        assert resumed.scan.id == cancelled.scan.id
        assert resumed.result.status is ScanStatus.COMPLETED
        assert refs(resumed) == refs(reference)
