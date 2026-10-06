"""Pruning the cache after a scan (E04-23), through ``run_scan``.

The settings give ``scan.cache_max_size_mb`` a minimum of 64, so the tests shrink the unit
(``runner.MEGABYTE``) to a hundred bytes: the budget is then 6400 bytes, which fits one fake scan
(about 5 KB of blobs) and not two.
"""

from pathlib import Path

import pytest

from codekavach.config import LoadedConfig, load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline import runner as runner_module
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.discovery import discover
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.admin import CacheAdmin
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from tests.support import fake_stages_module
from tests.support.pipeline import write_fake_distribution

SALT_HEX = "5a" * 32  # pragma: allowlist secret
UNIT = 100
BUDGET = 64 * UNIT
MODULE = "tests.support.fake_stages_module"
STAGES = {
    "ingest": "ingest",
    "analyse-fake": "analyse_fake",
    "aggregate": "aggregate",
    "rate": "rate",
}


def registry(site: Path) -> PluginRegistry:
    write_fake_distribution(
        site,
        "ck-fake-stages",
        "1.0",
        entry_points={
            "codekavach.stages": {name: f"{MODULE}:{attr}" for name, attr in STAGES.items()}
        },
        modules={},
    )
    return PluginRegistry([spec for spec in discover() if spec.dist_name == "ck-fake-stages"])


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "codekavach.toml").write_text(
        "[scan]\ncache_max_size_mb = 64\ncache_keep_scans = 1\n", encoding="utf-8"
    )
    fake_stages_module.FAIL_ANALYSIS[0] = False
    fake_stages_module.CALLS.clear()
    return root


@pytest.fixture(autouse=True)
def tiny_megabyte(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_module, "MEGABYTE", UNIT)


def loaded(repo: Path) -> LoadedConfig:
    return load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})


def scan(fake_site: Path, repo: Path, **options: object) -> ScanOutcome:
    return run_scan(
        loaded(repo),
        str(repo),
        salt=ScanSalt.from_hex(SALT_HEX),
        registry=registry(fake_site),
        **options,  # type: ignore[arg-type]
    )


def test_three_scans_with_one_kept_stay_within_the_budget(fake_site: Path, repo: Path) -> None:
    outcome = scan(fake_site, repo)
    for _ in range(2):
        assert outcome.result.status is ScanStatus.COMPLETED
        outcome = scan(fake_site, repo)
    assert outcome.result.status is ScanStatus.COMPLETED
    stats = CacheAdmin(StateLayout(outcome.state_dir)).stats()
    assert stats.scan_count == 1
    assert stats.blob_bytes + stats.item_bytes <= BUDGET
    assert stats.tmp_files == 0
    # The newest scan is whole: every artefact it bound can still be read.
    reader = OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)
    assert reader.get("scan.record", type(outcome.scan)) == outcome.scan


def test_without_the_prune_the_same_scans_would_exceed_the_budget(
    fake_site: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control: the budget is exceeded by what three scans leave behind, so the test above
    # is about the prune and not about small scans.
    monkeypatch.setattr(CacheAdmin, "prune", lambda *args, **kwargs: None)
    outcome = scan(fake_site, repo)
    for _ in range(2):
        outcome = scan(fake_site, repo)
    stats = CacheAdmin(StateLayout(outcome.state_dir)).stats()
    assert stats.scan_count == 3
    assert stats.blob_bytes > BUDGET


def test_a_scan_after_a_prune_still_succeeds_and_reuses_what_survived(
    fake_site: Path, repo: Path
) -> None:
    for _ in range(3):
        scan(fake_site, repo)
    again = scan(fake_site, repo)
    assert again.result.status is ScanStatus.COMPLETED
    outcomes = {run.stage: run.outcome for run in again.result.stage_runs}
    assert outcomes["analyse-fake"] in {StageOutcome.CACHED, StageOutcome.SUCCEEDED}


def test_an_error_while_pruning_does_not_change_the_scan(
    fake_site: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk went away")

    monkeypatch.setattr(CacheAdmin, "prune", broken)
    outcome = scan(fake_site, repo)
    assert outcome.result.status is ScanStatus.COMPLETED
    assert outcome.manifest_path is not None
    assert outcome.manifest_path.is_file()


def test_a_bug_in_the_prune_does_not_lose_a_finished_scan(
    fake_site: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(CacheAdmin, "prune", broken)
    assert scan(fake_site, repo).result.status is ScanStatus.COMPLETED


def test_the_prune_is_called_with_the_settings_of_the_scan(
    fake_site: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[int, int]] = []

    def record(self: CacheAdmin, max_bytes: int, keep_scans: int, **_: object) -> None:
        calls.append((max_bytes, keep_scans))

    monkeypatch.setattr(CacheAdmin, "prune", record)
    scan(fake_site, repo)
    assert calls == [(BUDGET, 1)]


def test_a_scan_without_the_cache_does_not_prune(
    fake_site: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("pruned although the cache is off")

    monkeypatch.setattr(CacheAdmin, "prune", refuse)
    outcome = scan(fake_site, repo, use_cache=False)
    assert outcome.result.status is ScanStatus.COMPLETED
