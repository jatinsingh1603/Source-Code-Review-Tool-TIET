import os
import stat
from pathlib import Path

import pytest

from codekavach.config import LoadedConfig, load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.models.scan import Scan
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.discovery import discover
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from tests.support import fake_stages_module
from tests.support.pipeline import write_fake_distribution

SALT_HEX = "5a" * 32  # pragma: allowlist secret
BASE = {
    "ingest": "ingest",
    "analyse-fake": "analyse_fake",
    "aggregate": "aggregate",
    "rate": "rate",
}
EGRESS = {"privacy-prepare": "privacy", "llm-review": "llm"}
MODULE = "tests.support.fake_stages_module"


def registry(site: Path, *, with_egress: bool = False) -> PluginRegistry:
    entries = {**BASE, **(EGRESS if with_egress else {})}
    write_fake_distribution(
        site,
        "ck-fake-stages",
        "1.0",
        entry_points={
            "codekavach.stages": {name: f"{MODULE}:{attr}" for name, attr in entries.items()}
        },
        modules={},
    )
    return PluginRegistry([spec for spec in discover() if spec.dist_name == "ck-fake-stages"])


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    fake_stages_module.FAIL_ANALYSIS[0] = False
    fake_stages_module.CALLS.clear()
    return root


def loaded(repo: Path) -> LoadedConfig:
    return load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})


def test_fake_distribution_scan(fake_site: Path, repo: Path) -> None:
    outcome = run_scan(
        loaded(repo), str(repo), salt=ScanSalt.from_hex(SALT_HEX), registry=registry(fake_site)
    )
    assert outcome.result.status is ScanStatus.COMPLETED
    scan = outcome.scan
    assert Scan.model_validate(scan.model_dump()) == scan
    assert scan.summary is not None
    assert scan.summary.files_scanned == 1
    assert [language.value for language in scan.languages] == ["python"]
    state = outcome.state_dir
    assert (state / ".gitignore").read_text() == "*\n"
    if os.name != "nt":
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
    reader = OnDiskArtefactStore.open_existing(StateLayout(state), scan.id)
    assert reader.get("scan.record", Scan) == scan
    for path in state.rglob("*"):
        if path.is_file():
            assert SALT_HEX not in path.read_text(encoding="utf-8", errors="replace")


def test_failing_analysis_completes_with_errors(fake_site: Path, repo: Path) -> None:
    fake_stages_module.FAIL_ANALYSIS[0] = True
    outcome = run_scan(
        loaded(repo), str(repo), salt=ScanSalt.generate(), registry=registry(fake_site)
    )
    assert outcome.result.status is ScanStatus.COMPLETED_WITH_ERRORS
    failed = [stage for stage in outcome.scan.stages if stage.status.value == "failed"]
    assert [stage.name for stage in failed] == ["analyse-fake"]
    assert failed[0].error_summary is None
    aggregate = outcome.result.run_of("aggregate")
    assert aggregate is not None
    assert aggregate.outcome is StageOutcome.SKIPPED


def test_llm_disabled_excludes_egress_stages(fake_site: Path, repo: Path) -> None:
    (repo / "codekavach.toml").write_text("[llm]\nenabled = false\n", encoding="utf-8")
    outcome = run_scan(
        loaded(repo),
        str(repo),
        salt=ScanSalt.generate(),
        registry=registry(fake_site, with_egress=True),
    )
    assert fake_stages_module.CALLS == []
    assert {item.name for item in outcome.result.excluded} == {"privacy-prepare", "llm-review"}
    assert outcome.result.status is ScanStatus.COMPLETED


def test_credentials_in_target_write_nothing(repo: Path) -> None:
    target = "https://" + "user" + ":" + "pw" + "@" + "example.invalid/repo.git"
    with pytest.raises(ValueError, match="credentials"):
        run_scan(loaded(repo), target, salt=ScanSalt.generate(), registry=PluginRegistry([]))
    assert not (repo / ".codekavach").exists()
