"""Every run_scan leaves a manifest and a configuration snapshot (E04-24)."""

import getpass
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.core.models import ScanStatus
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.cancel import CancellationToken
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.core.pipeline.manifest import ScanManifest
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.discovery import discover
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from tests.integration.core.test_run_scan import BASE, MODULE, SALT_HEX, loaded, registry
from tests.support import fake_stages_module
from tests.support.pipeline import write_fake_distribution

POSIX = sys.platform != "win32"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    fake_stages_module.FAIL_ANALYSIS[0] = False
    fake_stages_module.CALLS.clear()
    fake_stages_module.PARTIAL_MANIFESTS.clear()
    return root


def files_of(outcome: Any) -> tuple[Path, Path]:
    scan_dir = outcome.state_dir / "scans" / outcome.scan.id
    return scan_dir / "manifest.json", scan_dir / "config-snapshot.json"


def scan(site: Path, repo: Path, **kwargs: Any) -> Any:
    return run_scan(
        loaded(repo), str(repo), salt=ScanSalt.from_hex(SALT_HEX), registry=registry(site), **kwargs
    )


def test_completed_scan_writes_both_files(fake_site: Path, repo: Path) -> None:
    outcome = scan(fake_site, repo)
    manifest_path, snapshot_path = files_of(outcome)
    assert outcome.manifest_path == manifest_path
    manifest = ScanManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    assert manifest.status == "completed"
    assert manifest.settings_fingerprint == outcome.scan.config_hash
    assert manifest.salt_fingerprint == ScanSalt.from_hex(SALT_HEX).fingerprint()
    assert manifest.consent_source == "none"
    assert [stage.name for stage in manifest.stages] == list(manifest.order)
    json.loads(snapshot_path.read_text(encoding="utf-8"))
    if POSIX:
        for path in (manifest_path, snapshot_path):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    second = OnDiskArtefactStore(StateLayout(outcome.state_dir), outcome.scan.id)
    assert second.get(keys.MANIFEST, ScanManifest) == manifest


def test_failing_stage_and_cancelled_scan(fake_site: Path, repo: Path) -> None:
    fake_stages_module.FAIL_ANALYSIS[0] = True
    failed = scan(fake_site, repo)
    manifest = ScanManifest.model_validate_json(files_of(failed)[0].read_text(encoding="utf-8"))
    assert manifest.status == ScanStatus.COMPLETED_WITH_ERRORS.value
    fake_stages_module.FAIL_ANALYSIS[0] = False
    token = CancellationToken()
    token.cancel()
    cancelled = scan(fake_site, repo, cancellation=token)
    manifest = ScanManifest.model_validate_json(files_of(cancelled)[0].read_text(encoding="utf-8"))
    assert manifest.status == ScanStatus.CANCELLED.value


def test_orchestrator_crash_still_leaves_a_manifest(
    fake_site: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(self: Orchestrator, plan: Any, ctx: Any) -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(Orchestrator, "run", crash)
    with pytest.raises(RuntimeError, match="unexpected"):
        scan(fake_site, repo)
    state = repo / ".codekavach" / "scans"
    [scan_dir] = list(state.iterdir())
    manifest = ScanManifest.model_validate_json(
        (scan_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest.status == ScanStatus.FAILED.value


def test_volatile_setting_keeps_the_fingerprint(fake_site: Path, repo: Path) -> None:
    first = scan(fake_site, repo)
    (repo / "codekavach.toml").write_text("[scan]\njobs = 3\n", encoding="utf-8")
    second = scan(fake_site, repo)
    fingerprints = [
        ScanManifest.model_validate_json(
            files_of(o)[0].read_text(encoding="utf-8")
        ).settings_fingerprint
        for o in (first, second)
    ]
    assert fingerprints[0] == fingerprints[1]


def test_consent_source_recorded(fake_site: Path, repo: Path) -> None:
    outcome = scan(fake_site, repo, consent=ConsentDecision(True, "env"))
    assert '"consent_source": "env"' in files_of(outcome)[0].read_text(encoding="utf-8")


def test_no_salt_paths_or_user_name(fake_site: Path, repo: Path, tmp_path: Path) -> None:
    outcome = scan(fake_site, repo)
    user = getpass.getuser()
    for path in files_of(outcome):
        text = path.read_text(encoding="utf-8")
        assert SALT_HEX not in text
        for spelling in {str(tmp_path), str(tmp_path).replace("\\", "/"), str(tmp_path.resolve())}:
            assert spelling not in text
        if len(user) >= 4:
            assert user not in text


def test_partial_manifest_from_a_report_stage(fake_site: Path, repo: Path) -> None:
    write_fake_distribution(
        fake_site,
        "ck-fake-report",
        "1.0",
        entry_points={
            "codekavach.stages": {
                **{name: f"{MODULE}:{attr}" for name, attr in BASE.items()},
                "report": f"{MODULE}:report",
            }
        },
        modules={},
    )
    reg = PluginRegistry([spec for spec in discover() if spec.dist_name == "ck-fake-report"])
    run_scan(loaded(repo), str(repo), salt=ScanSalt.from_hex(SALT_HEX), registry=reg)
    [partial] = fake_stages_module.PARTIAL_MANIFESTS
    assert isinstance(partial, ScanManifest)
    assert partial.status == "running"
    assert [stage.name for stage in partial.stages] == [
        "ingest",
        "analyse-fake",
        "aggregate",
        "rate",
    ]


@given(st.binary(min_size=32, max_size=32), st.sampled_from(["alice", "client-bank", "ops"]))
@settings(
    max_examples=10,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_manifest_never_holds_salt_or_root(
    fake_site: Path, tmp_path_factory: pytest.TempPathFactory, salt: bytes, owner: str
) -> None:
    root = tmp_path_factory.mktemp(owner) / "repo"
    (root / ".git").mkdir(parents=True)
    outcome = run_scan(
        loaded(root), str(root), salt=ScanSalt.from_hex(salt.hex()), registry=registry(fake_site)
    )
    text = files_of(outcome)[0].read_text(encoding="utf-8")
    assert salt.hex() not in text
    assert str(root) not in text
    assert str(root).replace(os.sep, "/") not in text
