"""The core alone runs a scan offline: no socket (blocked for every test) and no process (E04-30).

``run_scan`` is called with its default arguments, so the manifest, the configuration snapshot,
the stage cache, the checkpoint and database persistence are all part of the run.
"""

import os
import subprocess
from pathlib import Path
from typing import NoReturn

import pytest

from codekavach.config import load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry
from tests.support import fake_stages_module

TARGETS = {
    "ingest": "ingest",
    "analyse-fake": "analyse_fake",
    "aggregate": "aggregate",
    "rate": "rate",
}


def refuse(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("the core must not start a process")


def test_fake_scan_starts_no_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The fake stages share a failure switch with other tests; the suite runs in random order.
    monkeypatch.setattr(fake_stages_module, "FAIL_ANALYSIS", [False])
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(os, "system", refuse)
    registry = PluginRegistry(
        [
            PluginSpec(
                "codekavach.stages", name, f"tests.support.fake_stages_module:{attr}", "p", "1"
            )
            for name, attr in TARGETS.items()
        ]
    )
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(tmp_path / "home")})
    outcome = run_scan(loaded, str(repo), salt=ScanSalt.generate(), registry=registry)
    assert outcome.result.status is ScanStatus.COMPLETED
    assert [run.outcome for run in outcome.result.stage_runs] == [StageOutcome.SUCCEEDED] * 4
    assert (outcome.state_dir / "codekavach.db").is_file()
    assert outcome.manifest_path is not None
    assert outcome.manifest_path.is_file()
    with pytest.raises(AssertionError, match="must not start a process"):
        subprocess.run(["true"], check=False)  # the block is active  # noqa: S607
