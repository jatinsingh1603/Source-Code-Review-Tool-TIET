"""The admin's stored policy wins over a project's file and never enters the scanned tree."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from codekavach.config import Settings
from codekavach.privacy.policy.engine import PolicyEngine
from codekavach.server.jobs.scan import POLICY_FILE, _materialise, server_policy

ADMIN = 'policy_version = 1\n\n[[path]]\npattern = "src/payments/**"\nnever_send = true\n'
HOSTILE = "policy_version = 1\n"


def _job(tmp_path: Path, project_dir: Path) -> tuple[Any, Any, Any]:
    data = tmp_path / "data"
    data.mkdir()
    config = SimpleNamespace(data_dir=data, allow_local_paths=True)
    project = SimpleNamespace(source_type="path", source_path=str(project_dir))
    paths = SimpleNamespace(source=tmp_path / "work" / "source")
    job = SimpleNamespace(state=SimpleNamespace(config=config))
    return project, paths, job


def _project(tmp_path: Path, policy: str | None) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    if policy is not None:
        (root / POLICY_FILE).write_text(policy)
    return root


def test_admin_policy_is_not_written_into_the_scanned_tree(tmp_path: Path) -> None:
    project, paths, job = _job(tmp_path, _project(tmp_path, None))
    (job.state.config.data_dir / POLICY_FILE).write_text(ADMIN)
    _materialise(project, paths, job)
    assert not (paths.source / POLICY_FILE).exists()
    assert sorted(p.name for p in paths.source.iterdir() if p.name != ".git") == ["app.py"]
    assert server_policy(job.state.config.data_dir) == job.state.config.data_dir / POLICY_FILE


def test_project_policy_cannot_replace_the_admin_policy(tmp_path: Path) -> None:
    project, paths, job = _job(tmp_path, _project(tmp_path, HOSTILE))
    (job.state.config.data_dir / POLICY_FILE).write_text(ADMIN)
    _materialise(project, paths, job)
    engine = PolicyEngine.for_scan(
        Settings(),
        project_root=paths.source,
        policy_file=server_policy(job.state.config.data_dir),
    )
    assert engine.is_never_send("src/payments/card.py")
    assert (paths.source / POLICY_FILE).read_text() == HOSTILE  # the project's file is untouched


def test_no_server_policy_leaves_the_project_file_in_charge(tmp_path: Path) -> None:
    project, paths, job = _job(tmp_path, _project(tmp_path, None))
    _materialise(project, paths, job)
    assert server_policy(job.state.config.data_dir) is None
