"""The admin's stored policy replaces any policy file a scanned project ships."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from codekavach.server.jobs.scan import POLICY_FILE, _materialise

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


def test_project_policy_cannot_replace_the_admin_policy(tmp_path: Path) -> None:
    project, paths, job = _job(tmp_path, _project(tmp_path, HOSTILE))
    (job.state.config.data_dir / POLICY_FILE).write_text(ADMIN)
    _materialise(project, paths, job)
    assert (paths.source / POLICY_FILE).read_text() == ADMIN


def test_admin_policy_is_copied_when_the_project_has_none(tmp_path: Path) -> None:
    project, paths, job = _job(tmp_path, _project(tmp_path, None))
    (job.state.config.data_dir / POLICY_FILE).write_text(ADMIN)
    _materialise(project, paths, job)
    assert (paths.source / POLICY_FILE).read_text() == ADMIN
