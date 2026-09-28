from pathlib import Path

import pytest

from codekavach.config import paths
from codekavach.config.paths import collect_paths


def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True, exist_ok=True)
    return root


def test_repository_fixture(tmp_path: Path) -> None:
    root = repo(tmp_path)
    (root / "src").mkdir()
    (root / "codekavach.toml").write_text('[project]\nstate_dir = "state"\n', encoding="utf-8")
    home = tmp_path / "home"
    found = collect_paths(root / "src", {"CODEKAVACH_HOME": str(home)})
    assert found.project_root.path == root
    assert found.project_config.path == root / "codekavach.toml"
    assert found.project_config.exists
    assert found.state_dir.path == root / "state"
    assert not found.state_dir.exists
    assert found.state_dir.note == "created on first scan"
    assert found.database.path == root / "state" / "codekavach.db"
    assert found.user_config.path == home / "config.toml"
    assert found.trust_store.path == home / "trusted-projects.json"


def test_outside_any_repository(tmp_path: Path) -> None:
    lonely = tmp_path / "lonely"
    lonely.mkdir()
    found = collect_paths(lonely, {"CODEKAVACH_HOME": str(tmp_path / "home")})
    assert found.project_config.path is None
    assert found.project_config.note == "none found"
    assert found.project_root.path is not None
    assert found.state_dir.path == found.project_root.path / ".codekavach"


def test_policy_variables(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("x = 1\n", encoding="utf-8")
    env = {
        "CODEKAVACH_HOME": str(tmp_path / "home"),
        "CODEKAVACH_ORG_POLICY": str(policy),
        "CODEKAVACH_ORG_POLICY_PUBKEY": str(tmp_path / "missing.pub"),
    }
    found = collect_paths(repo(tmp_path), env)
    assert (found.org_policy.path, found.org_policy.exists) == (policy, True)
    assert found.policy_public_key.exists is False
    unset = collect_paths(repo(tmp_path), {"CODEKAVACH_HOME": str(tmp_path / "home")})
    assert unset.org_policy.path is None
    assert unset.org_policy.note == "CODEKAVACH_ORG_POLICY is not set"


def test_system_policy_paths_listed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system = tmp_path / "etc" / "policy.toml"
    monkeypatch.setattr(paths, "system_policy_paths", lambda: (system,))
    found = collect_paths(repo(tmp_path), {"CODEKAVACH_HOME": str(tmp_path / "h")})
    assert [entry.path for entry in found.system_policies] == [system]
    assert found.system_policies[0].exists is False


def test_broken_project_file_is_reported(tmp_path: Path) -> None:
    root = repo(tmp_path)
    (root / "codekavach.toml").write_text("[project\n", encoding="utf-8")
    found = collect_paths(root, {"CODEKAVACH_HOME": str(tmp_path / "home")})
    assert found.project_config.note == "does not parse"
    assert found.state_dir.path == root / ".codekavach"


def test_creates_nothing(tmp_path: Path) -> None:
    root = repo(tmp_path)
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    collect_paths(root, {"CODEKAVACH_HOME": str(tmp_path / "home")})
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
