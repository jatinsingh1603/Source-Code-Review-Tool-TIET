import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import platformdirs
import pytest

from codekavach.config import paths
from codekavach.config.errors import ConfigError, ConfigErrorCode
from codekavach.config.paths import (
    check_discovered_project_file,
    check_trusted_file,
    default_database_path,
    ensure_state_dir,
    find_project_config,
    project_root_for,
    resolve_state_dir,
    system_policy_paths,
    user_config_dir,
    user_config_file,
)

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode checks")


@pytest.fixture
def platform_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    fake = tmp_path / "platform"
    monkeypatch.setattr(platformdirs, "user_config_path", lambda *a, **k: fake)
    return fake


def test_codekavach_home_wins(tmp_path: Path, platform_dir: Path) -> None:
    env = {"CODEKAVACH_HOME": str(tmp_path / "x"), "XDG_CONFIG_HOME": str(tmp_path / "y")}
    assert user_config_file(env) == tmp_path / "x" / "config.toml"


def test_xdg_config_home(tmp_path: Path, platform_dir: Path) -> None:
    env = {"XDG_CONFIG_HOME": str(tmp_path / "y")}
    assert user_config_file(env) == tmp_path / "y" / "codekavach" / "config.toml"


@pytest.mark.parametrize("env", [{}, {"XDG_CONFIG_HOME": "relative/dir"}, {"CODEKAVACH_HOME": " "}])
def test_platform_default(env: dict[str, str], platform_dir: Path) -> None:
    assert user_config_dir(env) == platform_dir


def tree(root: Path, *dirs: str) -> None:
    for directory in dirs:
        (root / directory).mkdir(parents=True, exist_ok=True)


def test_file_above_repository_boundary_is_ignored(tmp_path: Path) -> None:
    tree(tmp_path, "repo/.git", "repo/pkg/sub")
    (tmp_path / "codekavach.toml").write_text("")
    assert find_project_config(tmp_path / "repo/pkg/sub", home=tmp_path.parent) is None


def test_file_in_repository_root(tmp_path: Path) -> None:
    tree(tmp_path, "repo/.git", "repo/pkg/sub")
    config = tmp_path / "repo" / "codekavach.toml"
    config.write_text("")
    assert find_project_config(tmp_path / "repo/pkg/sub", home=tmp_path) == config.resolve()
    assert project_root_for(tmp_path / "repo/pkg/sub") == (tmp_path / "repo").resolve()


def test_file_at_start_and_start_is_file(tmp_path: Path) -> None:
    tree(tmp_path, "proj")
    config = tmp_path / "proj" / "codekavach.toml"
    config.write_text("")
    source = tmp_path / "proj" / "main.py"
    source.write_text("")
    assert find_project_config(tmp_path / "proj", home=tmp_path) == config.resolve()
    assert find_project_config(source, home=tmp_path) == config.resolve()


def test_git_file_marks_worktree_boundary(tmp_path: Path) -> None:
    tree(tmp_path, "wt/src")
    (tmp_path / "wt" / ".git").write_text("gitdir: elsewhere\n")
    (tmp_path / "codekavach.toml").write_text("")
    assert find_project_config(tmp_path / "wt/src", home=tmp_path.parent) is None
    assert project_root_for(tmp_path / "wt/src") == (tmp_path / "wt").resolve()


def test_home_boundary(tmp_path: Path) -> None:
    tree(tmp_path, "home/user/work")
    (tmp_path / "home" / "codekavach.toml").write_text("")
    assert find_project_config(tmp_path / "home/user/work", home=tmp_path / "home/user") is None


def test_filesystem_root_stops(tmp_path: Path) -> None:
    anchor = Path(tmp_path.anchor)
    result = find_project_config(tmp_path, home=tmp_path / "not-an-ancestor")
    assert result is None or result.parent in (tmp_path.resolve(), *tmp_path.resolve().parents)
    assert find_project_config(anchor, home=tmp_path) in (None, anchor / "codekavach.toml")


def test_project_root_falls_back_to_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paths, "find_project_config", lambda start: None)
    monkeypatch.setattr(Path, "exists", lambda self: False)
    source = tmp_path / "loose.py"
    source.write_text("")
    assert project_root_for(tmp_path) == tmp_path.resolve()
    assert project_root_for(source) == tmp_path.resolve()


def test_resolve_state_dir(tmp_path: Path) -> None:
    assert resolve_state_dir(tmp_path, Path(".codekavach")) == tmp_path / ".codekavach"
    absolute = tmp_path / "elsewhere"
    assert resolve_state_dir(Path("ignored"), absolute) == absolute
    assert default_database_path(absolute) == absolute / "codekavach.db"


def test_ensure_state_dir_creates_and_is_idempotent(tmp_path: Path) -> None:
    state = tmp_path / "a" / ".codekavach"
    assert ensure_state_dir(state) == state
    assert (state / ".gitignore").read_text() == "*\n"
    if os.name != "nt":
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
    (state / "vault.bin").write_text("x")
    ensure_state_dir(state)
    assert (state / ".gitignore").read_text() == "*\n"
    assert (state / "vault.bin").exists()


def test_ensure_state_dir_keeps_existing_gitignore(tmp_path: Path) -> None:
    state = tmp_path / ".codekavach"
    state.mkdir()
    (state / ".gitignore").write_text("custom\n")
    ensure_state_dir(state)
    assert (state / ".gitignore").read_text() == "custom\n"


@posix_only
def test_ensure_state_dir_tightens(tmp_path: Path) -> None:
    state = tmp_path / ".codekavach"
    state.mkdir(mode=0o755)
    state.chmod(0o755)
    ensure_state_dir(state)
    assert stat.S_IMODE(state.stat().st_mode) == 0o700


def test_ensure_state_dir_refuses_regular_file(tmp_path: Path) -> None:
    state = tmp_path / ".codekavach"
    state.write_text("")
    with pytest.raises(ConfigError) as error:
        ensure_state_dir(state)
    assert error.value.code is ConfigErrorCode.CK_CFG_070


@posix_only
def test_ensure_state_dir_refuses_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    state = tmp_path / ".codekavach"
    state.symlink_to(real)
    with pytest.raises(ConfigError) as error:
        ensure_state_dir(state)
    assert error.value.code is ConfigErrorCode.CK_CFG_070


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("linux", (Path("/etc/codekavach/policy.toml"),)),
        ("freebsd14", (Path("/etc/codekavach/policy.toml"),)),
        (
            "darwin",
            (
                Path("/Library/Application Support/CodeKavach/policy.toml"),
                Path("/etc/codekavach/policy.toml"),
            ),
        ),
    ],
)
def test_system_policy_paths_posix(
    platform: str, expected: tuple[Path, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    assert system_policy_paths() == expected


def test_system_policy_paths_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("PROGRAMDATA", "D:\\Data")
    assert system_policy_paths() == (Path("D:\\Data") / "CodeKavach" / "policy.toml",)
    monkeypatch.delenv("PROGRAMDATA")
    assert system_policy_paths() == (Path("C:\\ProgramData") / "CodeKavach" / "policy.toml",)


def test_windows_checks_are_no_ops(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paths, "_is_windows", lambda: True)
    missing = tmp_path / "missing.toml"
    check_trusted_file(missing, what="user configuration")
    check_discovered_project_file(missing, tmp_path / "sub")


def secure_file(tmp_path: Path, file_mode: int = 0o644, dir_mode: int = 0o755) -> Path:
    directory = tmp_path / "conf"
    directory.mkdir()
    path = directory / "config.toml"
    path.write_text("")
    path.chmod(file_mode)
    directory.chmod(dir_mode)
    return path


@posix_only
def test_trusted_file_accepted(tmp_path: Path) -> None:
    check_trusted_file(secure_file(tmp_path), what="user configuration")


@posix_only
@pytest.mark.parametrize(
    ("file_mode", "dir_mode"), [(0o664, 0o755), (0o646, 0o755), (0o644, 0o777), (0o644, 0o775)]
)
def test_trusted_file_refused_for_modes(tmp_path: Path, file_mode: int, dir_mode: int) -> None:
    path = secure_file(tmp_path, file_mode, dir_mode)
    with pytest.raises(ConfigError) as error:
        check_trusted_file(path, what="user configuration", code=ConfigErrorCode.CK_CFG_052)
    assert error.value.code is ConfigErrorCode.CK_CFG_052
    assert error.value.issues[0].hint


def foreign_owner(monkeypatch: pytest.MonkeyPatch, victim: Path) -> None:
    real_stat = os.stat

    def fake_stat(target: Any, *args: Any, **kwargs: Any) -> Any:
        result = real_stat(target, *args, **kwargs)
        if Path(target).resolve() == victim.resolve():
            return SimpleNamespace(
                st_uid=getattr(os, "geteuid", lambda: 0)() + 4242, st_mode=result.st_mode
            )
        return result

    monkeypatch.setattr(os, "stat", fake_stat)


@posix_only
def test_trusted_file_refused_for_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = secure_file(tmp_path)
    foreign_owner(monkeypatch, path)
    with pytest.raises(ConfigError, match="another user"):
        check_trusted_file(path, what="user configuration")


@posix_only
def test_trusted_file_follows_symlink(tmp_path: Path) -> None:
    target = secure_file(tmp_path, 0o666)
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    with pytest.raises(ConfigError):
        check_trusted_file(link, what="user configuration")
    target.chmod(0o644)
    check_trusted_file(link, what="user configuration")


@posix_only
def test_planted_file_in_world_writable_parent(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    (shared / "project").mkdir(parents=True)
    config = shared / "codekavach.toml"
    config.write_text("")
    shared.chmod(0o1777)
    with pytest.raises(ConfigError) as error:
        check_discovered_project_file(config, shared / "project")
    assert error.value.code is ConfigErrorCode.CK_CFG_005
    assert "--config" in (error.value.issues[0].hint or "")
    check_discovered_project_file(config, shared)


@posix_only
def test_planted_file_with_foreign_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "project").mkdir()
    config = tmp_path / "codekavach.toml"
    config.write_text("")
    tmp_path.chmod(0o755)
    check_discovered_project_file(config, tmp_path / "project")
    foreign_owner(monkeypatch, config)
    with pytest.raises(ConfigError, match="another owner"):
        check_discovered_project_file(config, tmp_path / "project")
    check_discovered_project_file(config, tmp_path)
