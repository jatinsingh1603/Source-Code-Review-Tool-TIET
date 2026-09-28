import hashlib
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import paths
from codekavach.config.errors import OrgPolicyError
from codekavach.config.orgpolicy.discovery import (
    ORG_POLICY_ENV,
    ORG_POLICY_SHA256_ENV,
    check_policy_file_trust,
    discover_org_policies,
)
from tests.support.config import ConfigSandbox
from tests.support.synthetic import example_secret

POSIX = sys.platform != "win32"
VALID = 'policy_version = 1\norganisation = "Example Bank Ltd"\n'


def write(path: Path, text: str = VALID) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if POSIX:
        path.chmod(0o644)
        path.parent.chmod(0o755)
    return path


def code_of(info: pytest.ExceptionInfo[OrgPolicyError]) -> str:
    return info.value.issues[0].code.value


# discovery matrix


def test_none(tmp_path: Path) -> None:
    assert discover_org_policies({}, project_root=tmp_path / "repo", system_paths=[]) == ()
    missing_system = [tmp_path / "etc" / "policy.toml"]
    assert discover_org_policies({}, project_root=tmp_path, system_paths=missing_system) == ()


def test_system_only_env_only_and_both_in_order(tmp_path: Path) -> None:
    system = write(tmp_path / "etc" / "policy.toml")
    named = write(tmp_path / "ops" / "team.toml", VALID.replace("Example", "Team"))
    root = tmp_path / "repo"
    [only_system] = discover_org_policies({}, project_root=root, system_paths=[system])
    assert (only_system.origin, only_system.path) == ("system", system)
    assert only_system.sha256 == hashlib.sha256(system.read_bytes()).hexdigest()
    assert only_system.signature == "not-checked"
    [only_env] = discover_org_policies(
        {ORG_POLICY_ENV: str(named)}, project_root=root, system_paths=[]
    )
    assert only_env.origin == "env"
    both = discover_org_policies(
        {ORG_POLICY_ENV: str(named)}, project_root=root, system_paths=[system]
    )
    assert [p.origin for p in both] == ["system", "env"]
    assert both[1].policy.organisation == "Team Bank Ltd"


def test_variable_naming_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(OrgPolicyError) as info:
        discover_org_policies(
            {ORG_POLICY_ENV: str(tmp_path / "nope.toml")}, project_root=tmp_path, system_paths=[]
        )
    assert code_of(info) == "CK-CFG-050"


# 050


@pytest.mark.parametrize(
    "text",
    [
        "policy_version = 1\norganisation = \n",
        'policy_version = 2\norganisation = "X"\n',
        VALID + "surprise = true\n",
        VALID + '[privacy]\nmin_level = "L7"\n',
        VALID + '[lock]\n"privacy.levle" = "L3"\n',
    ],
)
def test_050_invalid(tmp_path: Path, text: str) -> None:
    policy = write(tmp_path / "p.toml", text)
    with pytest.raises(OrgPolicyError) as info:
        discover_org_policies(
            {ORG_POLICY_ENV: str(policy)}, project_root=tmp_path / "r", system_paths=[]
        )
    assert code_of(info) == "CK-CFG-050"


def test_050_lock_hint(tmp_path: Path) -> None:
    policy = write(tmp_path / "p.toml", VALID + '[lock]\n"privacy.levle" = "L3"\n')
    with pytest.raises(OrgPolicyError) as info:
        discover_org_policies(
            {ORG_POLICY_ENV: str(policy)}, project_root=tmp_path / "r", system_paths=[]
        )
    assert "did you mean 'privacy.level'?" in str(info.value)


def test_050_plaintext_secret_not_echoed(tmp_path: Path) -> None:
    value = example_secret("github_token")
    policy = write(
        tmp_path / "p.toml", VALID + f'[lock]\n"integrations.github.token" = "{value}"\n'
    )
    with pytest.raises(OrgPolicyError) as info:
        discover_org_policies(
            {ORG_POLICY_ENV: str(policy)}, project_root=tmp_path / "r", system_paths=[]
        )
    assert code_of(info) == "CK-CFG-050"
    assert value not in str(info.value) + repr(info.value)


# 051


def test_051_inside_project(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    policy = write(root / "policy.toml")
    with pytest.raises(OrgPolicyError) as info:
        check_policy_file_trust(policy, project_root=root)
    assert code_of(info) == "CK-CFG-051"


def test_051_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    inside = write(root / "real.toml")
    outside = write(tmp_path / "etc" / "real.toml")
    try:
        (tmp_path / "etc" / "link.toml").symlink_to(inside)
        (root / "link.toml").symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    with pytest.raises(OrgPolicyError) as info:
        check_policy_file_trust(tmp_path / "etc" / "link.toml", project_root=root)
    assert code_of(info) == "CK-CFG-051"
    check_policy_file_trust(root / "link.toml", project_root=root)  # the target is outside


# 052


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_052_writable_by_others(tmp_path: Path) -> None:
    policy = write(tmp_path / "etc" / "policy.toml")
    policy.chmod(0o666)
    with pytest.raises(OrgPolicyError) as info:
        check_policy_file_trust(policy, project_root=tmp_path / "repo")
    assert code_of(info) == "CK-CFG-052"
    policy.chmod(0o644)
    policy.parent.chmod(0o777)
    with pytest.raises(OrgPolicyError) as info:
        check_policy_file_trust(policy, project_root=tmp_path / "repo")
    assert code_of(info) == "CK-CFG-052"
    policy.parent.chmod(0o755)


@pytest.mark.skipif(not POSIX, reason="POSIX ownership")
def test_052_foreign_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = write(tmp_path / "etc" / "policy.toml")
    real_stat = os.stat

    class Foreign:
        def __init__(self, info: os.stat_result) -> None:
            self._info = info
            self.st_uid = 4242
            self.st_mode = info.st_mode

    def fake_stat(target: Any, *args: Any, **kwargs: Any) -> Any:
        info = real_stat(target, *args, **kwargs)
        return Foreign(info) if str(target).endswith("policy.toml") else info

    monkeypatch.setattr(os, "stat", fake_stat)
    with pytest.raises(OrgPolicyError) as info:
        check_policy_file_trust(policy, project_root=tmp_path / "repo")
    assert code_of(info) == "CK-CFG-052"


def test_windows_skips_mode_bits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = write(tmp_path / "etc" / "policy.toml")
    if POSIX:
        policy.chmod(0o666)
    monkeypatch.setattr(os, "name", "nt")
    assert paths._is_windows()
    check_policy_file_trust(policy, project_root=tmp_path / "repo")
    with pytest.raises(OrgPolicyError):  # every other check still applies
        check_policy_file_trust(policy, project_root=tmp_path)


# 053


def test_053_hash_pin(tmp_path: Path) -> None:
    policy = write(tmp_path / "p.toml")
    good = hashlib.sha256(policy.read_bytes()).hexdigest()
    env = {ORG_POLICY_ENV: str(policy), ORG_POLICY_SHA256_ENV: good.upper()}
    assert len(discover_org_policies(env, project_root=tmp_path / "r", system_paths=[])) == 1
    env[ORG_POLICY_SHA256_ENV] = "0" * 64
    with pytest.raises(OrgPolicyError) as info:
        discover_org_policies(env, project_root=tmp_path / "r", system_paths=[])
    assert code_of(info) == "CK-CFG-053"


# 056


def test_056_expired(tmp_path: Path) -> None:
    policy = write(tmp_path / "p.toml", VALID + "expires = 2027-03-31\n")
    env = {ORG_POLICY_ENV: str(policy)}
    common: dict[str, Any] = {"project_root": tmp_path / "r", "system_paths": []}
    assert discover_org_policies(env, today=date(2027, 3, 31), **common)
    with pytest.raises(OrgPolicyError) as info:
        discover_org_policies(env, today=date(2027, 4, 1), **common)
    assert code_of(info) == "CK-CFG-056"


# loader


def test_loader_without_policy(config_sandbox: ConfigSandbox) -> None:
    assert config_sandbox.load().org_policies == ()


def test_loader_records_policy(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_policy(VALID)
    [loaded] = config_sandbox.load().org_policies
    assert loaded.origin == "env"


@pytest.mark.parametrize(
    "text",
    ["not toml = ", 'policy_version = 1\norganisation = "X"\nexpires = 2000-01-01\n'],
)
def test_loader_aborts(config_sandbox: ConfigSandbox, text: str) -> None:
    config_sandbox.write_policy(text)
    with pytest.raises(OrgPolicyError):
        config_sandbox.load()


def test_loader_aborts_on_policy_inside_project(config_sandbox: ConfigSandbox) -> None:
    policy = write(config_sandbox.root / "policy.toml")
    config_sandbox.env[ORG_POLICY_ENV] = str(policy)
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    assert code_of(info) == "CK-CFG-051"
