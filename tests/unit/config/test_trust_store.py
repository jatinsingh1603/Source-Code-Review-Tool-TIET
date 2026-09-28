import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from codekavach.config import ConfigError
from codekavach.config.errors import ProjectTrustError
from codekavach.config.trust import TrustStore, is_project_trusted, store_path
from tests.support.config import ConfigSandbox

POSIX = sys.platform != "win32"
SHA_A = hashlib.sha256(b"a").hexdigest()
SHA_B = hashlib.sha256(b"b").hexdigest()
RESTRICTED = "[integrations.github]\ndry_run = false\n"


def sha_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# TrustStore


def test_grant_revoke_and_reload(tmp_path: Path) -> None:
    path = tmp_path / "cfg" / "trusted-projects.json"
    root = tmp_path / "repo"
    root.mkdir()
    store = TrustStore.load(path)
    assert store.entries() == []
    store.grant(root, SHA_A)
    reloaded = TrustStore.load(path)
    assert reloaded.is_trusted(root, SHA_A)
    assert not reloaded.is_trusted(root, SHA_B)
    [entry] = reloaded.entries()
    assert entry.root == os.path.normcase(str(root.resolve()))
    assert entry.trusted_at.endswith("Z")
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["version"] == 1
    assert reloaded.revoke(root)
    assert not reloaded.revoke(root)
    assert TrustStore.load(path).entries() == []


def test_path_normalisation(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    store = TrustStore(tmp_path / "s.json")
    store.grant(root / "sub" / "..", SHA_A)
    assert store.is_trusted(root, SHA_A)
    if not POSIX:
        assert store.is_trusted(Path(str(root).upper()), SHA_A)


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_modes(tmp_path: Path) -> None:
    path = tmp_path / "cfg" / "trusted-projects.json"
    TrustStore(path).grant(tmp_path, SHA_A)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_atomic_write_failure_keeps_old_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "store" / "trusted-projects.json"
    store = TrustStore(path)
    store.grant(tmp_path, SHA_A)
    before = path.read_bytes()

    def fail(self: Path, target: Path) -> Path:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        store.grant(tmp_path / "other", SHA_B)
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == ["trusted-projects.json"]


@pytest.mark.parametrize(
    "content",
    [
        b'{"version": 1, "projects": {',
        b"\xff\xfe",
        b'{"version": 2, "projects": {}}',
        b'{"version": 1, "projects": []}',
        b'{"version": 1, "projects": {"/r": {"sha256": "nothex"}}}',
    ],
)
def test_corrupt_store(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "trusted-projects.json"
    path.write_bytes(content)
    with pytest.raises(ConfigError) as info:
        TrustStore.load(path)
    assert info.value.issues[0].code.value == "CK-CFG-042"


def test_decision_table_store(tmp_path: Path) -> None:
    store = TrustStore(tmp_path / "s.json")
    store.grant(tmp_path, SHA_A)
    common = {"flag": False, "env": {}, "loaded_external": False, "store": store, "root": tmp_path}
    assert is_project_trusted(**common, sha256=SHA_A) == (True, "store")  # type: ignore[arg-type]
    assert is_project_trusted(**common, sha256=SHA_B) == (False, "untrusted")  # type: ignore[arg-type]


# loader


def test_store_grant_and_lapse(config_sandbox: ConfigSandbox) -> None:
    project = config_sandbox.write_project(RESTRICTED)
    TrustStore.load(store_path(config_sandbox.env)).grant(config_sandbox.root, sha_of(project))
    assert config_sandbox.load().project_trust == "store"
    with project.open("a", encoding="utf-8") as handle:
        handle.write("# edited\n")
    with pytest.raises(ProjectTrustError) as info:
        config_sandbox.load()
    assert {issue.code.value for issue in info.value.issues} == {"CK-CFG-040"}


def test_truncated_store_warns_and_trusts_nothing(config_sandbox: ConfigSandbox) -> None:
    project = config_sandbox.write_project(RESTRICTED)
    path = store_path(config_sandbox.env)
    TrustStore(path).grant(config_sandbox.root, sha_of(project))
    path.write_bytes(path.read_bytes()[:20])
    with pytest.raises(ProjectTrustError) as info:
        config_sandbox.load()
    warnings = [i for i in info.value.issues if i.severity == "warning"]
    assert [w.code.value for w in warnings] == ["CK-CFG-042"]


def test_corrupt_store_ignored_when_trust_is_not_needed(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project("[scan]\njobs = 2\n")
    store_path(config_sandbox.env).write_bytes(b"not json")
    loaded = config_sandbox.load()
    assert loaded.project_trust == "not-needed"
    assert loaded.warnings == ()
