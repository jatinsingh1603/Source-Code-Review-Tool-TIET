import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from codekavach.cli.vault import ENTRY_KINDS, entry_counts, key_backend_text
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden"
ADMIN = "codekavach.privacy.vault.admin"
IDENTIFIER_MARKER = "accrue_premium_interest"
SECRET_MARKER = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
KEY_ARN = "arn:aws:kms:eu-west-1:111122223333:key/planted-key-id"
KEYS = {
    "exists", "path", "format_version", "cipher", "key_backend", "created_at", "rotated_at",
    "size_bytes", "entries",
}  # fmt: skip


@dataclass
class FakeInfo:
    exists: bool = True
    path: Path | None = Path(".codekavach/vault/vault.ckv")
    format_version: int | None = 1
    cipher: str | None = "AES-256-GCM"
    key_backend: str | None = "keyring"
    created_at: datetime | None = datetime(2026, 10, 1, 9, 14, 3, tzinfo=UTC)
    rotated_at: datetime | None = None
    size_bytes: int | None = 48211
    key_service: str = "codekavach"
    keyring_account: str = f"vault:{IDENTIFIER_MARKER}"
    kms_provider: str = "aws"
    kms_key_id: str = KEY_ARN
    kdf: str = "scrypt"
    kdf_params: Mapping[str, int] = field(default_factory=lambda: {"n": 32768, "r": 8, "p": 1})
    sample_entry: str = IDENTIFIER_MARKER


@dataclass
class FakeAdmin:
    vault: FakeInfo = field(default_factory=FakeInfo)
    locked: bool = False
    count_calls: int = 0

    def info(self, state_dir: Path) -> FakeInfo:
        return self.vault

    def counts(self, state_dir: Path) -> Mapping[str, int]:
        self.count_calls += 1
        if self.locked:
            raise PermissionError(f"wrong passphrase for {IDENTIFIER_MARKER} / {SECRET_MARKER}")
        return {
            "identifiers": 12,
            "literals": 5,
            "secrets": 2,
            IDENTIFIER_MARKER: 1,
            SECRET_MARKER: 1,
        }


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


@pytest.fixture
def admin(monkeypatch: pytest.MonkeyPatch) -> FakeAdmin:
    fake = FakeAdmin()
    fake_backend(monkeypatch, ADMIN, fake)
    return fake


def status(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["vault", "status", *args], cwd=project, **kwargs)


def test_metadata_panel_and_json_keys(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    human = status(cli, project)
    assert human.exit_code == 0, human.stderr
    assert_matches_golden(human.stdout.replace("\\", "/"), GOLDEN / "vault_status.txt")
    machine = status(cli, project, "--json")
    data = machine.json["data"]
    assert set(data) == KEYS
    assert data == {
        "exists": True,
        "path": str(Path(".codekavach/vault/vault.ckv")),
        "format_version": 1,
        "cipher": "AES-256-GCM",
        "key_backend": "keyring (service codekavach)",
        "created_at": "2026-10-01T09:14:03Z",
        "rotated_at": None,
        "size_bytes": 48211,
        "entries": None,
    }
    assert admin.count_calls == 0


def test_unlock_shows_three_counts(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    human = status(cli, project, "--unlock")
    assert human.exit_code == 0, human.stderr
    assert_matches_golden(human.stdout.replace("\\", "/"), GOLDEN / "vault_status_unlocked.txt")
    assert "identifiers 12, literals 5, secrets 2" in " ".join(human.stdout.split())
    machine = status(cli, project, "--unlock", "--json")
    assert machine.json["data"]["entries"] == {"identifiers": 12, "literals": 5, "secrets": 2}
    assert set(machine.json["data"]) == KEYS
    assert admin.count_calls == 2


def test_no_vault(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    admin.vault = FakeInfo(exists=False, path=None)
    human = status(cli, project, "--unlock")
    assert human.exit_code == 0
    assert_matches_golden(human.stdout, GOLDEN / "vault_status_missing.txt")
    assert "no vault for this project" in human.stdout
    data = status(cli, project, "--json").json["data"]
    assert set(data) == KEYS
    assert data["exists"] is False
    assert all(value is None for key, value in data.items() if key != "exists")
    assert admin.count_calls == 0


def test_no_marker_reaches_any_output(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    for arguments in ((), ("--json",), ("--unlock", "-vv"), ("--unlock", "--json", "-vv")):
        result = status(cli, project, *arguments)
        assert result.exit_code == 0, result.stderr
        combined = result.stdout + result.stderr
        for marker in (IDENTIFIER_MARKER, SECRET_MARKER, KEY_ARN, "planted-key-id"):
            assert marker not in combined, (arguments, marker)
    admin.locked = True
    refused = status(cli, project, "--unlock", "--debug", "--log-level", "debug")
    assert refused.exit_code == 3
    for marker in (IDENTIFIER_MARKER, SECRET_MARKER):
        assert marker not in refused.stdout + refused.stderr


def test_locked_vault_exits_3(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    admin.locked = True
    result = status(cli, project, "--unlock", tty=True)
    assert result.exit_code == 3
    assert "error[vault_locked]" in result.stderr
    assert "wrong passphrase" not in result.stderr
    machine = status(cli, project, "--unlock", "--json")
    assert (machine.exit_code, machine.json["exit_code"]) == (3, 3)
    assert [error["code"] for error in machine.json["errors"]] == ["vault_locked"]
    assert status(cli, project).exit_code == 0  # metadata needs no key


def test_passphrase_vault_is_not_prompted_for_without_a_terminal(
    cli: Cli, project: Path, admin: FakeAdmin
) -> None:
    admin.vault = FakeInfo(key_backend="passphrase")
    refused = status(cli, project, "--unlock", tty=False)
    assert refused.exit_code == 3
    assert "error[vault_locked]" in refused.stderr
    assert admin.count_calls == 0
    interactive = status(cli, project, "--unlock", tty=True)
    assert interactive.exit_code == 0, interactive.stderr
    assert admin.count_calls == 1


def test_key_backend_text_is_an_allow_list() -> None:
    assert key_backend_text(FakeInfo()) == "keyring (service codekavach)"
    kms = key_backend_text(FakeInfo(key_backend="kms"))
    assert kms == "kms (aws)"
    passphrase = key_backend_text(FakeInfo(key_backend="passphrase"))
    assert passphrase == "passphrase (scrypt, n=32768, p=1, r=8)"
    assert key_backend_text(FakeInfo(key_backend=None)) is None
    assert key_backend_text(FakeInfo(key_backend="hsm")) == "hsm"
    assert entry_counts({"identifiers": 3, IDENTIFIER_MARKER: 9}) == {
        "identifiers": 3,
        "literals": 0,
        "secrets": 0,
    }
    assert tuple(entry_counts({})) == ENTRY_KINDS


def test_kms_backend_shows_the_provider_only(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    admin.vault = FakeInfo(key_backend="kms")
    for arguments in ((), ("--json",)):
        result = status(cli, project, *arguments)
        assert "kms (aws)" in result.stdout
        assert KEY_ARN not in result.stdout + result.stderr
        assert "arn:" not in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_permissions_warning(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    state = project / ".codekavach"
    (state / "vault").mkdir(parents=True)
    state.chmod(0o700)
    vault = state / "vault" / "vault.ckv"
    vault.write_bytes(b"x")
    vault.chmod(0o600)
    admin.vault = FakeInfo(path=vault)
    assert "vault_permissions" not in status(cli, project).stderr
    vault.chmod(0o644)
    warned = status(cli, project)
    assert warned.exit_code == 0
    assert "warning[vault_permissions]" in warned.stderr
    vault.chmod(0o600)
    state.chmod(0o755)
    assert "warning[vault_permissions]" in status(cli, project).stderr
    machine = status(cli, project, "--json")
    assert [warning["code"] for warning in machine.json["warnings"]] == ["vault_permissions"]


def test_build_without_the_vault_epic(cli: Cli, project: Path) -> None:
    result = status(cli, project)
    assert result.exit_code == 2
    assert "error[backend_unavailable]" in result.stderr
    assert cli(["vault", "status", str(project / "missing")]).exit_code == 2


def test_status_does_not_import_keyring(project: Path, isolated_home: Path) -> None:
    code = (
        "import sys\n"
        "from codekavach.cli.app import build_cli, run\n"
        "code = run(build_cli(), ['vault', 'status'])\n"
        "assert code == 2, code\n"
        "assert 'keyring' not in sys.modules, 'keyring imported'\n"
    )
    env = {**os.environ, "CODEKAVACH_HOME": str(isolated_home)}
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_there_is_no_export_command(cli: Cli) -> None:
    listed = cli(["vault", "--help"]).stdout
    for forbidden in ("export", "dump", "show-mapping"):
        assert forbidden not in listed
    assert cli(["vault", "export"]).exit_code == 2
