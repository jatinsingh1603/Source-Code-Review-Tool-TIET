import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codekavach.cli.vault import (
    BACKUP_LINE,
    DESTROYED_LINE,
    consequence_lines,
    running_scans,
)
from codekavach.core.models.ids import new_scan_id
from codekavach.core.pipeline.resume import Checkpoint, write_checkpoint
from codekavach.core.store.layout import StateLayout
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden" / "vault_destroy_consequence.txt"
ADMIN = "codekavach.privacy.vault.admin"
IDENTIFIER_MARKER = "accrue_premium_interest"
SECRET_MARKER = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
ROTATED = datetime(2026, 10, 5, 8, 0, tzinfo=UTC)
EARLIER = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
VAULT_PATH = Path(".codekavach/vault/vault.ckv")
PROJECT_NAME = "project"


class VaultLockedError(Exception):
    """What E10 raises when the vault cannot be unlocked."""


@dataclass
class FakeAdmin:
    exists: bool = True
    key_backend: str = "keyring"
    rotated_at: datetime | None = EARLIER
    lock: BaseException | None = None
    rotate_error: BaseException | None = None
    entries: int = 1204
    calls: list[str] = field(default_factory=list)
    requested_backends: list[str | None] = field(default_factory=list)

    def info(self, state_dir: Path) -> Any:
        return SimpleNamespace(
            exists=self.exists,
            path=VAULT_PATH if self.exists else None,
            format_version=1,
            cipher="AES-256-GCM",
            key_backend=self.key_backend,
            created_at=EARLIER,
            rotated_at=self.rotated_at,
            size_bytes=48211,
            key_service="codekavach",
            sample_entry=IDENTIFIER_MARKER,
        )

    def counts(self, state_dir: Path) -> Mapping[str, int]:
        self.calls.append("counts")
        if self.lock is not None:
            raise self.lock
        return {"identifiers": self.entries - 4, "literals": 3, "secrets": 1, SECRET_MARKER: 7}

    def rotate(self, state_dir: Path, *, new_backend: str | None) -> Any:
        self.calls.append("rotate")
        self.requested_backends.append(new_backend)
        for error in (self.lock, self.rotate_error):
            if error is not None:
                raise error
        previous, self.rotated_at = self.rotated_at, ROTATED
        self.key_backend = new_backend or self.key_backend
        return SimpleNamespace(
            entries=self.entries,
            key_backend=self.key_backend,
            rotated_at=ROTATED,
            previous_rotated_at=previous,
            new_key_material=SECRET_MARKER,
        )

    def destroy(self, state_dir: Path) -> Any:
        self.calls.append("destroy")
        self.exists = False
        return SimpleNamespace(path=VAULT_PATH, keyring_entry_removed=self.key_backend == "keyring")


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


@pytest.fixture
def admin(monkeypatch: pytest.MonkeyPatch) -> FakeAdmin:
    fake = FakeAdmin()
    fake_backend(monkeypatch, ADMIN, fake)
    return fake


def vault(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["vault", *args], cwd=project, **kwargs)


def running_checkpoint(project: Path, *, age: timedelta = timedelta(seconds=5)) -> None:
    layout = StateLayout(project / ".codekavach").ensure()
    write_checkpoint(
        layout,
        Checkpoint(
            scan_id=new_scan_id(),
            status="running",
            codekavach_version="0.1.0",
            settings_fingerprint="ab" * 32,
            salt_fingerprint="0123456789abcdef",
            target_digest="cd" * 32,
            order=["ingest"],
            completed=[],
            updated_at=datetime.now(UTC) - age,
        ),
    )


# rotate


def test_rotate_reports_the_new_key_metadata(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    result = vault(cli, project, "rotate")
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip() == (
        "vault re-encrypted: 1204 entries, key backend keyring, rotated at 2026-10-05T08:00:00Z"
    )
    assert admin.requested_backends == [None]
    machine = vault(cli, project, "rotate", "--json")
    assert machine.json["data"] == {
        "entries": 1204,
        "key_backend": "keyring",
        "rotated_at": "2026-10-05T08:00:00Z",
        "previous_rotated_at": "2026-10-05T08:00:00Z",
    }
    assert SECRET_MARKER not in machine.stdout + result.stdout


def test_rotate_passes_the_backend_change(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    result = vault(cli, project, "rotate", "--key-backend", "KMS")
    assert result.exit_code == 0, result.stderr
    assert admin.requested_backends == ["kms"]
    assert "key backend kms" in result.stdout
    assert vault(cli, project, "rotate", "--key-backend", "floppy").exit_code == 2


def test_rotate_to_or_from_a_passphrase_needs_a_terminal(
    cli: Cli, project: Path, admin: FakeAdmin
) -> None:
    refused = vault(cli, project, "rotate", "--key-backend", "passphrase")
    assert refused.exit_code == 2
    assert "error[passphrase_needs_terminal]" in refused.stderr
    admin.key_backend = "passphrase"
    assert vault(cli, project, "rotate").exit_code == 2
    assert "rotate" not in admin.calls
    interactive = vault(cli, project, "rotate", tty=True)
    assert interactive.exit_code == 0, interactive.stderr


def test_rotate_locked_and_failed(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    admin.lock = VaultLockedError(f"no keyring entry for {IDENTIFIER_MARKER}")
    locked = vault(cli, project, "rotate")
    assert locked.exit_code == 3
    assert "error[vault_locked]" in locked.stderr
    admin.lock = None
    admin.rotate_error = OSError(f"disk full while writing {SECRET_MARKER}")
    before = (admin.rotated_at, admin.key_backend, admin.exists)
    failed = vault(cli, project, "rotate", "--key-backend", "kms")
    assert failed.exit_code == 4
    assert "error[vault_rotate_failed]" in failed.stderr
    assert (admin.rotated_at, admin.key_backend, admin.exists) == before
    machine = vault(cli, project, "rotate", "--json")
    assert [error["code"] for error in machine.json["errors"]] == ["vault_rotate_failed"]
    for output in (locked, failed, machine):
        for marker in (IDENTIFIER_MARKER, SECRET_MARKER, "disk full"):
            assert marker not in output.stdout + output.stderr


def test_no_vault(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    admin.exists = False
    rotate = vault(cli, project, "rotate")
    assert (rotate.exit_code, "error[vault_not_found]" in rotate.stderr) == (2, True)
    destroy = vault(cli, project, "destroy")
    assert destroy.exit_code == 0
    assert destroy.stdout.strip() == "nothing to destroy"
    machine = vault(cli, project, "destroy", "--json")
    assert machine.json["data"] == {
        "destroyed": False,
        "path": None,
        "keyring_entry_removed": False,
    }
    assert admin.calls == []


# destroy


@pytest.mark.parametrize(
    ("tty", "yes", "typed", "destroyed"),
    [
        (True, False, f"{PROJECT_NAME}\n", True),
        (True, False, "Project\n", False),
        (True, False, f"{PROJECT_NAME} \n", False),
        (True, False, "n\n", False),
        (True, False, "\n", False),
        (True, False, "", False),
        (True, True, "", True),
        (False, False, f"{PROJECT_NAME}\n", False),
        (False, True, "", True),
    ],
)
def test_destroy_confirmation_matrix(  # noqa: PLR0917 - fixtures and the matrix columns
    cli: Cli, project: Path, admin: FakeAdmin, tty: bool, yes: bool, typed: str, destroyed: bool
) -> None:
    arguments = ["destroy", "--yes"] if yes else ["destroy"]
    started = time.monotonic()
    result = vault(cli, project, *arguments, tty=tty, input=typed)
    elapsed = time.monotonic() - started
    assert tty or elapsed < 1, elapsed  # no terminal: refused or done at once, never waiting
    assert ("destroy" in admin.calls) is destroyed
    assert admin.exists is not destroyed
    if destroyed:
        assert result.exit_code == 0, result.stderr
        assert DESTROYED_LINE in " ".join(result.stdout.split())
    else:
        assert result.exit_code == 2
        assert "error[not_confirmed]" in result.stderr
        assert "re-run with --yes" in result.stderr


def test_destroy_states_the_consequence_first(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    result = vault(cli, project, "destroy", tty=True, input=f"{PROJECT_NAME}\n")
    flat = " ".join(result.stderr.split())
    assert "This deletes the mapping vault of project 'project':" in flat
    assert (
        ".codekavach/vault/vault.ckv (48 kB, 1 204 entries, referenced by 0 stored scans)" in flat
    )
    assert "This cannot be undone." in flat
    assert f"Type {PROJECT_NAME} to confirm:" in flat
    assert "keyring entry removed: yes" in result.stdout
    assert admin.exists is False


def test_destroy_json(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    result = vault(cli, project, "destroy", "--yes", "--json")
    assert result.json["data"] == {
        "destroyed": True,
        "path": str(VAULT_PATH),
        "keyring_entry_removed": True,
    }


def test_destroy_works_for_a_vault_that_cannot_be_unlocked(
    cli: Cli, project: Path, admin: FakeAdmin
) -> None:
    admin.lock = VaultLockedError("the passphrase is lost")
    result = vault(cli, project, "destroy", "--yes")
    assert result.exit_code == 0, result.stderr
    assert "unknown number of entries" in " ".join(result.stderr.split())
    assert admin.calls == ["counts", "destroy"]


def test_destroy_of_a_passphrase_vault_does_not_prompt_for_it(
    cli: Cli, project: Path, admin: FakeAdmin
) -> None:
    admin.key_backend = "passphrase"
    result = vault(cli, project, "destroy", "--yes")
    assert result.exit_code == 0, result.stderr
    assert admin.calls == ["destroy"]
    assert BACKUP_LINE in " ".join(result.stdout.split())
    assert "keyring entry removed" not in result.stdout


def test_destroy_wording_and_leaks(cli: Cli, project: Path, admin: FakeAdmin) -> None:
    for arguments in (("destroy", "--yes", "-vv"), ("rotate", "-vv"), ("rotate", "--json")):
        admin.exists = True
        result = vault(cli, project, *arguments)
        combined = (result.stdout + result.stderr).lower()
        for phrase in ("securely erased", "secure deletion"):
            assert phrase not in combined
        for marker in (IDENTIFIER_MARKER, SECRET_MARKER):
            assert marker.lower() not in combined
    text = " ".join([DESTROYED_LINE, BACKUP_LINE]).lower()
    assert "securely erased" not in text
    assert "secure deletion" not in text


def test_consequence_text_matches_the_golden_file() -> None:
    lines = consequence_lines(
        project="kavachbank", path=VAULT_PATH, size_bytes=48211, entries=1204, scans=3
    )
    assert all(len(line) <= 100 for line in lines)
    assert_matches_golden("\n".join(lines) + "\n", GOLDEN)
    unknown = consequence_lines(
        project="kavachbank", path=VAULT_PATH, size_bytes=None, entries=None, scans=0
    )
    assert "(unknown size, unknown number of entries, referenced by 0 stored scans)" in unknown[1]


# scans in progress


def test_both_commands_are_refused_while_a_scan_runs(
    cli: Cli, project: Path, admin: FakeAdmin
) -> None:
    running_checkpoint(project)
    for arguments in (("rotate",), ("destroy", "--yes")):
        result = vault(cli, project, *arguments)
        assert result.exit_code == 2
        assert "error[scan_in_progress]" in result.stderr
    assert admin.calls == []
    assert admin.exists


def test_a_stale_running_checkpoint_does_not_block(
    cli: Cli, project: Path, admin: FakeAdmin
) -> None:
    running_checkpoint(project, age=timedelta(days=30))
    state = project / ".codekavach"
    now = datetime.now(UTC)
    assert running_scans(state, now=now, timeout_seconds=3600) == []
    assert len(running_scans(state, now=now, timeout_seconds=40 * 86_400)) == 1
    assert vault(cli, project, "rotate").exit_code == 0
    destroyed = vault(cli, project, "destroy", "--yes")
    assert destroyed.exit_code == 0, destroyed.stderr
    assert "referenced by 1 stored scans" in " ".join(destroyed.stderr.split())


def test_build_without_the_vault_epic(cli: Cli, project: Path) -> None:
    for command in ("rotate", "destroy"):
        result = vault(cli, project, command)
        assert result.exit_code == 2
        assert "error[backend_unavailable]" in result.stderr
