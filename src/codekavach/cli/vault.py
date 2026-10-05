"""``codekavach vault``: metadata of the local mapping vault, never its contents.

Owning epic: E05.

The vault links pseudonyms to the client's real identifiers, literals and secrets; its disclosure
would undo pseudonymisation for every payload ever sent. Invariant I3 says its contents are never
logged, exported or serialised outside the vault module. ``vault status`` therefore shows
metadata only, built field by field from what the vault back end (E10) reports: existence,
location, format, cipher, key backend, timestamps and size. It unlocks nothing unless
``--unlock`` is given, and then shows three counts under fixed names and nothing derived from an
entry's text, not even a length or a hash.

There is deliberately no ``export``, ``dump``, ``get`` or ``--show-mapping``. A mapping file that
travelled with a report would defeat the privacy layer; such a need goes through an ADR.

The key backend is shown by an allow-list: the keyring service name but not the account, the KMS
provider but not the key identifier or ARN (they describe the client's infrastructure), and for a
passphrase the KDF with its cost parameters.

``vault rotate`` re-encrypts the vault under a new key and ``vault destroy`` deletes it (E05-25).
Both are implemented by the vault back end; this module adds the command surface, the
confirmation and the exit codes. Neither takes a secret on the command line or prints vault
content. Destruction is irreversible: afterwards pseudonyms of past scans cannot be mapped back,
so it needs the project name typed on a terminal, or ``--yes``. Its message does not claim that
the file is erased from the storage medium; what makes destruction effective is removing the
key. Both commands are refused while a scan is running on the same state directory: a scan
counts as running when its checkpoint says so and was updated within ``scan.timeout_seconds``.
"""

import os
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, Protocol

import typer
from rich.console import Console

from codekavach.cli.backends import load_backend
from codekavach.cli.console import get_err_console
from codekavach.cli.context import CliContext, with_target
from codekavach.cli.errors import InternalError, PrivacyBlockError, UsageError
from codekavach.cli.output import Output, get_output, kv_table
from codekavach.cli.prompts import confirm_typed, is_interactive
from codekavach.cli.report import human_size

ENTRY_KINDS: Final = ("identifiers", "literals", "secrets")
NO_VAULT: Final = "no vault for this project (created on the first scan that pseudonymises code)"
PASSPHRASE: Final = "passphrase"  # noqa: S105 - the name of a key backend
_OTHERS: Final = stat.S_IRWXG | stat.S_IRWXO

vault_app = typer.Typer(
    help="Manage the local mapping vault. Its contents never appear in any output.",
    no_args_is_help=True,
)


class VaultInfo(Protocol):
    """Metadata of a vault, as the vault back end reports it without unlocking."""

    @property
    def exists(self) -> bool:
        """Whether the project has a vault."""

    @property
    def path(self) -> Path | None:
        """Where the vault file is."""

    @property
    def format_version(self) -> int | None:
        """The version of the file format."""

    @property
    def cipher(self) -> str | None:
        """The cipher, for example ``AES-256-GCM``."""

    @property
    def key_backend(self) -> str | None:
        """``keyring``, ``passphrase`` or ``kms``."""

    @property
    def created_at(self) -> datetime | None:
        """When the vault was created."""

    @property
    def rotated_at(self) -> datetime | None:
        """When its key was last rotated."""

    @property
    def size_bytes(self) -> int | None:
        """The size of the vault file."""


class VaultAdmin(Protocol):
    """The administrative interface of the vault (E10)."""

    def info(self, state_dir: Path) -> VaultInfo:
        """Metadata; needs no key."""

    def counts(self, state_dir: Path) -> Mapping[str, int]:
        """Entries per kind; unlocks the vault and raises when that is not possible."""

    def rotate(self, state_dir: Path, *, new_backend: str | None) -> "RotationResult":
        """Re-encrypt under a new key, atomically; raises ``VaultLockedError`` when locked."""

    def destroy(self, state_dir: Path) -> "DestroyResult":
        """Delete the vault file and its key; needs no unlocking."""


class RotationResult(Protocol):
    """What a rotation reports."""

    @property
    def entries(self) -> int:
        """How many entries were re-encrypted."""

    @property
    def key_backend(self) -> str:
        """The key backend after the rotation."""

    @property
    def rotated_at(self) -> datetime:
        """When the rotation happened."""

    @property
    def previous_rotated_at(self) -> datetime | None:
        """The rotation before this one."""


class DestroyResult(Protocol):
    """What a destruction reports."""

    @property
    def path(self) -> Path:
        """The deleted vault file."""

    @property
    def keyring_entry_removed(self) -> bool:
        """Whether the key was removed from the keyring."""


class KeyBackend(StrEnum):
    """Accepted values of ``rotate --key-backend``."""

    keyring = "keyring"
    passphrase = "passphrase"  # noqa: S105 - the name of a key backend
    kms = "kms"


def _admin() -> VaultAdmin:
    admin: VaultAdmin = load_backend(
        "codekavach.privacy.vault", "admin", feature="mapping vault", epic="E10"
    )
    return admin


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def key_backend_text(info: VaultInfo) -> str | None:
    """The key backend with the details that are safe to show (see the module docstring)."""
    backend = info.key_backend
    if backend is None:
        return None
    detail: str | None = None
    if backend == "keyring":
        service = getattr(info, "key_service", None)
        detail = f"service {service}" if isinstance(service, str) else None
    elif backend == "kms":
        provider = getattr(info, "kms_provider", None)
        detail = provider if isinstance(provider, str) else None
    elif backend == PASSPHRASE:
        kdf = getattr(info, "kdf", None)
        params = getattr(info, "kdf_params", None)
        costs = (
            [f"{name}={value}" for name, value in sorted(params.items()) if isinstance(value, int)]
            if isinstance(params, Mapping)
            else []
        )
        detail = ", ".join([kdf, *costs]) if isinstance(kdf, str) else None
    return f"{backend} ({detail})" if detail else backend


def entry_counts(counts: Mapping[str, int]) -> dict[str, int]:
    """The three counts under their fixed names; anything else the back end returned is dropped."""
    return {kind: int(counts.get(kind, 0)) for kind in ENTRY_KINDS}


def status_data(info: VaultInfo, entries: Mapping[str, int] | None) -> dict[str, Any]:
    """The JSON ``data`` of ``vault status``, built field by field."""
    exists = bool(info.exists)
    return {
        "exists": exists,
        "path": str(info.path) if exists and info.path is not None else None,
        "format_version": info.format_version if exists else None,
        "cipher": info.cipher if exists else None,
        "key_backend": key_backend_text(info) if exists else None,
        "created_at": _timestamp(info.created_at) if exists else None,
        "rotated_at": _timestamp(info.rotated_at) if exists else None,
        "size_bytes": info.size_bytes if exists else None,
        "entries": dict(entries) if exists and entries is not None else None,
    }


def _locked() -> PrivacyBlockError:
    return PrivacyBlockError(
        "the vault could not be unlocked",
        code="vault_locked",
        hint="check the keyring entry, the passphrase or the KMS permission",
    )


def unlock_counts(
    ctx: typer.Context, admin: VaultAdmin, info: VaultInfo, state_dir: Path
) -> dict[str, int]:
    """Entry counts of an unlocked vault.

    Raises:
        PrivacyBlockError: ``vault_locked`` when the vault cannot be unlocked, and, without a
            prompt, when it needs a passphrase in a non-interactive session.
    """
    if info.key_backend == PASSPHRASE and not is_interactive(ctx):
        raise _locked()
    try:
        return entry_counts(admin.counts(state_dir))
    except Exception:  # noqa: BLE001 - the reason is not shown; it may describe the key
        raise _locked() from None


def warn_permissions(out: Output, info: VaultInfo, state_dir: Path) -> None:
    """Warn when the vault file or the state directory is open to group or others (POSIX)."""
    if os.name == "nt":
        return
    for path in (info.path, state_dir):
        try:
            mode = path.stat().st_mode if path is not None else 0
        except OSError:
            continue
        if mode & _OTHERS:
            out.warn(
                "vault_permissions",
                f"{path} is accessible by group or others",
                hint="chmod go-rwx on the vault file and the state directory",
            )


def _render(data: Mapping[str, Any]) -> Any:
    def render(console: Console) -> None:
        if not data["exists"]:
            console.print(NO_VAULT, markup=False)
            return
        rows = [
            (key, "-" if data[key] is None else str(data[key])) for key in data if key != "entries"
        ]
        entries = data["entries"]
        if entries is not None:
            rows.append(("entries", ", ".join(f"{kind} {entries[kind]}" for kind in ENTRY_KINDS)))
        console.print(kv_table(None, rows))

    return render


@vault_app.command("status")
def status_command(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Project directory.")] = ".",
    unlock: Annotated[
        bool, typer.Option("--unlock", help="Unlock the vault to count its entries.")
    ] = False,
) -> None:
    """Show metadata of the project's vault; nothing is unlocked without --unlock."""
    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415

    project = Path(target)
    if not project.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    loaded = with_target(ctx, project).loaded
    out = get_output(ctx)
    state_dir = resolve_state_dir(loaded.project_root, loaded.settings.project.state_dir)
    admin = _admin()
    info = admin.info(state_dir)
    entries = unlock_counts(ctx, admin, info, state_dir) if unlock and info.exists else None
    if info.exists:
        warn_permissions(out, info, state_dir)
    data = status_data(info, entries)
    out.result(data, human=_render(data))


# vault rotate and vault destroy (E05-25)

LOCKED_ERROR_NAME: Final = "VaultLockedError"
DESTROYED_LINE: Final = (
    "vault destroyed; results of past scans can no longer be mapped back to original names"
)
BACKUP_LINE: Final = (
    "the file was deleted; any backup copies remain decryptable with the passphrase"
)
NOTHING_TO_DESTROY: Final = "nothing to destroy"


def _is_locked(error: BaseException) -> bool:
    """Whether ``error`` says that the vault could not be unlocked (by class name, see E10)."""
    return any(cls.__name__ == LOCKED_ERROR_NAME for cls in type(error).__mro__)


def running_scans(state_dir: Path, *, now: datetime, timeout_seconds: int) -> list[str]:
    """Scans of ``state_dir`` whose checkpoint says ``running`` and is younger than the timeout.

    An older ``running`` checkpoint was left by a process that died and does not block.
    """
    from codekavach.core.pipeline.resume import load_checkpoint  # noqa: PLC0415
    from codekavach.core.store.artefacts import list_scan_ids  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

    layout = StateLayout(state_dir)
    limit = now - timedelta(seconds=timeout_seconds)
    found = []
    for scan_id in list_scan_ids(layout):
        checkpoint = load_checkpoint(layout, scan_id)
        if (
            checkpoint is not None
            and checkpoint.status == "running"
            and checkpoint.updated_at >= limit
        ):
            found.append(scan_id)
    return found


def stored_scan_count(state_dir: Path) -> int:
    """How many scans have records below ``state_dir``."""
    from codekavach.core.store.artefacts import list_scan_ids  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

    return len(list_scan_ids(StateLayout(state_dir)))


def _refuse_during_scan(cli_ctx: CliContext, state_dir: Path) -> None:
    running = running_scans(
        state_dir,
        now=datetime.now(UTC),
        timeout_seconds=cli_ctx.settings.scan.timeout_seconds,
    )
    if running:
        raise UsageError(
            "a scan is running on this state directory",
            code="scan_in_progress",
            hint="wait for the scan to finish or cancel it",
        )


def _print_lines(console: Console, lines: Sequence[str]) -> None:
    for line in lines:
        console.print(line, markup=False, highlight=False, soft_wrap=True)


def _grouped(number: int) -> str:
    return f"{number:,}".replace(",", " ")


def consequence_lines(
    *, project: str, path: Path, size_bytes: int | None, entries: int | None, scans: int
) -> list[str]:
    """What ``vault destroy`` says before it asks."""
    size = human_size(size_bytes) if size_bytes is not None else "unknown size"
    count = "unknown number of entries" if entries is None else f"{_grouped(entries)} entries"
    return [
        f"This deletes the mapping vault of project '{project}':",
        f"  {path.as_posix()} ({size}, {count}, referenced by {scans} stored scans)",
        "Without it, pseudonyms in stored LLM responses and ledger payloads cannot be mapped "
        "back to",
        "the original names. Reports that were already generated are not affected. "
        "This cannot be undone.",
    ]


def _open(ctx: typer.Context, target: str) -> tuple[CliContext, Path]:
    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415

    project = Path(target)
    if not project.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    cli_ctx = with_target(ctx, project)
    loaded = cli_ctx.loaded
    return cli_ctx, resolve_state_dir(loaded.project_root, loaded.settings.project.state_dir)


@vault_app.command("rotate")
def rotate_command(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Project directory.")] = ".",
    key_backend: Annotated[
        KeyBackend | None,
        typer.Option(
            "--key-backend", case_sensitive=False, help="Move the key to another backend."
        ),
    ] = None,
) -> None:
    """Re-encrypt the vault under a new key. Refused while a scan is running."""
    cli_ctx, state_dir = _open(ctx, target)
    out = get_output(ctx)
    admin = _admin()
    info = admin.info(state_dir)
    if not info.exists:
        raise UsageError(
            "this project has no vault", code="vault_not_found", hint="a scan creates it"
        )
    _refuse_during_scan(cli_ctx, state_dir)
    wanted = key_backend.value if key_backend is not None else None
    if PASSPHRASE in {wanted or info.key_backend, info.key_backend} and not is_interactive(ctx):
        raise UsageError(
            "a passphrase has to be typed on a terminal",
            code="passphrase_needs_terminal",
            hint="run the command on a terminal",
        )
    try:
        result = admin.rotate(state_dir, new_backend=wanted)
    except Exception as error:  # noqa: BLE001 - the text may describe the key; it is not shown
        if _is_locked(error):
            raise _locked() from None
        raise InternalError(
            "the vault could not be re-encrypted; the previous vault is unchanged",
            code="vault_rotate_failed",
        ) from None
    data = {
        "entries": int(result.entries),
        "key_backend": str(result.key_backend),
        "rotated_at": _timestamp(result.rotated_at),
        "previous_rotated_at": _timestamp(result.previous_rotated_at),
    }
    out.result(
        data,
        human=lambda console: console.print(
            f"vault re-encrypted: {data['entries']} entries, key backend {data['key_backend']}, "
            f"rotated at {data['rotated_at']}",
            markup=False,
            soft_wrap=True,
        ),
    )


def _entry_total(admin: VaultAdmin, info: VaultInfo, state_dir: Path) -> int | None:
    """The number of entries when the vault unlocks without a prompt; ``None`` otherwise."""
    if info.key_backend == PASSPHRASE:
        return None
    try:
        return sum(entry_counts(admin.counts(state_dir)).values())
    except Exception:  # noqa: BLE001 - destroying must work for a vault that cannot be unlocked
        return None


@vault_app.command("destroy")
def destroy_command(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Project directory.")] = ".",
    yes: Annotated[
        bool, typer.Option("--yes", help="Delete without asking for the project name.")
    ] = False,
) -> None:
    """Delete the vault; past scans can then no longer be mapped back. Refused during a scan."""
    cli_ctx, state_dir = _open(ctx, target)
    out = get_output(ctx)
    admin = _admin()
    info = admin.info(state_dir)
    if not info.exists:
        out.result(
            {"destroyed": False, "path": None, "keyring_entry_removed": False},
            human=lambda console: console.print(NOTHING_TO_DESTROY, markup=False),
        )
        return
    _refuse_during_scan(cli_ctx, state_dir)
    loaded = cli_ctx.loaded
    project = loaded.settings.project.name or loaded.project_root.name
    lines = consequence_lines(
        project=project,
        path=info.path or state_dir,
        size_bytes=info.size_bytes,
        entries=_entry_total(admin, info, state_dir),
        scans=stored_scan_count(state_dir),
    )
    _print_lines(get_err_console(), lines)
    if not confirm_typed(
        ctx, "Deleting the vault needs confirmation.", expected=project, assume_yes=yes
    ):
        raise UsageError(
            "vault destroy was not confirmed", code="not_confirmed", hint="re-run with --yes"
        )
    try:
        result = admin.destroy(state_dir)
    except Exception:  # noqa: BLE001 - the text is not shown
        raise InternalError("the vault could not be deleted", code="vault_destroy_failed") from None
    removed = bool(result.keyring_entry_removed)
    messages = [DESTROYED_LINE]
    if info.key_backend == PASSPHRASE:
        messages.append(BACKUP_LINE)
    elif info.key_backend == "keyring":
        messages.append(f"keyring entry removed: {'yes' if removed else 'no'}")
    out.result(
        {"destroyed": True, "path": str(result.path), "keyring_entry_removed": removed},
        human=lambda shown: _print_lines(shown, messages),
    )
