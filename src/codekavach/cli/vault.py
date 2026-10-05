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
"""

import os
import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Final, Protocol

import typer
from rich.console import Console

from codekavach.cli.backends import load_backend
from codekavach.cli.context import with_target
from codekavach.cli.errors import PrivacyBlockError, UsageError
from codekavach.cli.output import Output, get_output, kv_table
from codekavach.cli.prompts import is_interactive

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
