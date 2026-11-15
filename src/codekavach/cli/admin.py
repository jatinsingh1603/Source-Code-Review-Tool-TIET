"""``codekavach admin``: recover access to the server's local accounts.

Owning epic: E32.

``admin reset-password`` is the recovery path when nobody can sign in as an administrator any
more. It works on the server's data directory, so whoever may read and write that directory may
run it; it needs no running server and no network. It sets a new password for one account
(generated, or read from standard input), marks it as temporary so the account must choose its
own at the next sign-in, revokes the account's sessions and personal tokens, and writes an audit
event. Only the scrypt hash is stored. A generated password is printed once, to standard output.
"""

import sys
from pathlib import Path
from typing import Annotated, Final

import typer

from codekavach.cli.errors import UsageError

admin_app = typer.Typer(
    help="Recover access to the server's local accounts.",
    no_args_is_help=True,
)

CLI_ACTOR: Final = "cli:admin"


def _read_password_from_stdin(minimum: int) -> str:
    lines = sys.stdin.read().splitlines()
    value = lines[0].strip() if lines else ""
    if len(value) < minimum:
        raise UsageError(
            f"the password read from standard input needs at least {minimum} characters",
            code="password_too_short",
        )
    return value


@admin_app.command("reset-password")
def reset_password_command(
    username: Annotated[
        str, typer.Option("--username", "-u", help="Account whose password is reset.")
    ] = "admin",
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Server data directory (default: $CODEKAVACH_SERVER_DATA_DIR or the platform "
            "data directory).",
        ),
    ] = None,
    password_stdin: Annotated[
        bool,
        typer.Option(
            "--password-stdin",
            help="Read the new password from the first line of standard input instead of "
            "generating one.",
        ),
    ] = False,
    activate: Annotated[
        bool, typer.Option("--activate", help="Also re-enable the account when it is disabled.")
    ] = False,
) -> None:
    """Set a new temporary password for a server account.

    The account must choose its own password at the next sign-in; its open sessions and
    personal API tokens stop working. A generated password is printed once.
    """
    try:
        from sqlalchemy import func, select  # noqa: PLC0415

        from codekavach.server import audit  # noqa: PLC0415
        from codekavach.server.auth.passwords import hash_password  # noqa: PLC0415
        from codekavach.server.auth.tokens import revoke_user_tokens  # noqa: PLC0415
        from codekavach.server.config import (  # noqa: PLC0415
            INITIAL_PASSWORD_FILE,
            MIN_PASSWORD_LENGTH,
            default_data_dir,
        )
        from codekavach.server.db.engine import Database  # noqa: PLC0415
        from codekavach.server.db.models import User  # noqa: PLC0415
        from codekavach.server.state import generate_password  # noqa: PLC0415
    except ImportError as error:
        raise UsageError(
            f"the server needs the 'server' extra ({error.name} is missing); install it with "
            "uv sync --extra server or pip install 'codekavach[server]'",
            code="server_extra_missing",
        ) from None

    root = (data_dir or default_data_dir()).expanduser().resolve()
    database = root / "server.db"
    if not database.is_file():
        raise UsageError(
            f"no server database in {root}",
            code="server_data_missing",
            hint="pass --data-dir with the directory `codekavach serve` uses",
        )
    password = (
        _read_password_from_stdin(MIN_PASSWORD_LENGTH) if password_stdin else generate_password()
    )
    db = Database(database)
    try:
        with db.transaction() as session:
            user = session.scalars(
                select(User).where(func.lower(User.username) == username.lower())
            ).first()
            if user is None:
                known = ", ".join(sorted(session.scalars(select(User.username)))) or "none"
                raise UsageError(
                    f"no account named {username}",
                    code="user_not_found",
                    hint=f"accounts on this server: {known}",
                )
            if not user.active and not activate:
                raise UsageError(
                    f"the account {user.username} is disabled",
                    code="user_disabled",
                    hint="add --activate to re-enable it with the new password",
                )
            user.password_hash = hash_password(password)
            user.must_change_password = True
            user.active = True
            revoked = revoke_user_tokens(session, user.id)
            name, user_id, role = user.username, user.id, user.role
        audit.record(
            db,
            actor=CLI_ACTOR,
            action="user.password_reset",
            resource=user_id,
            client="local",
            detail={"revoked": revoked, "generated": not password_stdin},
        )
        audit.flush(db)
    finally:
        db.dispose()
    # A password generated at first start that was never used is now stale.
    (root / INITIAL_PASSWORD_FILE).unlink(missing_ok=True)
    typer.echo(
        f"Password of {name} ({role}) reset; {revoked} session(s) and token(s) revoked.", err=True
    )
    if password_stdin:
        typer.echo("The account must choose a new password at the next sign-in.", err=True)
        return
    typer.echo("Temporary password (shown once; a new one must be chosen at sign-in):", err=True)
    typer.echo(password)
