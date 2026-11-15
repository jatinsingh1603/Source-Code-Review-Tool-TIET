"""``codekavach serve``: run the REST API server and the web dashboard (E32).

Owning epic: E32.

The command builds a ``ServerConfig`` from its options, creates the FastAPI application and runs
it with Uvicorn. On the first start (no user yet) it creates the ``admin`` account. Its password
comes from ``CODEKAVACH_ADMIN_PASSWORD`` or the file named by ``CODEKAVACH_ADMIN_PASSWORD_FILE``;
such a password never reaches stdout, stderr or container logs. Without either the server
generates a random password, prints it once in the start-up banner and keeps it in
``<data dir>/initial-admin-password`` (mode 0600) until the first admin sign-in. In both cases
the first sign-in must choose a new password. ``codekavach admin reset-password`` recovers a
lost one. The server is imported only when the command runs, so ``codekavach --help`` does not
load FastAPI.
"""

from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Final

import typer

from codekavach.cli.errors import UsageError

if TYPE_CHECKING:
    from codekavach.server.state import ServerState

# Seconds Ctrl+C waits for open connections (a dashboard's live scan log) before closing them;
# the running scans are then cancelled and marked failed on the next start.
GRACEFUL_SHUTDOWN_SECONDS: Final = 5


def _admin_lines(server: "ServerState") -> list[str]:
    """What the banner says about the admin account; a password only when it was generated."""
    from codekavach.server.config import (  # noqa: PLC0415
        ADMIN_PASSWORD_ENV,
        ADMIN_PASSWORD_FILE_ENV,
    )

    config = server.config
    generated = server.take_generated_admin_password()
    if generated is not None:
        return [
            "",
            "  First start: the administrator account was created with a generated password.",
            "    user name: admin",
            f"    password:  {generated}",
            "  It is shown this once. You must choose a new password at the first sign-in.",
            f"  Until then it is also kept in {config.initial_password_path} (mode 0600);",
            "  that file is deleted at the first administrator sign-in.",
            "",
        ]
    if server.admin_created:
        return [
            f"  admin login: admin / (password from {ADMIN_PASSWORD_ENV} or "
            f"{ADMIN_PASSWORD_FILE_ENV}); a new one must be chosen at the first sign-in"
        ]
    if config.initial_password_path.is_file():
        return [
            "  admin login: admin / the generated password in "
            f"{config.initial_password_path} (not used yet)"
        ]
    return ["  lost the admin password? run: codekavach admin reset-password"]


def serve_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    host: Annotated[str, typer.Option("--host", help="Address to listen on.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535, help="Port.")] = 8080,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Server data directory (database, scans, uploads)."),
    ] = None,
    ui_dir: Annotated[
        Path | None,
        typer.Option("--ui-dir", help="Built dashboard to serve at / (default: ui/dist)."),
    ] = None,
    workers: Annotated[
        int, typer.Option("--workers", min=1, max=32, help="Scans that may run at once.")
    ] = 2,
    print_openapi: Annotated[
        bool, typer.Option("--print-openapi", help="Print the OpenAPI document and exit.")
    ] = False,
) -> None:
    """Run the REST API server and the web dashboard."""
    try:
        import uvicorn  # noqa: PLC0415

        from codekavach.server.app import create_app  # noqa: PLC0415
        from codekavach.server.config import (  # noqa: PLC0415
            AdminPasswordError,
            ServerConfig,
        )
    except ImportError as error:
        raise UsageError(
            f"the server needs the 'server' extra ({error.name} is missing); install it with "
            "uv sync --extra server or pip install 'codekavach[server]'",
            code="server_extra_missing",
        ) from None

    try:
        config = ServerConfig(workers=workers)
        if data_dir is not None:
            config = ServerConfig(data_dir=data_dir, workers=workers)
    except AdminPasswordError as error:
        raise UsageError(str(error), code="admin_password_invalid") from None
    if ui_dir is not None:
        config.ui_dir = ui_dir
    if print_openapi:
        import json  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as scratch:
            app = create_app(ServerConfig(data_dir=Path(scratch), seed=False, workers=1))
            typer.echo(json.dumps(app.openapi(), indent=2, sort_keys=True))
        return
    try:
        app = create_app(config)
    except AdminPasswordError as error:
        raise UsageError(str(error), code="admin_password_invalid") from None
    shown = "localhost" if host in {"127.0.0.1", "0.0.0.0"} else host  # noqa: S104 - display only
    ui = config.ui_dir if config.ui_dir is not None else "not built (API only)"
    typer.echo(
        "\n".join(
            [
                "CodeKavach server",
                f"  dashboard:   http://{shown}:{port}/",
                f"  API docs:    http://{shown}:{port}/api/docs",
                f"  data dir:    {config.data_dir}",
                f"  dashboard files: {ui}",
                *_admin_lines(app.state.server),
            ]
        ),
        err=True,
    )
    # An open dashboard keeps a live-log stream open for as long as a scan runs; without a
    # limit, Ctrl+C waited for the scan to finish (minutes) before stopping the server.
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        proxy_headers=False,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS,
    )
