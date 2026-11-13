"""``codekavach serve``: run the REST API server and the web dashboard (E32).

Owning epic: E32.

The command builds a ``ServerConfig`` from its options, creates the FastAPI application and runs
it with Uvicorn. On first start it creates the ``admin`` account (password from
``CODEKAVACH_ADMIN_PASSWORD``, default ``kavach-admin``) and the "KavachBank (sample)" project and
prints the address. It prints the admin password only when it is the public default; a password
set through the environment never reaches stdout, stderr or container logs. The server is
imported only when the command runs, so ``codekavach --help`` does not load FastAPI.
"""

from pathlib import Path
from typing import Annotated

import typer

from codekavach.cli.errors import UsageError


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
            ADMIN_PASSWORD_ENV,
            DEFAULT_ADMIN_PASSWORD,
            ServerConfig,
        )
    except ImportError as error:
        raise UsageError(
            f"the server needs the 'server' extra ({error.name} is missing); install it with "
            "uv sync --extra server or pip install 'codekavach[server]'",
            code="server_extra_missing",
        ) from None

    config = ServerConfig(workers=workers)
    if data_dir is not None:
        config = ServerConfig(data_dir=data_dir, workers=workers)
    if ui_dir is not None:
        config.ui_dir = ui_dir
    if print_openapi:
        import json  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as scratch:
            app = create_app(ServerConfig(data_dir=Path(scratch), seed=False, workers=1))
            typer.echo(json.dumps(app.openapi(), indent=2, sort_keys=True))
        return
    app = create_app(config)
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
                # Only the public default is shown: a chosen password must not reach the logs.
                f"  admin login: admin / {DEFAULT_ADMIN_PASSWORD}  (default; change it in Users)"
                if config.admin_password == DEFAULT_ADMIN_PASSWORD
                else f"  admin login: admin / (password from {ADMIN_PASSWORD_ENV})",
            ]
        ),
        err=True,
    )
    uvicorn.run(app, host=host, port=port, log_level="info", proxy_headers=False)
