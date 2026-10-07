"""``codekavach sync github``: send findings to the client's GitHub repository (E05-27).

Owning epic: E05.

The command grammar is fixed here; the back end is
``codekavach.integrations.github.run_github_sync`` of epic E34. Until that epic has landed the
command validates its arguments and ends with ``backend_unavailable``. The token is not an
option: it comes from the secret reference ``integrations.github.token``. The command refuses
``--offline``, because it needs the network.
"""

from pathlib import Path
from typing import Annotated

import typer

from codekavach.cli.context import get_context, with_target
from codekavach.cli.deferred import (
    check_project,
    check_repository,
    check_scan,
    run_backend,
)
from codekavach.cli.errors import UsageError

sync_app = typer.Typer(help="Send findings to a client system.", no_args_is_help=True)


@sync_app.command("github")
def github_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Project directory.")] = ".",
    scan: Annotated[
        str, typer.Option("--scan", metavar="[SCAN_ID|latest]", help="The scan to send.")
    ] = "latest",
    repo: Annotated[
        str | None,
        typer.Option(
            "--repo",
            metavar="OWNER/NAME",
            help="Repository for the issues; default: integrations.github.repository.",
        ),
    ] = None,
    project: Annotated[
        str | None,
        typer.Option("--project", metavar="NUMBER_OR_URL", help="Projects v2 board to update."),
    ] = None,
    issues: Annotated[
        bool, typer.Option("--issues/--no-issues", help="Create or update one issue per finding.")
    ] = True,
    board: Annotated[
        bool, typer.Option("--board/--no-board", help="Place the items on the project board.")
    ] = True,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would change; change nothing.")
    ] = False,
    max_issues: Annotated[
        int | None,
        typer.Option("--max-issues", min=1, help="Create or update at most this many issues."),
    ] = None,
) -> None:
    """Create or update GitHub issues for a scan's findings and place them on a board.

    Creates or updates one issue per finding in the client's repository and places the items on
    the client's Projects v2 board. It does not modify code, open pull requests or push commits.
    The token comes from the secret reference integrations.github.token, never from an option.
    It needs the network and refuses --offline. Delivered by epic E34.
    """
    check_scan(scan)
    check_repository(repo)
    check_project(project)
    if get_context(ctx).offline:
        raise UsageError(
            "sync github needs the network and cannot run with --offline",
            code="offline_network_conflict",
            hint="drop --offline, or sync from a machine that may connect",
        )
    path = Path(target)
    if not path.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    settings = with_target(ctx, path).settings
    run_backend(
        ctx,
        module="codekavach.integrations.github",
        attribute="run_github_sync",
        feature="GitHub sync",
        epic="E34",
        arguments={
            "target": path,
            "scan": scan,
            "repo": repo if repo is not None else settings.integrations.github.repository,
            "project": project,
            "issues": issues,
            "board": board,
            "dry_run": dry_run,
            "max_issues": max_issues,
            "settings": settings,
        },
    )
