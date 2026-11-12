"""``codekavach sync github``: send findings to the client's GitHub repository (E05-27).

Owning epic: E05.

The command grammar is fixed here; the back end is
``codekavach.integrations.github.run_github_sync`` of epic E34. Until that epic has landed the
command validates its arguments and ends with ``backend_unavailable``. The token is not an
option: it comes from the secret reference ``integrations.github.token``. The command refuses
``--offline``, because it needs the network.
"""

from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from codekavach.cli.backends import load_backend
from codekavach.cli.context import get_context, with_target
from codekavach.cli.deferred import (
    check_project,
    check_repository,
    check_scan,
)
from codekavach.cli.errors import UsageError
from codekavach.cli.output import TABLE_BOX, get_output

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
    A real run needs the network and refuses --offline; with --dry-run it reads the existing
    issues when a token is set (GET only) and prints what would be created, updated or closed.
    """
    check_scan(scan)
    check_repository(repo)
    check_project(project)
    offline = get_context(ctx).offline
    if offline and not dry_run:
        raise UsageError(
            "sync github needs the network and cannot run with --offline",
            code="offline_network_conflict",
            hint="drop --offline, or use --dry-run, which then reads nothing from GitHub",
        )
    path = Path(target)
    if not path.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    settings = with_target(ctx, path).settings
    backend = load_backend(
        "codekavach.integrations.github", "run_github_sync", feature="GitHub sync", epic="E34"
    )
    result = backend(
        target=path,
        scan=scan,
        repo=repo or settings.integrations.github.repository,
        project=project,
        issues=issues,
        board=board,
        dry_run=dry_run,
        max_issues=max_issues,
        settings=settings,
        offline=offline,
    )
    get_output(ctx).result(result, human=lambda console: _render(console, result))


def _render(console: Console, result: Mapping[str, Any]) -> None:
    mode = "dry run: nothing was changed" if result.get("dry_run") else "applied"
    console.print(
        f"{result.get('repo')}: {result.get('created', 0)} to create, "
        f"{result.get('updated', 0)} to update, {result.get('closed', 0)} to close ({mode})",
        markup=False,
    )
    table = Table(show_header=True, header_style="bold", box=TABLE_BOX, pad_edge=False)
    for column in ("action", "severity", "issue", "title"):
        table.add_column(column, overflow="fold")
    for item in result.get("items", ()):
        number = f"#{item['number']}" if item.get("number") else "-"
        table.add_row(item["action"], item.get("severity", ""), number, item.get("title", ""))
    console.print(table)
    for note in result.get("notes", ()):
        console.print(f"note: {note}", markup=False)
