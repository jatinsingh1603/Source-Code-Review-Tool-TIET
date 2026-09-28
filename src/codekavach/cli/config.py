"""``codekavach config trust|untrust``: the persistent project trust store (E03-27).

Owning epic: E03.

Trusting a project records its root with the SHA-256 of its configuration file, so the grant
lapses as soon as the file changes (direnv-style). ``trust`` first shows which restricted keys,
escaping paths and loosened privacy settings the file contains (keys only, never values) and asks
for confirmation unless ``--yes``; without a terminal it refuses instead of waiting. E05-19 mounts
``config_app`` on the root application as ``config``.
"""

import json
import os
import sys
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from codekavach.cli.console import get_console, get_err_console
from codekavach.cli.errors import UsageError
from codekavach.cli.output import simple_table
from codekavach.config.errors import ConfigError, ConfigIssue
from codekavach.config.paths import find_project_config, project_root_for, user_config_file
from codekavach.config.provenance import Layer
from codekavach.config.toml_source import read_toml
from codekavach.config.trust import TrustStore, project_violations, store_path

config_app = typer.Typer(help="Inspect and manage configuration.", no_args_is_help=True)

REASONS = {
    "CK-CFG-040": "restricted keys",
    "CK-CFG-041": "loosened privacy settings",
}
ESCAPES = "paths that escape the project"


class ListFormat(StrEnum):
    """Output formats of ``trust --list``."""

    text = "text"
    json = "json"


def _store() -> TrustStore:
    try:
        return TrustStore.load(store_path(os.environ))
    except ConfigError as error:
        issue = error.issues[0]
        raise UsageError(
            f"{issue.code.value}: {issue.message} ({issue.source})",
            code="trust_store_corrupt",
            hint=issue.hint,
        ) from None


def _project(path: Path | None) -> tuple[Path, Path]:
    """The project root and its configuration file, discovered like the loader does."""
    start = (path or Path.cwd()).resolve()
    found = find_project_config(start)
    if found is None:
        raise UsageError(
            "no codekavach.toml found for this project",
            code="no_project_config",
            hint="run the command inside the project, or pass its path",
        )
    return project_root_for(start), found


def _user_layer() -> Layer | None:
    path = user_config_file(os.environ)
    if not path.is_file():
        return None
    document = read_toml(path)
    return Layer(name="user", source=str(path), data=document.data, text=document.text)


def _grouped(issues: Sequence[ConfigIssue]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for issue in issues:
        reason = ESCAPES if "escapes" in issue.message else REASONS[issue.code.value]
        key = issue.key or "(unknown key)"
        if key not in groups.setdefault(reason, []):
            groups[reason].append(key)
    return groups


def _list(output_format: ListFormat) -> None:
    entries = _store().entries()
    if output_format is ListFormat.json:
        document = {
            "projects": [
                {"root": e.root, "sha256": e.sha256, "trusted_at": e.trusted_at} for e in entries
            ]
        }
        sys.stdout.write(json.dumps(document, indent=2) + "\n")
        return
    if not entries:
        get_console().print("no trusted projects", markup=False)
        return
    rows = [(e.root, e.sha256[:12], e.trusted_at) for e in entries]
    get_console().print(simple_table(("project", "sha256", "trusted at"), rows))


@config_app.command("trust")
def trust(
    path: Annotated[Path | None, typer.Argument(help="Project directory (default: here).")] = None,
    yes: Annotated[bool, typer.Option("--yes", help="Trust without asking.")] = False,
    list_: Annotated[
        bool, typer.Option("--list", help="List trusted projects instead of trusting one.")
    ] = False,
    output_format: Annotated[
        ListFormat, typer.Option("--format", help="Format of --list.")
    ] = ListFormat.text,
) -> None:
    """Trust a project's configuration file, as it is now."""
    if list_:
        _list(output_format)
        return
    store = _store()
    root, config_file = _project(path)
    document = read_toml(config_file, confine_to=root.resolve())
    layer = Layer(
        name="project",
        source=str(config_file),
        data=document.data,
        text=document.text,
        sha256=document.sha256,
    )
    issues = project_violations(layer, project_root=root, user=_user_layer())
    console = get_err_console()
    console.print(f"project: {root}", markup=False)
    console.print(f"file:    {config_file}", markup=False)
    groups = _grouped(issues)
    if not groups:
        console.print("the file sets nothing that needs trust", markup=False)
    for reason, keys in groups.items():
        console.print(f"{reason}:", markup=False)
        for key in keys:
            console.print(f"  {key}", markup=False)
    if not yes:
        if not sys.stdin.isatty():
            raise UsageError(
                "standard input is not a terminal, so trust cannot be confirmed",
                code="confirmation_required",
                hint="review the file, then run again with --yes",
            )
        if not typer.confirm("Trust this configuration file as it is now?", default=False):
            raise typer.Abort
    store.grant(root, document.sha256)
    get_console().print(f"trusted {root}", markup=False)


@config_app.command("untrust")
def untrust(
    path: Annotated[Path | None, typer.Argument(help="Project directory (default: here).")] = None,
) -> None:
    """Forget the trust granted to a project."""
    store = _store()
    root = project_root_for((path or Path.cwd()).resolve())
    if store.revoke(root):
        get_console().print(f"no longer trusted: {root}", markup=False)
    else:
        get_console().print(f"was not trusted: {root}", markup=False)
