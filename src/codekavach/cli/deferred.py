"""Shared pieces of the commands whose back ends later epics deliver (E05-27).

Owning epic: E05.

``sync github``, ``eval detection``, ``eval leakage`` and ``demo`` fix their grammar now, so the
GitHub Action, the evaluation scripts and the demo runbook can be written against it. Each command
validates its arguments without a back end and then asks ``load_backend`` for the function of the
owning epic. While that epic has not landed the command ends with ``backend_unavailable`` (exit 2)
and names the epic in its hint; nothing is simulated, no file is written and no connection is
opened. When the back end is present it is called once with the parsed arguments and its report is
rendered through ``Output.result``.
"""

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import typer

from codekavach.cli.backends import load_backend
from codekavach.cli.errors import UsageError
from codekavach.cli.output import get_output

LEVELS: Final = ("L0", "L1", "L2", "L3", "L4")
REPOSITORY: Final = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SCAN_ID: Final = re.compile(r"^scan_[0-9A-HJKMNP-TV-Z]{26}$")
LATEST: Final = "latest"
NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PROJECT_NUMBER: Final = re.compile(r"^[0-9]{1,9}$")
PROJECT_URL: Final = re.compile(r"^https://[^\s/]+/\S+$")


def check_levels(values: Sequence[str]) -> list[str]:
    """Normalise ``--level`` values to ``L0`` to ``L4``, in the order given.

    Raises:
        UsageError: ``bad_level`` for a value that is not one of the five levels.
    """
    levels: list[str] = []
    for value in values:
        level = value.strip().upper()
        if level not in LEVELS:
            raise UsageError(f"--level must be one of {', '.join(LEVELS)}", code="bad_level")
        if level not in levels:
            levels.append(level)
    return levels


def check_repository(value: str | None) -> str | None:
    """``OWNER/NAME`` or ``None``.

    Raises:
        UsageError: ``bad_repo`` when the value is not of the form ``OWNER/NAME``.
    """
    if value is not None and REPOSITORY.match(value) is None:
        raise UsageError("--repo must look like OWNER/NAME", code="bad_repo")
    return value


def check_scan(value: str) -> str:
    """A scan id or ``latest``.

    Raises:
        UsageError: ``bad_scan`` for anything else.
    """
    if value != LATEST and SCAN_ID.match(value) is None:
        raise UsageError("--scan must be a scan id or 'latest'", code="bad_scan")
    return value


def check_project(value: str | None) -> str | None:
    """A project number or an ``https`` project URL, or ``None``.

    Raises:
        UsageError: ``bad_project`` for anything else.
    """
    if value is not None and not (PROJECT_NUMBER.match(value) or PROJECT_URL.match(value)):
        raise UsageError("--project must be a project number or an https URL", code="bad_project")
    return value


def looks_like_path(text: str) -> bool:
    """Whether a name-or-path argument is meant as a path."""
    return any(separator in text for separator in ("/", "\\")) or text.startswith((".", "~"))


def check_dataset(value: str, *, option: str = "--dataset") -> str:
    """A dataset or fixture name, or a path that exists.

    Raises:
        UsageError: ``dataset_not_found`` for a path that does not exist, ``bad_dataset`` for a
            name that is not a plain name.
    """
    if looks_like_path(value):
        if not Path(value).expanduser().exists():
            raise UsageError(f"{option} path does not exist: {value}", code="dataset_not_found")
    elif NAME.match(value) is None:
        raise UsageError(f"{option} must be a name or an existing path", code="bad_dataset")
    return value


def check_names(values: Sequence[str], *, option: str) -> list[str]:
    """Plain names for a repeatable option, without duplicates, in the order given.

    Raises:
        UsageError: ``bad_name`` for a value that is not a plain name.
    """
    names: list[str] = []
    for value in values:
        if NAME.match(value) is None:
            raise UsageError(f"{option} takes plain names", code="bad_name")
        if value not in names:
            names.append(value)
    return names


def run_backend(
    ctx: typer.Context,
    *,
    module: str,
    attribute: str,
    feature: str,
    epic: str,
    arguments: Mapping[str, Any],
) -> None:
    """Call the back end of the owning epic once, or end with ``backend_unavailable``.

    Raises:
        BackendUnavailableError: the module or the function is not part of this build.
    """
    backend = load_backend(module, attribute, feature=feature, epic=epic)
    get_output(ctx).result(backend(**arguments))
