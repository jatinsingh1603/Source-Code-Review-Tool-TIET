"""``codekavach plugins list|check``: which plugins are installed, and whether they form a pipeline.

Owning epic: E05.

``list`` renders the rows of the plugin registry: one line per entry point with its status
(``ok``, ``error``, ``shadowed`` or ``disabled``). ``check`` asks whether the discovered stages
resolve into a valid order, using the orchestrator's own functions (``diagnose``,
``build_graph`` and ``resolve_order``), so the command cannot disagree with a scan. It reports
the resolved order, plugins that failed to load, name collisions, unmet requirements, duplicate
providers and a dependency cycle. It exits 1 when the order does not resolve or a plugin failed
to load; ``--strict`` also fails on collisions.

Both commands load every installed plugin that the ``[plugins]`` settings allow, which imports
third-party code exactly as a scan would; ``--help``, ``--version`` and completion do not.
Plugin code is untrusted text: a failed plugin is reported by its entry-point coordinates and the
class name of its exception, never by the message, with or without ``--debug``.
"""

import dataclasses
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Final

import typer
from rich.console import Console

from codekavach.cli.backends import load_backend
from codekavach.cli.context import CliContext, get_context
from codekavach.cli.errors import ThresholdExceeded
from codekavach.cli.output import get_output

COLUMNS: Final = ("kind", "name", "dist", "version", "status", "error")
ARROW: Final = " > "

plugins_app = typer.Typer(
    help="Inspect installed plugins and check that their stages form a pipeline.\n\n"
    "Loads every installed plugin that the [plugins] settings allow.",
    invoke_without_command=True,
    no_args_is_help=False,
)


def build_registry(cli_ctx: CliContext) -> Any:
    """The plugin registry for the effective settings (so the allow-list applies).

    Raises:
        BackendUnavailableError: this build has no plugin registry (exit 2).
    """
    factory = load_backend(
        "codekavach.core.plugins.registry",
        "registry_from_environment",
        feature="the plugin registry",
        epic="E04",
    )
    return factory(cli_ctx.settings)


# --- the pipeline check ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineCheck:
    """What ``plugins check`` found; plain data, safe to print and to serialise."""

    order: tuple[str, ...]
    load_errors: tuple[dict[str, str], ...]
    collisions: tuple[dict[str, str], ...]
    unsatisfied: tuple[dict[str, str], ...]
    duplicate_providers: tuple[dict[str, Any], ...]
    cycle: tuple[str, ...] | None

    @property
    def resolves(self) -> bool:
        """True when the stages form a valid order (a cycle or an unmet requirement says no)."""
        return not (self.unsatisfied or self.duplicate_providers or self.cycle)

    def failed(self, *, strict: bool = False) -> bool:
        """Whether the check fails: no valid order, a load error, or (strict) a collision."""
        return not self.resolves or bool(self.load_errors) or (strict and bool(self.collisions))

    def to_data(self) -> dict[str, Any]:
        """The JSON ``data`` of the command."""
        return {
            "order": list(self.order),
            "load_errors": list(self.load_errors),
            "collisions": list(self.collisions),
            "unsatisfied": list(self.unsatisfied),
            "duplicate_providers": list(self.duplicate_providers),
            "cycle": list(self.cycle) if self.cycle else None,
        }


def _coordinates(spec: Any) -> dict[str, str]:
    return {
        "group": str(spec.group),
        "name": str(spec.name),
        "dist": str(spec.dist_name),
        "version": str(spec.dist_version),
    }


def _open_cycle(names: tuple[str, ...]) -> tuple[str, ...]:
    """The stages of a cycle without the repeated first stage that closes it."""
    return names[:-1] if len(names) > 1 and names[0] == names[-1] else names


def check_registry(registry: Any) -> PipelineCheck:
    """Resolve the stages of ``registry`` with the orchestrator's own functions.

    Loads every plugin of the registry. A plugin that fails to load is reported by its
    coordinates and the class name of its exception (``PluginFailure`` holds nothing more).
    """
    from codekavach.core.pipeline.graph import (  # noqa: PLC0415 - keeps start-up light
        build_graph,
        diagnose,
        resolve_order,
    )
    from codekavach.core.pipeline.keys import TARGET  # noqa: PLC0415

    infos = list(registry.stage_infos().values())
    problems = diagnose(infos, initial_keys=(TARGET,))
    unsatisfied = tuple(
        {"stage": str(problem.stage), "key": str(problem.key)}
        for problem in problems
        if problem.code == "unsatisfied_requirement"
    )
    duplicates = tuple(
        {"key": str(problem.key), "stages": [str(name) for name in problem.detail_names]}
        for problem in problems
        if problem.code == "duplicate_provider"
    )
    cycles = [_open_cycle(problem.detail_names) for problem in problems if problem.code == "cycle"]
    order: tuple[str, ...] = ()
    if not problems:
        order = tuple(resolve_order(build_graph(infos, initial_keys=(TARGET,))))
    failures = tuple(
        {
            **_coordinates(failure.spec),
            "stage": str(failure.stage),
            "error_type": failure.error_type,
        }
        for failure in registry.failures()
    )
    return PipelineCheck(
        order=order,
        load_errors=failures,
        collisions=tuple(_coordinates(spec) for spec in registry.shadowed()),
        unsatisfied=unsatisfied,
        duplicate_providers=duplicates,
        cycle=tuple(cycles[0]) if cycles else None,
    )


# --- rendering ------------------------------------------------------------------------------------


def _table(columns: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    """Aligned plain-text lines: a header and one line per row, never folded."""
    widths = [len(column) for column in columns]
    for row in rows:
        widths = [max(width, len(cell)) for width, cell in zip(widths, row, strict=True)]
    return [
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        for line in (columns, *rows)
    ]


def _print(console: Console, lines: Sequence[str]) -> None:
    for line in lines:
        console.print(line, markup=False, highlight=False, soft_wrap=True)


def _row_data(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return dict(row)
    data: dict[str, Any] = dataclasses.asdict(row)
    return data


def _where(entry: dict[str, str]) -> str:
    return f"{entry['group']} / {entry['name']} ({entry['dist']} {entry['version']})"


def _check_lines(report: PipelineCheck) -> list[str]:
    lines = [f"order: {ARROW.join(report.order) if report.order else 'none'}"]
    lines.append(f"load errors: {len(report.load_errors) or 'none'}")
    lines.extend(f"  {_where(entry)}: {entry['error_type']}" for entry in report.load_errors)
    if report.collisions:
        lines.append(f"collisions: {len(report.collisions)}")
        lines.extend(f"  {_where(entry)} lost a name collision" for entry in report.collisions)
    if report.unsatisfied:
        lines.append("unsatisfied:")
        lines.extend(
            f"  stage {entry['stage']} requires {entry['key']}" for entry in report.unsatisfied
        )
    else:
        lines.append("unsatisfied: none")
    if report.duplicate_providers:
        lines.append("duplicate providers:")
        lines.extend(
            f"  {entry['key']} is provided by {', '.join(entry['stages'])}"
            for entry in report.duplicate_providers
        )
    if report.cycle:
        lines.append(f"cycle: {ARROW.join((*report.cycle, report.cycle[0]))}")
    return lines


# --- commands -------------------------------------------------------------------------------------


def run_list(ctx: typer.Context) -> None:
    """Render the registry rows: a table, or ``data.plugins`` in the JSON envelope."""
    out = get_output(ctx)
    registry = build_registry(get_context(ctx))
    rows = [_row_data(row) for row in registry.rows()]

    def render(console: Console) -> None:
        if not rows:
            console.print("no plugin is installed", markup=False)
            return
        table = [
            (
                str(row["kind"]),
                str(row["name"]),
                str(row["dist"]),
                str(row["version"]),
                str(row["status"]),
                str(row.get("error_type") or "-"),
            )
            for row in rows
        ]
        _print(console, _table(COLUMNS, table))

    out.result({"plugins": rows}, human=render)


@plugins_app.callback(invoke_without_command=True)
def plugins_default(ctx: typer.Context) -> None:
    """Without a sub-command, list the plugins."""
    if ctx.invoked_subcommand is None:
        run_list(ctx)


@plugins_app.command("list")
def list_command(ctx: typer.Context) -> None:
    """List every installed plugin with its status. Loads every installed plugin."""
    run_list(ctx)


@plugins_app.command("check")
def check_command(
    ctx: typer.Context,
    strict: Annotated[
        bool, typer.Option("--strict", help="Also fail when two plugins share a name.")
    ] = False,
) -> None:
    """Check that the installed stages resolve into a valid order. Loads every installed plugin."""
    out = get_output(ctx)
    report = check_registry(build_registry(get_context(ctx)))
    out.result(report.to_data(), human=lambda console: _print(console, _check_lines(report)))
    if report.failed(strict=strict):
        raise ThresholdExceeded("the installed plugins do not form a runnable pipeline")
