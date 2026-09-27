"""``codekavach scan``: turn flags into overrides, call ``run_scan()`` and render a summary.

Owning epic: E05.

The command does no analysis. It validates the target, lets the E03 loader apply the flags (which
enforces privacy floors), refuses remote providers until the consent gate exists (E05-13), calls
``run_scan()`` of E04-16, the one function that builds the context, store and plan, and renders a
summary. It has no route to a provider of its own: it imports neither ``codekavach.llm`` nor
``codekavach.privacy.egress`` (I1, I2), and pipeline modules are imported only when a scan runs.
The JSON result carries counts and paths but no findings or snippets, because CI logs often live
outside the client's environment; findings belong in report files.
"""

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from codekavach.cli.backends import load_backend
from codekavach.cli.context import CliContext, with_overrides, with_target
from codekavach.cli.errors import InternalError, PrivacyBlockError, UsageError
from codekavach.cli.output import TABLE_BOX, Output, get_output, severity_style

if TYPE_CHECKING:
    from codekavach.core.models.summary import ScanSummary

REMOTE_TARGET = re.compile(r"^(https://|git@|ssh://)")
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
SEVERITIES = ("critical", "high", "medium", "low", "info")
LOCAL_KINDS = frozenset({"mock", "replay"})


class FailOn(StrEnum):
    """Accepted values of ``--fail-on``."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    none = "none"


@dataclass(frozen=True)
class ProviderChoice:
    """The provider this scan would use (``None`` id when the LLM is disabled)."""

    id: str | None
    kind: str | None
    remote: bool
    model: str | None


@dataclass(frozen=True)
class CliScanResult:
    """What the command renders, built from ``run_scan()``'s outcome."""

    scan_id: str
    status: str
    summary: "ScanSummary | None"
    report_files: tuple[Path, ...]
    degraded_stages: tuple[str, ...]
    egress_sent: int
    egress_blocked: int
    state_dir: Path
    stages_run: int


def check_target(target: str) -> Path | None:
    """The local path of ``target`` (``None`` for a remote URL); ``UsageError`` otherwise."""
    if target and REMOTE_TARGET.match(target):
        return None
    path = Path(target) if target else None
    if path is not None and (
        path.is_dir() or (path.is_file() and target.lower().endswith(ARCHIVE_SUFFIXES))
    ):
        return path
    raise UsageError(f"scan target does not exist: {target}", code="target_not_found")


def split_formats(values: Sequence[str]) -> tuple[str, ...]:
    """``--format html,pdf --format sarif`` gives ``("html", "pdf", "sarif")``."""
    return tuple(part.strip() for value in values for part in value.split(",") if part.strip())


def resolve_provider(cli_ctx: CliContext) -> ProviderChoice:
    """The provider of this run; ``auto`` means ``mock`` until provider selection (E22)."""
    llm = cli_ctx.settings.llm
    if not llm.enabled:
        return ProviderChoice(id=None, kind=None, remote=False, model=None)
    provider_id = "mock" if llm.default_provider == "auto" else llm.default_provider
    provider = llm.providers[provider_id]
    model = llm.model or provider.model
    return ProviderChoice(
        id=provider_id, kind=provider.kind.value, remote=provider.is_remote, model=model
    )


def _report_files(outcome: Any) -> tuple[Path, ...]:
    try:
        from codekavach.core.pipeline.keys import REPORT_OUTPUTS  # noqa: PLC0415
        from codekavach.core.store.artefacts import OnDiskArtefactStore  # noqa: PLC0415
        from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

        store = OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)
        if not store.has(REPORT_OUTPUTS):
            return ()
        value = store.get_json(REPORT_OUTPUTS)
    except Exception:  # noqa: BLE001 - report files are optional information
        return ()
    items = value.get("files", []) if isinstance(value, dict) else value
    return tuple(Path(str(item)) for item in items) if isinstance(items, list) else ()


def to_cli_result(outcome: Any) -> CliScanResult:
    """Build the rendered result from a ``ScanOutcome``."""
    result, scan = outcome.result, outcome.scan
    summary = scan.summary
    egress = summary.egress if summary is not None else None
    return CliScanResult(
        scan_id=str(scan.id),
        status=str(result.status.value),
        summary=summary,
        report_files=_report_files(outcome),
        degraded_stages=tuple(result.failed_stages()),
        egress_sent=egress.requests_sent if egress else 0,
        egress_blocked=egress.requests_blocked if egress else 0,
        state_dir=Path(outcome.state_dir),
        stages_run=len(result.order),
    )


def execute_scan(
    cli_ctx: CliContext, target: str, *, runner: Callable[..., Any] | None = None
) -> CliScanResult:
    """Run the pipeline through ``run_scan()`` and convert its outcome."""
    from codekavach.core.pipeline.cancel import (  # noqa: PLC0415
        CancellationToken,
        ScanCancelledError,
    )
    from codekavach.core.pipeline.errors import GraphError  # noqa: PLC0415
    from codekavach.core.pipeline.events import InMemoryEventBus  # noqa: PLC0415
    from codekavach.core.pipeline.plan import PlanError  # noqa: PLC0415
    from codekavach.core.pipeline.salt import ScanSalt  # noqa: PLC0415

    run_scan = runner or load_backend(
        "codekavach.core.pipeline.runner", "run_scan", feature="the scan pipeline", epic="E04"
    )
    try:
        outcome = run_scan(
            cli_ctx.loaded,
            target,
            salt=ScanSalt.generate(),
            bus=InMemoryEventBus(),
            cancellation=CancellationToken(),
        )
    except (PlanError, GraphError) as error:
        raise InternalError(
            f"the installed pipeline is invalid: {error}", code="pipeline_invalid"
        ) from None
    status = str(outcome.result.status.value)
    if status == "cancelled":
        raise ScanCancelledError("cancelled")
    if status == "failed":
        failed = ", ".join(outcome.result.failed_stages()) or "unknown"
        raise InternalError(f"the scan failed in stage {failed}", code="scan_failed")
    return to_cli_result(outcome)


def _counts(summary: "ScanSummary | None") -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    if summary is not None:
        for severity, count in summary.by_severity:
            counts[str(severity.value)] = count
    return counts


def scan_data(
    result: CliScanResult, *, target: str, provider: ProviderChoice, privacy_level: str
) -> dict[str, Any]:
    """The ``data`` object of the JSON envelope (counts and paths only)."""
    return {
        "scan_id": result.scan_id,
        "target": target,
        "privacy_level": privacy_level,
        "provider": {
            "id": provider.id,
            "kind": provider.kind,
            "remote": provider.remote,
            "model": provider.model,
        },
        "summary": {
            "findings_total": result.summary.findings_total if result.summary else 0,
            "by_severity": _counts(result.summary),
        },
        "egress": {"recorded": result.egress_sent, "blocked": result.egress_blocked},
        "degraded_stages": list(result.degraded_stages),
        "report_files": [str(path) for path in result.report_files],
        "state_dir": str(result.state_dir),
    }


def _renderer(
    result: CliScanResult, provider: ProviderChoice, privacy_level: str
) -> Callable[[Console], None]:
    def render(console: Console) -> None:
        counts = _counts(result.summary)
        table = Table(
            title=f"Scan {result.scan_id}", show_header=True, header_style="bold", box=TABLE_BOX
        )
        table.add_column("Severity")
        table.add_column("Findings", justify="right")
        for severity in SEVERITIES:
            table.add_row(severity, str(counts[severity]), style=severity_style(severity))
        console.print(table)
        console.print(f"findings: {sum(counts.values())}", markup=False)
        where = "remote" if provider.remote else "local"
        name = f"{provider.id} ({where})" if provider.id else "none (LLM disabled)"
        console.print(
            f"LLM provider: {name}, level {privacy_level}, payloads recorded: "
            f"{result.egress_sent}, blocked by guard: {result.egress_blocked}",
            markup=False,
        )
        if provider.kind in LOCAL_KINDS:
            console.print(
                "provider is local/mock: payloads were recorded but not transmitted", markup=False
            )
        for path in result.report_files:
            console.print(f"report: {path}", markup=False)
        console.print(f"next: codekavach privacy inspect --scan {result.scan_id}", markup=False)
        console.print(f"next: codekavach report --scan {result.scan_id}", markup=False)

    return render


def _warnings(out: Output, result: CliScanResult) -> None:
    if result.stages_run == 0:
        out.warn("no_stages", "no stages are installed; nothing was analysed")
    for stage in result.degraded_stages:
        out.warn("stage_degraded", f"stage {stage} failed; the scan continued without it")
    if result.egress_blocked:
        out.warn(
            "egress_blocked",
            f"the egress guard blocked {result.egress_blocked} payload(s); "
            "those candidates are reported from deterministic evidence",
        )


def scan_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Directory, archive or git URL to scan.")] = ".",
    fail_on: Annotated[
        FailOn | None,
        typer.Option("--fail-on", case_sensitive=False, help="Severity that fails the scan."),
    ] = None,
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Run deterministic engines only.")
    ] = False,
    formats: Annotated[
        list[str] | None,
        typer.Option("--format", help="Report format(s); repeatable or comma-separated."),
    ] = None,
    output_dir: Annotated[
        Path | None, typer.Option("--output-dir", help="Directory for report files.")
    ] = None,
    jobs: Annotated[int | None, typer.Option("--jobs", help="Worker processes.")] = None,
    include: Annotated[
        list[str] | None, typer.Option("--include", help="Glob to include; repeatable.")
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Glob to exclude; repeatable; replaces configured ones."),
    ] = None,
    rules: Annotated[
        list[Path] | None, typer.Option("--rules", help="Extra rule path; repeatable.")
    ] = None,
    engine: Annotated[
        list[str] | None, typer.Option("--engine", help="Engine to enable; repeatable.")
    ] = None,
    skip_engine: Annotated[
        list[str] | None, typer.Option("--skip-engine", help="Engine to disable; repeatable.")
    ] = None,
) -> None:
    """Scan a code base and print a severity summary."""
    from codekavach.config.overrides import overrides_from_flags  # noqa: PLC0415

    local = check_target(target)
    if local is not None:
        with_target(ctx, local if local.is_dir() else local.parent)
    cli_ctx = with_overrides(
        ctx,
        overrides_from_flags(
            fail_on=fail_on.value if fail_on else None,
            no_llm=no_llm,
            formats=split_formats(formats or []),
            output_dir=str(output_dir) if output_dir else None,
            jobs=jobs,
            include=tuple(include or ()),
            exclude=tuple(exclude or ()),
            rules=tuple(str(path) for path in rules or ()),
            engine=tuple(engine or ()),
            skip_engine=tuple(skip_engine or ()),
        ),
    )
    out = get_output(ctx)
    provider = resolve_provider(cli_ctx)
    if provider.remote:
        raise PrivacyBlockError(
            "remote providers require the consent gate, which this build does not include",
            code="consent_unavailable",
        )
    result = execute_scan(cli_ctx, target)
    level = str(cli_ctx.privacy_level.value)
    _warnings(out, result)
    out.result(
        scan_data(result, target=target, provider=provider, privacy_level=level),
        human=_renderer(result, provider, level),
    )
