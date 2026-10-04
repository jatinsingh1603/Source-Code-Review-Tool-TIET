"""``codekavach scan``: turn flags into overrides, call ``run_scan()`` and render a summary.

Owning epic: E05.

The command does no analysis. It validates the target, lets the E03 loader apply the flags (which
enforces privacy floors), passes the consent gate before a remote provider is used (E05-13), calls
``run_scan()`` of E04-16, the one function that builds the context, store and plan, and renders a
summary. It has no route to a provider of its own: it imports neither ``codekavach.llm`` nor
``codekavach.privacy.egress`` (I1, I2), and pipeline modules are imported only when a scan runs.
The JSON result carries counts and paths but no findings or snippets, because CI logs often live
outside the client's environment; findings belong in report files.

The exit code is decided once, after the result is rendered, by ``final_exit_code`` (E05-10):
4 over 3 over 1 over 0. The severity gate counts findings whose status is ``open`` or
``confirmed`` and compares their final severity with ``scan.fail_on``. It reads status and
severity only, never an LLM verdict: a deterministic finding is not waved through because a model
disagreed (ARCHITECTURE section 7). ``--strict-privacy`` turns a guard refusal into exit 3; the
refusal itself is fail-closed with or without the flag (I4).
"""

import contextlib
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

import typer
from rich.console import Console
from rich.table import Table

from codekavach.cli.backends import load_backend
from codekavach.cli.consent import EgressConsent, ensure_egress_consent
from codekavach.cli.context import CliContext, with_overrides, with_target
from codekavach.cli.errors import (
    CliError,
    InternalError,
    PrivacyBlockError,
    ThresholdExceeded,
    UsageError,
)
from codekavach.cli.exit_codes import ExitCode
from codekavach.cli.onboarding import maybe_show_first_run_notice
from codekavach.cli.output import TABLE_BOX, Output, get_output, severity_style
from codekavach.cli.progress import ProgressMode, progress_listener
from codekavach.cli.signals import report_cancelled, resume_refusal, scan_salt
from codekavach.core.models.enums import FindingStatus, Severity

if TYPE_CHECKING:
    from codekavach.core.models.finding import Finding
    from codekavach.core.models.summary import ScanSummary

REMOTE_TARGET = re.compile(r"^(https://|git@|ssh://)")
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
SEVERITIES = ("critical", "high", "medium", "low", "info")
LOCAL_KINDS = frozenset({"mock", "replay"})
COUNTED_STATUSES = frozenset({FindingStatus.OPEN, FindingStatus.CONFIRMED})


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
    findings: "tuple[Finding, ...]" = ()


@dataclass(frozen=True)
class ThresholdResult:
    """The severity gate applied to the findings of one scan."""

    exceeded: bool
    threshold: Severity | Literal["none"]
    counted_at_or_above: int
    worst: Severity | None
    not_counted: int = 0

    @property
    def fail_on(self) -> str:
        """The threshold as text (``high``, ``none``)."""
        return "none" if self.threshold == "none" else self.threshold.value


def evaluate_threshold(
    findings: "Iterable[Finding]", fail_on: Severity | Literal["none"]
) -> ThresholdResult:
    """Whether the counted findings reach ``fail_on``.

    Counted findings have status ``open`` or ``confirmed``; ``false_positive``, ``accepted_risk``,
    ``suppressed`` and ``fixed`` never trigger the gate. ``worst`` is the highest severity among
    the counted findings. ``none`` disables the gate.
    """
    items = list(findings)
    counted = [finding.severity for finding in items if finding.status in COUNTED_STATUSES]
    not_counted = len(items) - len(counted)
    worst = max(counted, default=None)
    if fail_on == "none":
        return ThresholdResult(False, "none", 0, worst, not_counted)
    at_or_above = sum(1 for severity in counted if severity >= fail_on)
    return ThresholdResult(at_or_above > 0, fail_on, at_or_above, worst, not_counted)


def final_exit_code(
    outcome: CliScanResult, threshold: ThresholdResult, *, strict: bool, strict_privacy: bool
) -> ExitCode:
    """The exit code of a rendered scan; the single decision point (4 over 3 over 1 over 0)."""
    if strict and outcome.degraded_stages:
        return ExitCode.INTERNAL
    if strict_privacy and outcome.egress_blocked > 0:
        return ExitCode.PRIVACY_BLOCK
    if threshold.exceeded:
        return ExitCode.FINDINGS
    return ExitCode.OK


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


def _findings(outcome: Any) -> "tuple[Finding, ...]":
    """The findings of the scan, or none when no stage produced a readable ``findings`` list."""
    try:
        from codekavach.core.models.finding import Finding  # noqa: PLC0415
        from codekavach.core.pipeline.keys import FINDINGS  # noqa: PLC0415
        from codekavach.core.store.artefacts import OnDiskArtefactStore  # noqa: PLC0415
        from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

        store = OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)
        if not store.has(FINDINGS):
            return ()
        return tuple(store.get_list(FINDINGS, Finding))
    except Exception:  # noqa: BLE001 - without findings the gate has nothing to count
        return ()


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
        findings=_findings(outcome),
    )


def execute_scan(
    cli_ctx: CliContext,
    target: str,
    *,
    runner: Callable[..., Any] | None = None,
    listen: Callable[[Any], contextlib.AbstractContextManager[None]] | None = None,
    consent: EgressConsent | None = None,
    resume: str | None = None,
    use_cache: bool | None = None,
    refresh: Sequence[str] = (),
    out: Output | None = None,
) -> CliScanResult:
    """Run the pipeline through ``run_scan()`` and convert its outcome.

    ``listen`` receives the event bus of the scan and returns a context manager that is active
    while the pipeline runs (the progress display, E05-11). ``consent`` is the outcome of the
    consent gate; it reaches the core only as ``run_scan(consent=...)``.

    The pipeline handles SIGINT and SIGTERM itself (``handle_sigint=True``, E04-29). ``resume``
    continues an interrupted scan with its stored salt; a refusal of the pipeline becomes a
    usage error with a ``resume_*`` code. A cancelled scan ends through ``report_cancelled``.
    """
    from codekavach.core.pipeline.cancel import (  # noqa: PLC0415
        CancellationToken,
        ScanCancelledError,
    )
    from codekavach.core.pipeline.errors import GraphError  # noqa: PLC0415
    from codekavach.core.pipeline.events import InMemoryEventBus  # noqa: PLC0415
    from codekavach.core.pipeline.plan import PlanError  # noqa: PLC0415
    from codekavach.core.pipeline.resume import ResumeMismatchError  # noqa: PLC0415

    run_scan = runner or load_backend(
        "codekavach.core.pipeline.runner", "run_scan", feature="the scan pipeline", epic="E04"
    )
    salt = scan_salt(cli_ctx.loaded, resume)
    bus = InMemoryEventBus()
    try:
        with listen(bus) if listen is not None else contextlib.nullcontext():
            outcome = run_scan(
                cli_ctx.loaded,
                target,
                salt=salt,
                bus=bus,
                cancellation=CancellationToken(),
                consent=consent.decision() if consent is not None else None,
                handle_sigint=True,
                resume=resume,
                use_cache=use_cache,
                refresh=tuple(refresh),
            )
    except ResumeMismatchError as error:
        raise resume_refusal(error) from None
    except (PlanError, GraphError) as error:
        raise InternalError(
            f"the installed pipeline is invalid: {error}", code="pipeline_invalid"
        ) from None
    status = str(outcome.result.status.value)
    if status == "cancelled":
        if out is None:
            raise ScanCancelledError("cancelled")
        report_cancelled(out, target, outcome)
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
    result: CliScanResult,
    *,
    target: str,
    provider: ProviderChoice,
    privacy_level: str,
    threshold: ThresholdResult,
    consent_source: str = "not-required",
) -> dict[str, Any]:
    """The ``data`` object of the JSON envelope (counts and paths only)."""
    return {
        "threshold": {
            "fail_on": threshold.fail_on,
            "exceeded": threshold.exceeded,
            "counted": threshold.counted_at_or_above,
        },
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
        "consent": {"source": consent_source},
        "degraded_stages": list(result.degraded_stages),
        "report_files": [str(path) for path in result.report_files],
        "state_dir": str(result.state_dir),
    }


def threshold_lines(threshold: ThresholdResult) -> list[str]:
    """The lines of the human summary that explain the gate."""
    if threshold.threshold == "none":
        lines = ["threshold: none; the severity gate is disabled"]
    else:
        verdict = "failing (exit 1)" if threshold.exceeded else "passing"
        lines = [
            f"threshold: {threshold.fail_on}; {threshold.counted_at_or_above} finding(s) at or "
            f"above it: {verdict}"
        ]
    if threshold.not_counted:
        lines.append(
            f"{threshold.not_counted} finding(s) not counted (suppressed, accepted or false "
            "positive)"
        )
    return lines


def _renderer(
    result: CliScanResult, provider: ProviderChoice, privacy_level: str, threshold: ThresholdResult
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
        for line in threshold_lines(threshold):
            console.print(line, markup=False, soft_wrap=True)
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
    strict: Annotated[
        bool, typer.Option("--strict", help="Exit 4 when a stage failed and the scan continued.")
    ] = False,
    strict_privacy: Annotated[
        bool,
        typer.Option("--strict-privacy", help="Exit 3 when the egress guard blocked a payload."),
    ] = False,
    resume: Annotated[
        str | None,
        typer.Option(
            "--resume",
            metavar="[SCAN_ID|latest]",
            help="Continue an interrupted scan (latest when no id is given). Needs the stored "
            "scan salt of the vault (E10); until then it is refused with resume_salt_changed.",
        ),
    ] = None,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Run every stage again; use no cached result.")
    ] = False,
    refresh_stage: Annotated[
        list[str] | None,
        typer.Option("--refresh-stage", help="Stage or group to run again; repeatable."),
    ] = None,
    accept_egress: Annotated[
        bool,
        typer.Option(
            "--accept-egress",
            help="Approve sending sanitised payloads to the remote provider for this run.",
        ),
    ] = False,
    progress: Annotated[
        ProgressMode,
        typer.Option(
            "--progress",
            case_sensitive=False,
            help="Progress on stderr: auto picks bar on a terminal, plain when piped, off "
            "under --quiet or --json.",
        ),
    ] = ProgressMode.auto,
) -> None:
    """Scan a code base and print a severity summary."""
    from codekavach.config.overrides import overrides_from_flags  # noqa: PLC0415

    if resume is not None and no_cache:
        raise UsageError(
            "--resume relies on the stage cache and cannot be combined with --no-cache",
            code="resume_no_cache_conflict",
        )
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
    maybe_show_first_run_notice(ctx)
    consent = EgressConsent("not-required")
    if provider.id is not None:
        consent = ensure_egress_consent(
            ctx,
            provider_id=provider.id,
            provider=cli_ctx.settings.llm.providers[provider.id],
            level=cli_ctx.privacy_level,
            accept=accept_egress,
        )
    if consent.source != "not-required":
        out.info(f"remote egress to {provider.id} accepted via {consent.source}")
    result = execute_scan(
        cli_ctx,
        target,
        listen=lambda bus: progress_listener(ctx, bus, progress),
        consent=consent,
        resume=resume,
        use_cache=False if no_cache else None,
        refresh=tuple(refresh_stage or ()),
        out=out,
    )
    level = str(cli_ctx.privacy_level.value)
    threshold = evaluate_threshold(result.findings, cli_ctx.settings.scan.fail_on)
    _warnings(out, result)
    out.result(
        scan_data(
            result,
            target=target,
            provider=provider,
            privacy_level=level,
            threshold=threshold,
            consent_source=consent.source,
        ),
        human=_renderer(result, provider, level, threshold),
    )
    refusal = exit_error(
        final_exit_code(result, threshold, strict=strict, strict_privacy=strict_privacy),
        result,
        threshold,
    )
    if refusal is not None:
        raise refusal


def exit_error(
    code: ExitCode, result: CliScanResult, threshold: ThresholdResult
) -> CliError | None:
    """The error that gives a rendered scan its exit code, or ``None`` for 0."""
    if code is ExitCode.INTERNAL:
        stages = ", ".join(result.degraded_stages)
        return InternalError(
            f"stage(s) failed and --strict is set: {stages}", code="stage_degraded"
        )
    if code is ExitCode.PRIVACY_BLOCK:
        return PrivacyBlockError(
            f"the egress guard blocked {result.egress_blocked} payload(s) and --strict-privacy "
            "is set",
            code="egress_blocked",
        )
    if code is ExitCode.FINDINGS:
        return ThresholdExceeded(
            f"{threshold.counted_at_or_above} finding(s) at or above {threshold.fail_on}"
        )
    return None
