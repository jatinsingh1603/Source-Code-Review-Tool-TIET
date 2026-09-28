"""``codekavach privacy ledger show|verify``: audit the egress ledger.

Owning epic: E05.

The ledger is the client's proof of what left (or would have left) the machine. ``show`` prints
metadata only, never payload text. ``verify`` walks the whole hash chain in ``seq`` order, using
the model's own hashing (``EgressRecord.compute_entry_hash``) so the CLI cannot diverge from it,
and checks that every stored payload still hashes to its recorded ``payload_hash``. Records are
streamed: only the previous record, the payload hashes and a map from ``seq`` to payload hash
are kept. A failure means an entry was altered, removed or inserted after it was written, or the
file is corrupt; the tool cannot tell which, and says so without speaking of an attack. Neither
command opens the vault or de-pseudonymises anything (I3); failures exit 3.

``verify`` is a list of ``VerifyStep`` callables (``chain``, ``payloads``) so that later issues can
append a step (E05-18: ``--check-terms``) without rewriting the command.
"""

import hashlib
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Protocol

import typer
from rich.console import Console

from codekavach.cli.backends import load_backend
from codekavach.cli.context import get_context, with_target
from codekavach.cli.errors import PrivacyBlockError, UsageError
from codekavach.cli.output import Output, get_output, to_jsonable

if TYPE_CHECKING:
    from codekavach.core.models.egress import EgressRecord
    from codekavach.core.models.text import SanitisedText
    from codekavach.core.store.layout import StateLayout

LOCAL_KINDS = frozenset({"mock", "replay"})
MOCK_SENTENCE = "these payloads were recorded but not transmitted (mock or replay provider)"

ledger_app = typer.Typer(help="Audit the egress ledger.", no_args_is_help=True)


class LedgerReader(Protocol):
    """Read access to the ledger of one project state directory."""

    def records(self, scan_id: str | None) -> "Iterator[EgressRecord]":
        """Records in ``seq`` order, of one scan or (``None``) of all scans."""

    def payload_text(self, payload_hash: str) -> "SanitisedText | None":
        """The stored payload for ``payload_hash``, or ``None`` when it is not stored."""


class Outcome(StrEnum):
    """Filter values of ``--outcome``."""

    sent = "sent"
    blocked = "blocked"
    completed = "completed"
    failed = "failed"


@dataclass
class VerifyContext:
    """What every verification step may read, and what earlier steps leave for later ones."""

    reader: LedgerReader
    require_payloads: bool = False
    options: dict[str, Any] = field(default_factory=dict)
    payload_hashes: set[str] = field(default_factory=set)
    records: int = 0


@dataclass
class StepResult:
    """The outcome of one verification step."""

    name: str
    ok: bool
    error_code: str | None = None
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[tuple[str, str]] = field(default_factory=list)
    summary: str = ""


VerifyStep = Callable[[VerifyContext], StepResult]


def _open_reader(layout: "StateLayout") -> LedgerReader:
    opener = load_backend(
        "codekavach.privacy.egress.ledger", "open_reader", feature="egress ledger", epic="E12"
    )
    reader: LedgerReader = opener(layout)
    return reader


def _layout(ctx: typer.Context, target: str) -> "StateLayout":
    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

    path = Path(target)
    if not path.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    with_target(ctx, path)
    loaded = get_context(ctx).loaded
    return StateLayout(resolve_state_dir(loaded.project_root, loaded.settings.project.state_dir))


def _chain_failure(  # noqa: PLR0911 - one return per reason code
    record: "EgressRecord", prev: "EgressRecord | None", seen: dict[int, str]
) -> tuple[int, str] | None:
    from codekavach.core.models.egress import GENESIS_PREV_HASH  # noqa: PLC0415

    expected = 1 if prev is None else prev.seq + 1
    if record.seq != expected:
        return expected, "seq_gap"
    if prev is None and record.prev_hash != GENESIS_PREV_HASH:
        return record.seq, "genesis_mismatch"
    if prev is not None and record.prev_hash != prev.entry_hash:
        return record.seq, "prev_hash_mismatch"
    if record.compute_entry_hash() != record.entry_hash:
        return record.seq, "entry_hash_mismatch"
    if record.ref_seq is not None and (
        record.ref_seq >= record.seq or seen.get(record.ref_seq) != record.payload_hash
    ):
        return record.seq, "ref_seq_invalid"
    try:
        record.verify_link(prev)
    except Exception:  # noqa: BLE001 - any other link rule the model enforces
        return record.seq, "prev_hash_mismatch"
    return None


def chain_step(context: VerifyContext) -> StepResult:
    """Walk the whole chain in ``seq`` order; stop at the first failure."""
    prev: EgressRecord | None = None
    seen: dict[int, str] = {}
    for record in context.reader.records(None):
        context.records += 1
        failure = _chain_failure(record, prev, seen)
        if failure is not None:
            seq, reason = failure
            return StepResult(
                name="chain",
                ok=False,
                error_code="ledger_chain_broken",
                message=f"ledger integrity check failed at seq {seq} ({reason})",
                data={"ok": False, "first_bad_seq": seq, "reason": reason},
            )
        seen[record.seq] = record.payload_hash
        if record.outcome.value in {"sent", "blocked"}:
            context.payload_hashes.add(record.payload_hash)
        prev = record
    return StepResult(
        name="chain",
        ok=True,
        data={"ok": True, "first_bad_seq": None, "reason": None},
        summary=f"chain intact: {context.records} records",
    )


def payloads_step(context: VerifyContext) -> StepResult:
    """Every stored payload of a sent or blocked record must still match its hash."""
    mismatched: list[str] = []
    missing: list[str] = []
    unreadable: list[str] = []
    for payload_hash in sorted(context.payload_hashes):
        try:
            text = context.reader.payload_text(payload_hash)
        except Exception:  # noqa: BLE001 - for example an encrypted store without its key
            unreadable.append(payload_hash)
            continue
        if text is None:
            missing.append(payload_hash)
            continue
        if hashlib.sha256(text.expose().encode("utf-8")).hexdigest() != payload_hash:
            mismatched.append(payload_hash)
    checked = len(context.payload_hashes) - len(missing) - len(unreadable)
    data = {"mismatched": mismatched, "missing": missing, "unreadable": unreadable}
    warnings = [("payload_missing", f"payload {h[:12]} is not stored") for h in missing]
    warnings += [("payload_unreadable", f"payload {h[:12]} cannot be read") for h in unreadable]
    summary = f"payloads: {checked} checked, {len(mismatched)} mismatches"
    if mismatched:
        return StepResult(
            "payloads",
            ok=False,
            error_code="ledger_payload_mismatch",
            message=f"{len(mismatched)} stored payload(s) no longer match their recorded hash",
            data=data | {"checked": checked},
            warnings=warnings,
            summary=summary,
        )
    if context.require_payloads and (missing or unreadable):
        return StepResult(
            "payloads",
            ok=False,
            error_code="ledger_payload_missing",
            message=f"{len(missing) + len(unreadable)} payload(s) are missing or unreadable",
            data=data | {"checked": checked},
            summary=summary,
        )
    return StepResult(
        "payloads", ok=True, data=data | {"checked": checked}, warnings=warnings, summary=summary
    )


VERIFY_STEPS: list[VerifyStep] = [chain_step, payloads_step]


def run_verify(context: VerifyContext, steps: Iterable[VerifyStep]) -> list[StepResult]:
    """Run the steps in order; after a chain failure the later steps are not run."""
    results: list[StepResult] = []
    for step in steps:
        result = step(context)
        results.append(result)
        if not result.ok and result.name == "chain":
            break
    return results


def verify_data(context: VerifyContext, results: list[StepResult]) -> dict[str, Any]:
    """The JSON ``data`` of ``verify``."""
    by_name = {result.name: result for result in results}
    payloads = by_name.get("payloads")
    data: dict[str, Any] = {
        "records": context.records,
        "payloads_checked": payloads.data.get("checked", 0) if payloads else 0,
        "chain": by_name["chain"].data if "chain" in by_name else None,
        "payloads": {
            "mismatched": payloads.data.get("mismatched", []) if payloads else [],
            "missing": payloads.data.get("missing", []) if payloads else [],
        },
    }
    for result in results:
        if result.name not in {"chain", "payloads"}:
            data[result.name] = result.data
    return data


def _finish_verify(out: Output, context: VerifyContext, results: list[StepResult]) -> None:
    for result in results:
        for code, message in result.warnings:
            out.warn(code, message)

    def render(console: Console) -> None:
        if context.records == 0:
            console.print("ledger intact: 0 records", markup=False)
            return
        for result in results:
            if result.summary:
                console.print(result.summary, markup=False)

    out.result(verify_data(context, results), human=render)
    for result in results:
        if not result.ok:
            raise PrivacyBlockError(result.message, code=result.error_code or "ledger_invalid")


@ledger_app.command("verify")
def verify_command(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Project directory.")] = ".",
    require_payloads: Annotated[
        bool,
        typer.Option("--require-payloads", help="Fail when a payload is missing or unreadable."),
    ] = False,
) -> None:
    """Recompute the hash chain and check stored payloads against their hashes."""
    reader = _open_reader(_layout(ctx, target))
    context = VerifyContext(reader=reader, require_payloads=require_payloads)
    _finish_verify(get_output(ctx), context, run_verify(context, VERIFY_STEPS))


def _since(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise UsageError("--since expects an ISO 8601 timestamp", code="bad_since") from None
    if moment.tzinfo is None:
        from datetime import UTC  # noqa: PLC0415

        moment = moment.replace(tzinfo=UTC)
    return moment


def _outcome_label(record: "EgressRecord", answered: set[int]) -> str:
    outcome = record.outcome.value
    if outcome == "sent" and record.seq not in answered:
        return "sent (no response recorded)"
    return outcome


def record_line(record: "EgressRecord", answered: set[int]) -> str:
    """One human line of ``show``: every column of the ledger, in a fixed order."""
    tokens = record.token_counts
    completion = "-" if tokens.completion is None else str(tokens.completion)
    parts = [
        f"{record.seq:>6}",
        record.timestamp.isoformat().replace("+00:00", "Z"),
        f"{_outcome_label(record, answered):<27}",
        f"{record.provider}/{record.model}",
        str(record.level.value),
        record.task or "-",
        str(record.candidate_id or "-"),
        f"payload {record.payload_hash[:12]}",
        f"tokens {tokens.prompt}/{completion}",
    ]
    if record.block_code:
        parts.append(f"block {record.block_code}")
    return "  ".join(parts)


SHOW_HEADER = (
    "   seq  timestamp             outcome                      provider/model  level  task  "
    "candidate  payload  tokens (prompt/completion)"
)


def _provider_kinds(ctx: typer.Context, providers: Iterable[str]) -> set[str]:
    llm = get_context(ctx).settings.llm
    kinds = set()
    for provider_id in providers:
        provider = llm.providers.get(provider_id)
        kinds.add(provider.kind.value if provider is not None else provider_id)
    return kinds


@ledger_app.command("show")
def show_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Project directory.")] = ".",
    scan: Annotated[str, typer.Option("--scan", help="Scan id, latest or all.")] = "latest",
    outcome: Annotated[
        list[Outcome] | None, typer.Option("--outcome", help="Outcome to list; repeatable.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help="Records to show; 0 shows all.")] = 50,
    since: Annotated[
        str | None, typer.Option("--since", help="Only records at or after this ISO 8601 time.")
    ] = None,
) -> None:
    """List ledger entries as metadata (never payload text)."""
    from codekavach.core.store.artefacts import list_scan_ids  # noqa: PLC0415

    if limit < 0:
        raise UsageError("--limit must not be negative", code="bad_limit")
    layout = _layout(ctx, target)
    scan_filter: str | None = None
    if scan == "latest":
        ids = list_scan_ids(layout)
        scan_filter = ids[-1] if ids else None
        if scan_filter is None:
            scan = "all"
    elif scan != "all":
        scan_filter = scan
    reader = _open_reader(layout)
    moment = _since(since)
    wanted = {item.value for item in outcome or []}
    records = list(reader.records(scan_filter if scan != "all" else None))
    answered = {record.ref_seq for record in records if record.ref_seq is not None}
    selected = [
        record
        for record in records
        if (not wanted or record.outcome.value in wanted)
        and (moment is None or record.timestamp >= moment)
    ]
    shown = selected if limit == 0 else selected[:limit]
    out = get_output(ctx)
    data = {
        "records": [to_jsonable(record) for record in shown],
        "total": len(selected),
        "shown": len(shown),
    }
    kinds = _provider_kinds(ctx, {record.provider for record in shown})

    def render(console: Console) -> None:
        if not shown:
            console.print("ledger is empty", markup=False)
            return
        console.print(SHOW_HEADER, markup=False, soft_wrap=True)
        for record in shown:
            console.print(record_line(record, answered), markup=False, soft_wrap=True)
        outcomes = Counter(record.outcome.value for record in shown)
        providers = Counter(record.provider for record in shown)
        console.print(
            "outcomes: " + ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())),
            markup=False,
        )
        console.print(
            "providers: " + ", ".join(f"{k} {v}" for k, v in sorted(providers.items())),
            markup=False,
        )
        if kinds and kinds <= LOCAL_KINDS:
            console.print(MOCK_SENTENCE, markup=False)
        if len(selected) > len(shown):
            console.print(
                f"{len(selected) - len(shown)} more record(s); use --limit 0", markup=False
            )

    out.result(data, human=render)
