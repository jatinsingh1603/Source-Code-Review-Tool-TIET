"""``codekavach privacy``: inspect what is prepared for, and recorded as sent to, LLM providers.

Owning epic: E05.

``privacy inspect`` shows, per candidate, the client's original code next to the exact sanitised
payload whose hash the ledger records (Demo 1 criterion 3). It is read-only and local and never
opens the vault: showing both sides needs no mapping, and I3 forbids exporting one, so there is no
option that prints the identifier mapping. Original code is rendered only to the terminal in human
mode, never into the JSON envelope, a log or a file; ``RawCode.expose()`` is called in this module
only, immediately before building the ``Syntax`` object. Sanitised text enters JSON only with
``--include-payload``. Each payload's hash is verified before display, so what the user audits is
what the ledger recorded (I6); a mismatch is reported and the payload is not shown.
"""

import fnmatch
import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Protocol

import typer
from rich.console import Console, Group, RenderableType
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from codekavach.cli.backends import load_backend
from codekavach.cli.context import get_context, with_target
from codekavach.cli.errors import PrivacyBlockError, UsageError
from codekavach.cli.ledger import ledger_app
from codekavach.cli.output import TABLE_BOX, get_output, simple_table, to_jsonable

if TYPE_CHECKING:
    from codekavach.core.models.candidate import Candidate
    from codekavach.core.models.payload import SanitisedPayload
    from codekavach.core.models.slice import CodeSlice
    from codekavach.core.store.layout import StateLayout

COLUMNS_MIN_WIDTH = 140
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ORIGINAL_TITLE = "Original (stays on this machine)"
PAYLOAD_TITLE = "Payload (what the provider receives)"
NOT_AVAILABLE = "original not available (file changed or removed since the scan)"

privacy_app = typer.Typer(
    help="Inspect what is prepared for, and recorded as sent to, LLM providers.",
    no_args_is_help=True,
)
privacy_app.add_typer(ledger_app, name="ledger")


class PayloadSource(Protocol):
    """Read access to the payloads, slices, candidates and ledger outcomes of one scan."""

    def payloads(self, scan_id: str) -> "Sequence[SanitisedPayload]":
        """Every payload prepared in the scan."""

    def slice_for(self, candidate_id: str) -> "CodeSlice | None":
        """The slice a payload was built from."""

    def candidate(self, candidate_id: str) -> "Candidate | None":
        """The candidate of a payload."""

    def ledger_outcome(self, payload_hash: str) -> str | None:
        """``recorded``, ``sent``, ``blocked:<code>`` or ``None`` when not in the ledger."""


class Layout(StrEnum):
    """How a pair is rendered."""

    auto = "auto"
    columns = "columns"
    stacked = "stacked"


@dataclass(frozen=True)
class Entry:
    """One payload with everything needed to show it."""

    payload: "SanitisedPayload"
    candidate: "Candidate | None"
    slice: "CodeSlice | None"
    outcome: str | None
    hash_ok: bool


def _source(layout: "StateLayout", scan_id: str) -> PayloadSource:
    opener = load_backend(
        "codekavach.privacy.inspect_source",
        "open_payload_source",
        feature="payload inspection",
        epic="E11",
    )
    source: PayloadSource = opener(layout, scan_id)
    return source


def resolve_scan(layout: "StateLayout", requested: str) -> str:
    """``latest`` or an explicit id, checked against the stored scans."""
    from codekavach.core.store.artefacts import list_scan_ids  # noqa: PLC0415

    ids = list_scan_ids(layout)
    if requested == "latest" and ids:
        return ids[-1]
    if requested in ids:
        return requested
    raise UsageError("no stored scan matches --scan", code="scan_not_found",
                     hint="run codekavach scan first")  # fmt: skip


def _severity(candidate: "Candidate | None") -> int:
    if candidate is None or candidate.engine_severity is None:
        return len(SEVERITY_RANK)
    return SEVERITY_RANK.get(str(candidate.engine_severity.value), len(SEVERITY_RANK))


def _first_location(candidate: "Candidate | None") -> tuple[str, int]:
    if candidate is None:
        return ("", 0)
    location = candidate.locations[0]
    return (str(location.path), location.start_line)


def order_key(entry: Entry) -> tuple[int, str, int, str]:
    """Severity (descending), then path, line and candidate id."""
    path, line = _first_location(entry.candidate)
    return (_severity(entry.candidate), path, line, str(entry.payload.candidate_id))


def hash_matches(payload: "SanitisedPayload") -> bool:
    """True when the payload text still hashes to the recorded ``payload_hash``."""
    digest = hashlib.sha256(payload.text.expose().encode("utf-8")).hexdigest()
    return digest == payload.payload_hash


def placeholder_counts(payload: "SanitisedPayload") -> list[dict[str, Any]]:
    """Distinct placeholders per kind and subtype, in a stable order."""
    counts: dict[tuple[str, str], int] = {}
    for ref in payload.placeholders:
        key = (str(ref.kind.value), ref.subtype)
        counts[key] = counts.get(key, 0) + 1
    return [
        {"kind": kind, "subtype": subtype, "count": count}
        for (kind, subtype), count in sorted(counts.items())
    ]


def outcome_text(outcome: str | None, provider_kind: str | None) -> str:
    """The ledger outcome as shown to people."""
    if outcome is None:
        return "not recorded"
    if outcome.startswith("blocked:"):
        return f"blocked: {outcome.removeprefix('blocked:')}"
    if outcome == "recorded" and provider_kind in {None, "mock", "replay"}:
        return "recorded (mock provider: not transmitted)"
    return outcome


def _tokens(entry: Entry) -> int:
    if entry.slice is not None:
        return entry.slice.token_estimate
    return max(1, len(entry.payload.text.expose()) // 4)


def _cwe(candidate: "Candidate | None") -> str:
    if candidate is None or not candidate.cwe:
        return ""
    return f"CWE-{int(candidate.cwe[0])}"


def header(entry: Entry, provider_kind: str | None) -> list[str]:
    """The two header lines of a pair."""
    candidate = entry.candidate
    path, line = _first_location(candidate)
    rule = candidate.rule_id if candidate else "unknown"
    level = str(entry.payload.level.value)
    placeholders = (
        ", ".join(
            f"{item['kind']}:{item['subtype']} x{item['count']}"
            for item in placeholder_counts(entry.payload)
        )
        or "none"
    )
    first = f"candidate {entry.payload.candidate_id} rule {rule} {_cwe(candidate)}".rstrip()
    first += f"  {path}:{line}  level {level}" if path else f"  level {level}"
    second = (
        f"payload {entry.payload.payload_hash[:12]}  ~{_tokens(entry)} tokens  "
        f"pseudonyms {entry.payload.pseudonym_count}  placeholders {placeholders}  "
        f"ledger: {outcome_text(entry.outcome, provider_kind)}"
    )
    return [first, second]


def _trim(text: str) -> str:
    """Drop the final line break so that no empty numbered line is shown."""
    return text.removesuffix("\n").removesuffix("\r")


def _original(entry: Entry) -> RenderableType:
    code_slice = entry.slice
    if code_slice is None:
        return Text(NOT_AVAILABLE)
    blocks: list[RenderableType] = []
    for segment in code_slice.segments:
        blocks.append(Text(str(segment.path), style="dim"))
        blocks.append(
            Syntax(
                _trim(segment.text.expose()),  # the only place the CLI exposes client code
                code_slice.language.value,
                line_numbers=True,
                start_line=segment.region.start_line,
                word_wrap=True,
            )
        )
    return Group(*blocks)


def _payload(entry: Entry) -> RenderableType:
    level = str(entry.payload.level.value)
    text = _trim(entry.payload.text.expose())
    if level == "L4":
        return Group(Text("L4: abstract facts, no code", style="bold"), Text(text))
    lexer = entry.slice.language.value if entry.slice is not None else "text"
    return Syntax(text, lexer, line_numbers=True, start_line=1, word_wrap=True)


def render_pair(console: Console, entry: Entry, layout: Layout, provider_kind: str | None) -> None:
    """Print one pair in the requested layout."""
    for line in header(entry, provider_kind):
        console.print(line, markup=False, highlight=False, soft_wrap=True)
    if str(entry.payload.level.value) == "L0":
        console.print("no payload: level L0", markup=False)
        return
    chosen = layout
    if layout is Layout.auto:
        chosen = Layout.columns if console.width >= COLUMNS_MIN_WIDTH else Layout.stacked
    if chosen is Layout.columns:
        table = Table(box=TABLE_BOX, show_header=True, expand=True)
        table.add_column(ORIGINAL_TITLE, ratio=1)
        table.add_column(PAYLOAD_TITLE, ratio=1)
        table.add_row(_original(entry), _payload(entry))
        console.print(table)
    else:
        console.print(ORIGINAL_TITLE, style="bold", markup=False)
        console.print(_original(entry))
        console.print(PAYLOAD_TITLE, style="bold", markup=False)
        console.print(_payload(entry))
    console.print()


def payload_row(entry: Entry, provider_kind: str | None) -> list[str]:
    """One row of the ``--list`` table."""
    path, line = _first_location(entry.candidate)
    placeholders = ", ".join(
        f"{item['kind']}:{item['subtype']} x{item['count']}"
        for item in placeholder_counts(entry.payload)
    )
    return [
        str(entry.payload.candidate_id),
        entry.candidate.rule_id if entry.candidate else "",
        _cwe(entry.candidate),
        f"{path}:{line}" if path else "",
        str(entry.payload.level.value),
        entry.payload.payload_hash[:12],
        str(_tokens(entry)),
        str(entry.payload.pseudonym_count),
        placeholders,
        outcome_text(entry.outcome, provider_kind),
    ]


LIST_COLUMNS = ["Candidate", "Rule", "CWE", "Location", "Level", "Payload", "Tokens",
                "Pseudonyms", "Placeholders", "Ledger"]  # fmt: skip


def payload_json(entry: Entry, *, include_payload: bool) -> dict[str, Any]:
    """Metadata of one payload; the sanitised text only on request, never original code."""
    segments = []
    if entry.slice is not None:
        segments = [
            {
                "path": str(segment.path),
                "start_line": segment.region.start_line,
                "end_line": segment.region.end_line,
            }
            for segment in entry.slice.segments
        ]
    data: dict[str, Any] = {
        "candidate_id": str(entry.payload.candidate_id),
        "rule_id": entry.candidate.rule_id if entry.candidate else None,
        "cwe": _cwe(entry.candidate) or None,
        "level": str(entry.payload.level.value),
        "payload_hash": entry.payload.payload_hash,
        "pseudonym_count": entry.payload.pseudonym_count,
        "placeholders": placeholder_counts(entry.payload),
        "segments": segments,
        "ledger_outcome": entry.outcome,
    }
    if include_payload:
        data["payload_text"] = to_jsonable(entry.payload.text, allow_sanitised=True)
    return data


def _matches(entry: Entry, candidates: Sequence[str], file_glob: str | None) -> bool:
    if candidates and str(entry.payload.candidate_id) not in candidates:
        return False
    if file_glob is None:
        return True
    paths = (
        [str(location.path) for location in entry.candidate.locations] if entry.candidate else []
    )
    return any(fnmatch.fnmatch(path, file_glob) for path in paths)


def collect(
    source: PayloadSource, scan_id: str, candidates: Sequence[str], file_glob: str | None
) -> list[Entry]:
    """The filtered, ordered entries of a scan."""
    entries = []
    for payload in source.payloads(scan_id):
        candidate_id = str(payload.candidate_id)
        entry = Entry(
            payload=payload,
            candidate=source.candidate(candidate_id),
            slice=source.slice_for(candidate_id),
            outcome=source.ledger_outcome(payload.payload_hash),
            hash_ok=hash_matches(payload),
        )
        if _matches(entry, candidates, file_glob):
            entries.append(entry)
    return sorted(entries, key=order_key)


def _renderer(
    shown: list[Entry],
    *,
    hidden: int,
    list_only: bool,
    layout: Layout,
    provider_kind: str | None,
    never_send: Sequence[str],
) -> Callable[[Console], None]:
    def render(console: Console) -> None:
        if list_only:
            table = simple_table(LIST_COLUMNS, [payload_row(e, provider_kind) for e in shown])
            table.columns[0].no_wrap = True
            console.print(table)
        else:
            for entry in shown:
                render_pair(console, entry, layout, provider_kind)
        for candidate_id in never_send:
            console.print(f"candidate {candidate_id}: no payload: policy never-send", markup=False)
        if hidden:
            console.print(f"{hidden} more payload(s); use --limit 0 to show all", markup=False)

    return render


@privacy_app.command("inspect")
def inspect_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Project directory.")] = ".",
    scan: Annotated[str, typer.Option("--scan", help="Scan id, or latest.")] = "latest",
    candidate: Annotated[
        list[str] | None, typer.Option("--candidate", help="Candidate id; repeatable.")
    ] = None,
    file_glob: Annotated[
        str | None, typer.Option("--file", help="Only candidates with a location matching.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help="Pairs to show; 0 shows all.")] = 5,
    layout: Annotated[
        Layout, typer.Option("--layout", case_sensitive=False, help="auto, columns or stacked.")
    ] = Layout.auto,
    list_only: Annotated[
        bool, typer.Option("--list", help="Only the table of payloads, no code.")
    ] = False,
    include_payload: Annotated[
        bool, typer.Option("--include-payload", help="JSON mode: add the sanitised text.")
    ] = False,
) -> None:
    """Show original code next to the exact payload prepared for the LLM."""
    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

    if limit < 0:
        raise UsageError("--limit must not be negative", code="bad_limit")
    path = Path(target)
    if not path.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    cli_ctx = with_target(ctx, path)
    out = get_output(ctx)
    loaded = get_context(ctx).loaded
    state = StateLayout(resolve_state_dir(loaded.project_root, loaded.settings.project.state_dir))
    scan_id = resolve_scan(state, scan)
    source = _source(state, scan_id)
    entries = collect(source, scan_id, candidate or [], file_glob)
    mismatched = [entry for entry in entries if not entry.hash_ok]
    valid = [entry for entry in entries if entry.hash_ok]
    shown = valid if limit == 0 else valid[:limit]
    never_send = [
        str(item) for item in getattr(source, "never_send_candidates", lambda _: [])(scan_id)
    ]
    llm = cli_ctx.settings.llm
    provider_id = "mock" if llm.default_provider == "auto" else llm.default_provider
    provider = llm.providers.get(provider_id)
    provider_kind = provider.kind.value if provider is not None else None
    data = {
        "scan_id": scan_id,
        "payloads": [payload_json(entry, include_payload=include_payload) for entry in shown],
    }
    out.result(
        data,
        human=_renderer(
            shown,
            hidden=len(valid) - len(shown),
            list_only=list_only,
            layout=layout,
            provider_kind=provider_kind,
            never_send=never_send,
        ),
    )
    if mismatched:
        ids = ", ".join(str(entry.payload.candidate_id) for entry in mismatched)
        raise PrivacyBlockError(
            f"payload text no longer matches the recorded hash for candidate(s) {ids}",
            code="payload_hash_mismatch",
        )
