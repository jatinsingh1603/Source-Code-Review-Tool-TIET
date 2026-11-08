"""The sequence behind ``codekavach demo``: Demo 1 on the mock provider, offline (E13-03).

Owning epic: E13.

``run_demo`` scans a copy of the sample project with ``--no-send`` semantics on the mock provider,
writes the two-column inspection page, verifies the ledger chain and payloads, searches every
ledger payload for the project's listed terms (the zero-leak check), and renders the report as
HTML and PDF. Everything lands below ``out``. It refuses any provider other than ``mock`` or
``replay``, so the demo opens no connection to a model, and it says so in its summary: a mock run
shows what *would* have left the machine, not what did.

The scan runs on a copy, in a state directory of its own that is removed at the end unless
``keep_state`` is set, so a demo never touches the original fixture or the user's ledger. The vault
passphrase is a random one that lives in this process only for the duration of the run.
"""

import os
import secrets
import shutil
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from codekavach.cli.errors import InternalError, PrivacyBlockError, UsageError
from codekavach.cli.inspect_page import render_page, write_page
from codekavach.cli.ledger import VERIFY_STEPS, StepResult, VerifyContext, run_verify
from codekavach.cli.privacy import collect
from codekavach.config import LoadedConfig, load_settings
from codekavach.core.models.finding import Finding
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.egress.ledger import open_reader
from codekavach.privacy.inspect_source import open_payload_source
from codekavach.report.model.build import build_report_document, summarise_ledger
from codekavach.report.model.document import ReportDocument, ZeroLeak
from codekavach.report.render.base import RendererRegistry, renderer_registry
from codekavach.report.render.pdf import PdfUnavailableError

LOCAL_PROVIDERS: Final = frozenset({"mock", "replay"})
PASSPHRASE_VARIABLE: Final = "CODEKAVACH_DEMO_PASSPHRASE"  # noqa: S105 - a variable name
TERMS_FILE: Final = Path("ground-truth") / "terms.txt"
WORK_DIR: Final = ".work"
PROJECT_DIR: Final = "kavachbank"
# A fixed salt gives the same pseudonyms, and so the same payload hashes, on every run: the replay
# cassettes are keyed by payload hash. The data is synthetic, so a published salt costs nothing.
DEMO_SALT_HEX: Final = "6c" * 32  # pragma: allowlist secret
REPLAY_ID: Final = "rec"
CASSETTES: Final = "cassettes"
SUMMARY_NOTE: Final = (
    "This demo used the {kind} provider: it answers on this machine and opens no connection. "
    "The ledger shows what would have been sent to a model, not what was."
)


@dataclass(frozen=True)
class DemoReport:
    """What the demo did and where it put the results."""

    scan_id: str
    provider: str
    findings: int
    reviewed: int
    payloads: int
    chain_ok: bool
    payloads_ok: bool
    zero_leak_checked: int
    zero_leak_occurrences: int
    zero_leak_passed: bool
    files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    state_dir: Path | None = None
    note: str = ""


def resolve_fixture(fixture: str) -> Path:
    """The directory of ``fixture``: a path as given, or ``fixtures/<name>`` of a checkout.

    Raises:
        UsageError: ``fixture_not_found`` when no such directory exists.
    """
    candidate = Path(fixture).expanduser()
    if candidate.is_dir():
        return candidate.resolve()
    roots = [Path.cwd(), *Path.cwd().parents, Path(__file__).resolve().parents[3]]
    for root in roots:
        found = root / "fixtures" / fixture
        if found.is_dir():
            return found.resolve()
    raise UsageError(
        f"the demo fixture {fixture!r} was not found; run from a checkout or pass a path",
        code="fixture_not_found",
    )


@contextmanager
def _passphrase() -> Iterator[dict[str, str]]:
    """A random vault passphrase in the environment for the run, and the settings that name it."""
    previous = os.environ.get(PASSPHRASE_VARIABLE)
    os.environ[PASSPHRASE_VARIABLE] = secrets.token_hex(24)
    try:
        yield {
            "CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE": "passphrase",
            "CODEKAVACH_PRIVACY__VAULT__PASSPHRASE": f"env:{PASSPHRASE_VARIABLE}",
        }
    finally:
        if previous is None:
            os.environ.pop(PASSPHRASE_VARIABLE, None)
        else:
            os.environ[PASSPHRASE_VARIABLE] = previous


def _prepare(fixture: Path, work: Path) -> Path:
    """A clean copy of the project (without its answer key) to scan."""
    if work.exists():
        shutil.rmtree(work)
    root = work / PROJECT_DIR
    shutil.copytree(fixture, root, ignore=shutil.ignore_patterns("ground-truth", ".git"))
    (root / ".git").mkdir()
    (work / "home").mkdir()
    return root


def _file(name: str, path: Path) -> str:
    return f"{name}: {path} ({path.stat().st_size} bytes)"


def _step(results: list[StepResult], name: str) -> StepResult | None:
    return next((result for result in results if result.name == name), None)


def run_demo(
    fixture: str,
    out: Path,
    *,
    keep_state: bool = False,
    provider: str = "mock",
    send: bool = False,
    cassette_dir: Path | None = None,
) -> DemoReport:
    """Run the Demo 1 sequence on ``fixture`` and write the results below ``out``.

    ``provider`` is ``mock`` or ``replay`` (answers from ``cassette_dir``, by default
    ``fixtures/kavachbank/cassettes``). The CLI runs ``--no-send``; ``send=True`` lets the offline
    provider answer, which a replay rehearsal needs. Both providers answer on this machine.

    Raises:
        UsageError: the fixture is missing, or the configured provider is not a local one.
        PrivacyBlockError: a listed term occurs in a ledger payload, or the ledger fails
            verification. The files are written first so the failure can be inspected.
        InternalError: the scan itself failed.
    """
    source = resolve_fixture(fixture)
    out = out.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    work = out / WORK_DIR
    root = _prepare(source, work)
    terms = source / TERMS_FILE
    try:
        with _passphrase() as secret_env:
            return _run(
                root, work, out, terms, secret_env, keep_state=keep_state,
                provider=provider, send=send, cassette_dir=cassette_dir or source / CASSETTES,
            )  # fmt: skip
    finally:
        if not keep_state and work.exists():
            shutil.rmtree(work, ignore_errors=True)


def _provider_kind(loaded: LoadedConfig) -> str:
    llm = loaded.settings.llm
    provider_id = "mock" if llm.default_provider == "auto" else llm.default_provider
    provider = llm.providers.get(provider_id)
    return str(provider.kind.value) if provider is not None else provider_id


def _overrides(provider: str, cassette_dir: Path | None) -> dict[str, object] | None:
    if provider != "replay":
        return None
    entry: dict[str, object] = {"kind": "replay"}
    if cassette_dir is not None:
        entry["cassette_dir"] = str(cassette_dir)
    return {"llm": {"default_provider": REPLAY_ID, "providers": {REPLAY_ID: entry}}}


def _scan(
    root: Path,
    work: Path,
    secret_env: dict[str, str],
    *,
    provider: str,
    send: bool,
    cassette_dir: Path | None,
) -> tuple[LoadedConfig, ScanOutcome, str]:
    env = {"CODEKAVACH_HOME": str(work / "home"), **secret_env}
    loaded = load_settings(target=root, env=env, cli_overrides=_overrides(provider, cassette_dir))
    kind = _provider_kind(loaded)
    if kind not in LOCAL_PROVIDERS:
        raise UsageError(
            f"the demo runs offline and refuses the {kind!r} provider; use mock or replay",
            code="demo_remote_provider",
        )
    outcome = run_scan(
        loaded, str(root), salt=ScanSalt.from_hex(DEMO_SALT_HEX), persist=False, no_send=not send
    )
    if outcome.result.status.value == "failed":
        failed = ", ".join(outcome.result.failed_stages()) or "unknown"
        raise InternalError(f"the demo scan failed in stage {failed}", code="scan_failed")
    return loaded, outcome, kind


def _run(
    root: Path,
    work: Path,
    out: Path,
    terms: Path,
    secret_env: dict[str, str],
    *,
    keep_state: bool,
    provider: str,
    send: bool,
    cassette_dir: Path | None,
) -> DemoReport:
    loaded, outcome, kind = _scan(
        root, work, secret_env, provider=provider, send=send, cassette_dir=cassette_dir
    )
    settings = loaded.settings
    layout = StateLayout(outcome.state_dir)
    scan_id = str(outcome.scan.id)
    files: list[str] = []
    skipped: list[str] = []

    entries = [
        entry
        for entry in collect(
            open_payload_source(layout, scan_id, settings=settings), scan_id, [], None
        )
        if entry.hash_ok
    ]
    page = write_page(
        out / "inspect.html", render_page(entries, scan_id=scan_id, provider_kind=kind)
    )
    files.append(_file("inspect page", page))

    context = VerifyContext(
        reader=open_reader(layout, settings=settings),
        options={
            "terms_files": [terms] if terms.is_file() else [],
            "ignore_case": True,
            # A --no-send run sends nothing, so without this every hit would be excused as
            # "blocked, not sent". The demo counts every payload that was prepared.
            "include_blocked": True,
        },
    )
    results = run_verify(context, VERIFY_STEPS)
    chain, payloads, listed = (_step(results, name) for name in ("chain", "payloads", "terms"))
    hits = listed.data.get("hits", []) if listed is not None else []
    checked = int(listed.data.get("checked", 0)) if listed is not None else 0
    zero_leak = ZeroLeak(checked=listed is not None, terms_checked=checked, occurrences=len(hits))
    verification = out / "verification.txt"
    verification.write_text(
        "\n".join(
            f"[{'ok' if r.ok else 'FAILED'}] {r.name}: {r.summary or r.message}" for r in results
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    files.append(_file("ledger verification", verification))

    store = OnDiskArtefactStore.open_existing(layout, scan_id)
    findings = store.get_list(keys.FINDINGS, Finding) if store.has(keys.FINDINGS) else []
    document = build_report_document(
        outcome.scan,
        findings,
        settings,
        summarise_ledger(outcome.state_dir, scan_id, settings, zero_leak=zero_leak),
    )
    formats = renderer_registry(settings)
    for name in ("html", "pdf"):
        render = _renderer(formats, name)
        if render is None:
            skipped.append(f"{name}: renderer not installed")
            continue
        try:
            written = render(document, out / f"report.{name}")
        except PdfUnavailableError as error:
            skipped.append(f"{name}: {error}")
            continue
        files.append(_file(f"{name} report", written))

    report = DemoReport(
        scan_id=scan_id,
        provider=kind,
        findings=len(findings),
        reviewed=sum(1 for finding in findings if finding.provenance.llm_reviews),
        payloads=len(entries),
        chain_ok=bool(chain and chain.ok),
        payloads_ok=bool(payloads and payloads.ok),
        zero_leak_checked=zero_leak.terms_checked,
        zero_leak_occurrences=zero_leak.occurrences,
        zero_leak_passed=zero_leak.passed,
        files=files,
        skipped=skipped,
        state_dir=outcome.state_dir if keep_state else None,
        note=SUMMARY_NOTE.format(kind=kind),
    )
    if not (report.chain_ok and report.payloads_ok and report.zero_leak_passed):
        raise PrivacyBlockError(
            "the demo's ledger failed verification or the zero-leak check "
            f"(chain {report.chain_ok}, payloads {report.payloads_ok}, "
            f"occurrences {report.zero_leak_occurrences}); see {verification}",
            code="demo_verification_failed",
        )
    return report


def _renderer(
    formats: RendererRegistry, name: str
) -> Callable[[ReportDocument, Path], Path] | None:
    if name not in formats.names():
        return None
    return formats.get(name).render


__all__ = ["DemoReport", "resolve_fixture", "run_demo"]
