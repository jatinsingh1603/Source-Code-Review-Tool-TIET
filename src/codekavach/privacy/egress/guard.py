"""Egress guard: pre-flight leak checks on every request before it may be sent.

Owning epic: E12 (issue E12-01). Normative layout: docs/ARCHITECTURE.md section 3.

Invariant I4: any failed check blocks the request (fail closed).

The guard scans the final serialised request body (system prompt, task template and payload
together), because only that is what actually leaves the machine. It takes ``bytes`` and an
``EgressMeta`` and imports nothing from ``codekavach.llm`` (ruling O-12), so the LLM layer cannot
reach into the guard to build its own ticket. The outcome is an ``EgressDecision``: a ticket bound
to this exact payload, or a block code from a closed vocabulary.

**Why consent is not a setting.** A scanned repository ships its own configuration file. If
consent to send data to a cloud provider were a settings key, a malicious repository could grant
it for itself. Consent therefore arrives as a ``ConsentDecision`` produced by an explicit operator
action outside the repository, every caller must pass one, and its absence blocks a remote
provider. The guard never reads a consent flag from the settings.

**What the guard is not.** It is a verbatim check plus budgets, run by independent scanners. It
cannot judge whether disclosed structure is sensitive; what remains disclosed is listed in
docs/research/INSIGHTS.md section 4.4 and measured by the leakage harness, not claimed here.
"""

import contextlib
import json
import re
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from codekavach.config import Settings
from codekavach.config.models.llm import ProviderSettings
from codekavach.core.log import get_logger
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import PrivacyLevel
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.privacy.egress.models import (
    BLOCK_CODES,
    EgressBlocked,
    EgressDecision,
    EgressMeta,
    EgressTicket,
    LeakHit,
    priority,
)

__all__ = [
    "BoundScanner",
    "EgressBlocked",
    "EgressGuard",
    "LeakHit",
    "LeakScanner",
    "ScannerRegistry",
    "VaultOriginals",
    "host_allowed",
    "payload_in_body",
]

_log = get_logger("codekavach.privacy.egress")
_SCANNER_ID = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
_MAX_LIVE_TICKETS = 1024


@runtime_checkable
class VaultOriginals(Protocol):
    """What a scanner may ask the vault for: the original identifiers, never their pseudonyms."""

    def iter_originals(self, *, min_len: int = 4) -> Iterator[str]:
        """Yield every stored original of at least ``min_len`` characters."""
        ...


@runtime_checkable
class LeakScanner(Protocol):
    """One independent check over the final request body.

    ``scan`` returns hits as counts and offsets. It never returns, logs or raises the matched
    text. A scanner that raises, exceeds its time limit or returns something malformed is treated
    as a ``scanner_error`` block by the guard.
    """

    id: str

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        """Return the hits found in ``body``; an empty sequence means clean."""
        ...


@runtime_checkable
class BoundScanner(Protocol):
    """An optional extension: scanners that need the vault or the settings are bound before use."""

    def bind(self, vault: VaultOriginals | None, settings: Settings) -> None:
        """Receive the vault view and the settings of the evaluation about to run."""
        ...


class ScannerRegistry:
    """The scanners the guard runs; ids are unique and iteration is ordered by id.

    There is deliberately no way to disable a scanner from configuration: the registry is filled
    by code (E12-02 registers the six scanners) and no settings key names a scanner.
    """

    def __init__(self, scanners: Iterable[LeakScanner] = ()) -> None:
        self._scanners: dict[str, LeakScanner] = {}
        for scanner in scanners:
            self.register(scanner)

    def register(self, scanner: LeakScanner) -> None:
        """Add ``scanner``; raise ``ValueError`` for a malformed or duplicate id."""
        scanner_id = getattr(scanner, "id", None)
        if not isinstance(scanner_id, str) or not _SCANNER_ID.match(scanner_id):
            raise ValueError("a scanner id is lower-case letters, digits and underscores")
        if scanner_id in self._scanners:
            raise ValueError(f"scanner id {scanner_id} is already registered")
        self._scanners[scanner_id] = scanner

    def unregister(self, scanner_id: str) -> None:
        """Remove a scanner; used by tests and by code that replaces a scanner."""
        self._scanners.pop(scanner_id, None)

    @property
    def ids(self) -> tuple[str, ...]:
        """The registered ids in the order the guard runs them."""
        return tuple(sorted(self._scanners))

    def __len__(self) -> int:
        return len(self._scanners)

    def __iter__(self) -> Iterator[LeakScanner]:
        return iter([self._scanners[scanner_id] for scanner_id in sorted(self._scanners)])


@dataclass(frozen=True, slots=True)
class _Outcome:
    hits: tuple[LeakHit, ...]
    error: bool


def _valid_hits(raw: object, scanner_id: str) -> tuple[LeakHit, ...] | None:
    """The hits when ``raw`` is a well-formed result of scanner ``scanner_id``, else ``None``."""
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        return None
    hits: list[LeakHit] = []
    for item in raw:
        if not isinstance(item, LeakHit):
            return None
        if item.scanner_id != scanner_id or item.block_code not in BLOCK_CODES:
            return None
        if item.count < 1 or item.first_offset < 0:
            return None
        hits.append(item)
    return tuple(hits)


def _run_scanner(scanner: LeakScanner, body: bytes, meta: EgressMeta, timeout: float) -> _Outcome:
    """Run one scanner with a time limit; every failure becomes ``error=True``.

    The exception itself is dropped, never logged: its message could quote the body. Only the
    scanner id reaches the log.
    """
    holder: dict[str, object] = {}
    scanner_id = scanner.id

    def target() -> None:
        # BaseException: not even SystemExit may reach the thread excepthook, which prints it.
        with contextlib.suppress(BaseException):
            holder["raw"] = scanner.scan(body, meta)

    worker = threading.Thread(target=target, name=f"egress-scan-{scanner_id}", daemon=True)
    worker.start()
    worker.join(timeout)
    hits = None if worker.is_alive() else _valid_hits(holder.get("raw"), scanner_id)
    if hits is None:
        _log.warning("egress_scanner_failed", scanner=scanner_id)
        return _Outcome((), True)
    return _Outcome(hits, False)


class _TicketBook:
    """The guard's live tickets: bounded, process-local, thread-safe, single use."""

    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._live: OrderedDict[str, EgressTicket] = OrderedDict()

    def add(self, ticket: EgressTicket) -> None:
        with self._lock:
            now = self._clock()
            for tag in [tag for tag, live in self._live.items() if live.expires_at <= now]:
                del self._live[tag]
            self._live[ticket.tag] = ticket
            while len(self._live) > _MAX_LIVE_TICKETS:
                self._live.popitem(last=False)

    def redeem(
        self, ticket: EgressTicket, payload_hash: str, provider: str, level: PrivacyLevel
    ) -> None:
        """Consume ``ticket`` or raise ``EgressBlocked``; any failed redemption burns the ticket."""
        with self._lock:
            live = self._live.pop(ticket.tag, None)
            now = self._clock()
        if live is None:
            raise EgressBlocked("ticket_expired")  # unknown, already used or evicted
        if live != ticket:
            raise EgressBlocked("hash_mismatch")  # same tag, altered fields
        if now >= ticket.expires_at:
            raise EgressBlocked("ticket_expired")
        if payload_hash != ticket.payload_hash:
            raise EgressBlocked("hash_mismatch")
        if provider != ticket.provider:
            raise EgressBlocked("provider_not_allowed")
        if level is not ticket.level:
            raise EgressBlocked("level_not_permitted")

    def live_count(self) -> int:
        with self._lock:
            return len(self._live)


def _mint(book: _TicketBook, meta: EgressMeta, ttl_seconds: int, now: datetime) -> EgressTicket:
    """The only place an ``EgressTicket`` is built (a convention a test enforces)."""
    ticket = EgressTicket(
        payload_hash=meta.payload_hash,
        provider=meta.provider,
        level=meta.level,
        expires_at=now + timedelta(seconds=ttl_seconds),
        tag=secrets.token_hex(16),
    )
    book.add(ticket)
    return ticket


def host_allowed(host: str | None, allowlist: Sequence[str]) -> bool:
    """True when ``allowlist`` names ``host`` (``*.example.com`` matches subdomains only).

    The list is default-deny: an empty list allows no remote host, and so does a provider with no
    ``base_url``, whose host cannot be checked here.
    """
    if host is None:
        return False
    name = host.lower().rstrip(".")
    for entry in allowlist:
        pattern = entry.lower()
        if pattern.startswith("*."):
            if name.endswith(pattern[1:]) and len(name) > len(pattern) - 1:
                return True
        elif name == pattern:
            return True
    return False


MIN_STATIC_CHARS = 24
# These two judge the size and the share of the whole request, so they read the whole request.
WHOLE_BODY_SCANNERS = frozenset({"budget", "aggregation"})


def mask_static(body: bytes, static_text: Sequence[str]) -> bytes | None:
    """``body`` with each trusted fragment replaced by ``null``, or ``None`` when there is none.

    A fragment is found as it was written (the schema's JSON) and as a JSON string body, escaped
    with and without ASCII-only output, because that is how a prompt sits inside the request.
    ``null`` is valid both as a JSON value (where the schema sat) and inside a string, so a JSON
    body stays JSON and the scanners keep reading its decoded strings.
    """
    fragments = [text for text in static_text if len(text) >= MIN_STATIC_CHARS]
    if not fragments:
        return None
    masked = body
    for text in fragments:
        needles = {
            text.encode("utf-8"),
            json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8"),
            json.dumps(text, ensure_ascii=True)[1:-1].encode("utf-8"),
        }
        for needle in needles:
            masked = masked.replace(needle, b"null")
    return masked


def payload_in_body(body: bytes, meta: EgressMeta, payload_text: str | None) -> bool:
    """True when the body really contains the payload that ``meta.payload_hash`` names.

    With the payload text, its SHA-256 must equal the hash and the text must occur in the body, as
    UTF-8 or as JSON string content. Without it, the hash digest itself must occur in the body.
    """
    if payload_text is None:
        return meta.payload_hash.encode("ascii") in body
    raw = payload_text.encode("utf-8")
    if sha256_hex(raw) != meta.payload_hash:
        return False
    if raw in body:
        return True
    for ensure_ascii in (False, True):
        if json.dumps(payload_text, ensure_ascii=ensure_ascii)[1:-1].encode("utf-8") in body:
            return True
    return False


class EgressGuard:
    """Decides whether one serialised request may leave the machine.

    ``evaluate`` is a function of the body, the metadata, the vault, the settings and the consent
    decision. Nothing interactive happens inside it: a request that would need confirmation blocks
    with ``consent_missing`` and the operator re-runs after granting consent (E05-13).
    """

    def __init__(
        self,
        registry: ScannerRegistry | None = None,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.registry = registry if registry is not None else ScannerRegistry()
        self._clock = clock
        self._book = _TicketBook(clock)

    def evaluate(
        self,
        body: bytes,
        meta: EgressMeta,
        *,
        settings: Settings,
        consent: ConsentDecision | None,
        vault: VaultOriginals | None = None,
        payload_text: str | None = None,
        static_text: Sequence[str] = (),
    ) -> EgressDecision:
        """Return the decision for ``body``; never raises and never allows on an error.

        ``static_text`` is text that CodeKavach itself wrote into the request (the fixed rubric of
        a prompt, the answer schema) and that therefore holds no client data. The content scanners
        do not look at it, because a client identifier such as ``name`` or ``config`` is also an
        ordinary word of the rubric and would otherwise block every request. It must come from the
        task, never from a provider; a part shorter than ``MIN_STATIC_CHARS`` is ignored, so it
        cannot be used to hide an identifier. The size and aggregation scanners still see the whole
        body, and the payload check uses the whole body.
        """
        scanned: tuple[str, ...] = ()
        hits: tuple[LeakHit, ...] = ()
        try:
            code = self._preconditions(body, meta, settings, consent, payload_text)
            if code is None:
                scanned = self.registry.ids
                hits, errored = self._scan(
                    body, meta, settings, vault, mask_static(body, static_text)
                )
                code = self._block_code(hits, errored or not scanned)
            decision = self._decide(meta, settings, code, hits)
        except Exception:  # noqa: BLE001 - nothing may turn an internal failure into a pass
            decision = EgressDecision(allowed=False, block_code="scanner_error")
        try:
            self._audit(decision, meta, scanned, body)
        except Exception:  # noqa: BLE001 - a request that cannot be audited does not leave
            return EgressDecision(allowed=False, block_code="scanner_error")
        return decision

    def redeem(
        self, ticket: EgressTicket, *, payload_hash: str, provider: str, level: PrivacyLevel
    ) -> None:
        """Consume ``ticket`` for the request about to be sent; raises ``EgressBlocked``."""
        try:
            self._book.redeem(ticket, payload_hash, provider, level)
        except EgressBlocked as blocked:
            _log.warning("egress_ticket_refused", block_code=blocked.block_code)
            raise

    @property
    def live_tickets(self) -> int:
        """How many minted tickets are still redeemable; the count is bounded."""
        return self._book.live_count()

    # ------------------------------------------------------------------ internals

    def _preconditions(
        self,
        body: bytes,
        meta: EgressMeta,
        settings: Settings,
        consent: ConsentDecision | None,
        payload_text: str | None,
    ) -> str | None:
        provider = settings.llm.providers.get(meta.provider)
        if provider is None or not self._provider_permitted(provider, settings):
            return "provider_not_allowed"
        if not self._level_permitted(meta.level, provider, settings):
            return "level_not_permitted"
        if provider.is_remote and (consent is None or not consent.granted):
            return "consent_missing"
        if not payload_in_body(body, meta, payload_text):
            return "hash_mismatch"
        return None

    @staticmethod
    def _provider_permitted(provider: ProviderSettings, settings: Settings) -> bool:
        if not settings.llm.enabled or not provider.enabled:
            return False
        if not provider.is_remote:
            return True
        allowlist = settings.privacy.egress.provider_host_allowlist
        return settings.llm.allow_remote and (
            host_allowed(provider.host, allowlist)
            or (provider.host is not None and provider.host == provider.preset_host)
        )

    @staticmethod
    def _level_permitted(
        level: PrivacyLevel, provider: ProviderSettings, settings: Settings
    ) -> bool:
        if level is PrivacyLevel.L0 and provider.is_remote:
            return False  # L0 sends nothing outside the machine
        floor = settings.privacy.floor_for_tier(provider.effective_trust_tier)
        return level.at_least(floor)

    def _scan(
        self,
        body: bytes,
        meta: EgressMeta,
        settings: Settings,
        vault: VaultOriginals | None,
        content: bytes | None = None,
    ) -> tuple[tuple[LeakHit, ...], bool]:
        timeout = settings.privacy.egress.scanner_timeout_seconds
        hits: list[LeakHit] = []
        errored = False
        for scanner in self.registry:
            if isinstance(scanner, BoundScanner):
                try:
                    scanner.bind(vault, settings)
                except Exception:  # noqa: BLE001 - an unbindable scanner is an error, not a pass
                    errored = True
                    continue
            seen = body if scanner.id in WHOLE_BODY_SCANNERS or content is None else content
            outcome = _run_scanner(scanner, seen, meta, timeout)
            errored = errored or outcome.error
            hits.extend(outcome.hits)
        return tuple(hits), errored

    @staticmethod
    def _block_code(hits: tuple[LeakHit, ...], errored: bool) -> str | None:
        if hits:
            return min((hit.block_code for hit in hits), key=priority)
        return "scanner_error" if errored else None

    def _decide(
        self, meta: EgressMeta, settings: Settings, code: str | None, hits: tuple[LeakHit, ...]
    ) -> EgressDecision:
        if code is not None:
            return EgressDecision(allowed=False, block_code=code, hits=hits)
        ticket = _mint(self._book, meta, settings.privacy.egress.ticket_ttl_seconds, self._clock())
        return EgressDecision(allowed=True, ticket=ticket)

    @staticmethod
    def _audit(
        decision: EgressDecision, meta: EgressMeta, scanned: tuple[str, ...], body: bytes
    ) -> None:
        """One log line: ids, counts, the code and hash prefixes; never matched text.

        ``body_hash_prefix`` is recorded apart from ``payload_hash_prefix``: the payload is only
        part of what leaves, and the two answer different questions in an audit.
        """
        counts: dict[str, int] = {}
        for hit in decision.hits:
            counts[hit.scanner_id] = counts.get(hit.scanner_id, 0) + hit.count
        _log.info(
            "egress_decision",
            scanners=list(scanned),
            hit_counts=counts,
            decision="allowed" if decision.allowed else "blocked",
            block_code=decision.block_code,
            provider=meta.provider,
            model=meta.model,
            level=str(meta.level),
            payload_hash_prefix=meta.payload_hash[:12],
            body_hash_prefix=sha256_hex(body)[:12],
        )
