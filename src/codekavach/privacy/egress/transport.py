"""Egress transport: the only way out to LLM endpoints.

Owning epic: E12. Normative layout: docs/ARCHITECTURE.md section 3.

Invariant I1 (ADR-0003): only this module opens connections to model endpoints. An import
contract (``.importlinter``, contract ``i1-single-egress``) and the ruff ban on ``socket``,
``ssl``, ``urllib.request`` and ``http.client`` outside this file make that checkable, and the
socket-blocking test fixture fails any test that opens a socket anywhere else.

**One HTTP client.** ``httpx`` (BSD-3-Clause), imported here and nowhere else. Rejected:
``requests`` (cannot express a total timeout and has no first-class control over redirects and
proxies from the environment), ``aiohttp`` (would force an asynchronous core), and the standard
library's ``http.client`` (TLS verification and proxy handling would be hand-rolled). Do not add a
second client for convenience; an exception needs its own record (cross-epic decision D-L).

**What a send is.** ``Transport.send(request, ticket)`` checks, in this order and before any byte
leaves: the method, the URL (HTTPS only; plain HTTP only for a local provider that resolves to
loopback; no credentials in the URL; no IP literal for a remote provider; the host on the
allow-list; no private or link-local address for a public provider), the header allow-list, that
the ticket's payload hash is in the body, and finally the ticket itself against the guard's live
book (process-local, unexpired, unconsumed). A refusal before the ticket check does not burn the
ticket. Certificate verification is always on and there is no argument that turns it off; redirects
are never followed; the proxy comes from ``privacy.egress.proxy_url`` and never from the
environment; the response is read with a size cap and a total deadline.

**What it does not do.** It never writes the ledger: the caller writes ``sent`` or ``failed``
around the call, so that the two responsibilities stay apart. It never logs a header value or a
body byte (the log line carries method, host, path template, status, sizes, elapsed time and a
payload-hash prefix), and no exception or ``repr`` carries one either.

**Limits, stated plainly.**

* A loopback endpoint is not proof that nothing left the machine: a local model runner can route
  some model tags to its vendor's servers while the client still talks to ``127.0.0.1``. The
  provider entry declares whether it is local, the configuration reference warns about
  cloud-routing tags, and the attestation records the provider and model used.
* A proxy is a new trust boundary (adversary A4, ``docs/research/INSIGHTS.md`` section 4.1). It is
  used only when ``privacy.egress.proxy_url`` is set, and ``attestation()`` reports it.
* The address check resolves the name once, and ``httpx`` resolves it again when it connects. A
  resolver that answers differently the second time (DNS rebinding) is not caught here; the host
  allow-list is the control for that.
"""

import hashlib
import ipaddress
import random
import re
import socket
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import urlsplit

import httpx

from codekavach.config import Settings
from codekavach.config.models.llm import ProviderSettings, is_loopback_host
from codekavach.core.log import get_logger
from codekavach.core.models import TrustTier
from codekavach.privacy.egress.guard import EgressGuard, host_allowed, payload_in_body
from codekavach.privacy.egress.models import EgressBlocked, EgressMeta, EgressTicket

_log = get_logger(__name__)

ALLOWED_METHODS: Final = frozenset({"POST", "GET"})
ALLOWED_HEADERS: Final = frozenset(
    {
        "authorization",
        "x-api-key",
        "api-key",
        "content-type",
        "accept",
        "user-agent",
        # gateways that accept only their own client identify it with this header (AgentRouter)
        "originator",
        "x-goog-api-key",
        # AWS Signature Version 4 (Bedrock)
        "x-amz-date",
        "x-amz-content-sha256",
        "x-amz-security-token",
    }
)
_VERSION_HEADER: Final = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*-version$")
MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
TRANSIENT_STATUSES: Final = frozenset({408, 429, 500, 502, 503, 504})
_CONNECT_TIMEOUT_SECONDS: Final = 10.0
_RESOLUTION_TTL_SECONDS: Final = 30.0
_BACKOFF_BASE_SECONDS: Final = 0.5
_BACKOFF_CAP_SECONDS: Final = 20.0
_OFFLINE_KINDS: Final = frozenset({"mock", "replay"})
_PATH_ID: Final = re.compile(r"/(?!v\d+(?:\.\d+)*(?=/|$))[^/]*\d[^/]*")

PROBE_TEXT: Final = "codekavach-probe"


class Refusal:
    """The closed vocabulary of reasons a request is refused before it is sent."""

    METHOD: Final = "method_not_allowed"
    URL: Final = "url_not_allowed"
    SCHEME: Final = "scheme_not_allowed"
    HOST: Final = "host_not_allowed"
    IP_LITERAL: Final = "ip_literal_not_allowed"
    PRIVATE_ADDRESS: Final = "private_address_not_allowed"
    HEADER: Final = "header_not_allowed"
    BODY_HASH: Final = "payload_hash_not_in_body"
    PROVIDER: Final = "provider_not_usable"


class TransportRefused(EgressBlocked):
    """A request failed the connection policy; nothing was sent.

    It is an ``EgressBlocked`` with the code ``provider_not_allowed`` (so the CLI maps it to the
    privacy exit code) and a ``reason`` from :class:`Refusal`. It carries no URL and no header.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__("provider_not_allowed")
        self.reason = reason

    def __str__(self) -> str:
        return f"provider_not_allowed ({self.reason})"

    def __repr__(self) -> str:
        return f"TransportRefused({self.reason!r})"


class TransportError(Exception):
    """A request was sent (or tried) and failed on the way; ``kind`` is the whole message."""

    __slots__ = ("kind",)

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind

    def __str__(self) -> str:
        return self.kind

    def __repr__(self) -> str:
        return f"TransportError({self.kind!r})"


class OutboundRequest(Protocol):
    """What a provider adapter hands over; structural, so this module imports nothing from llm."""

    @property
    def method(self) -> str:
        """``POST`` or ``GET``."""
        ...

    @property
    def url(self) -> str:
        """The absolute URL."""
        ...

    @property
    def headers(self) -> Mapping[str, str]:
        """Header names and values; only allow-listed names are accepted."""
        ...

    @property
    def body(self) -> bytes:
        """The serialised request body."""
        ...


@dataclass(frozen=True, slots=True, repr=False)
class SimpleRequest:
    """A plain ``OutboundRequest`` for callers that have no adapter of their own."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes

    def __repr__(self) -> str:
        return describe(self)


@dataclass(frozen=True, slots=True, repr=False)
class OutboundResponse:
    """What came back: a status, headers, a bounded body and the elapsed time."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    elapsed_ms: float
    dry_run: bool = False

    def __repr__(self) -> str:
        return (
            f"OutboundResponse(status={self.status}, bytes={len(self.body)}, "
            f"elapsed_ms={self.elapsed_ms:.0f}, dry_run={self.dry_run})"
        )


@dataclass(frozen=True, slots=True)
class TransportAttestation:
    """What the privacy attestation records about the path a request takes."""

    proxy_configured: bool
    proxy_trust: str


@dataclass(frozen=True, slots=True)
class Delivery:
    """What the caller needs to write its ledger entry: sizes and the outcome, no content."""

    provider: str
    payload_hash: str
    bytes_out: int
    bytes_in: int
    status: int | None
    elapsed_ms: float
    dry_run: bool
    error_kind: str | None = None


def path_template(path: str) -> str:
    """``/v1/accounts/42/items`` as ``/v1/accounts/{}/items``: segments with a digit are values."""
    return _PATH_ID.sub("/{}", path) or "/"


def describe(request: OutboundRequest) -> str:
    """The loggable subset of a request: method, host, path template and body length."""
    parts = urlsplit(request.url)
    host = parts.hostname or "?"
    return (
        f"{request.method} {host}{path_template(parts.path)} "
        f"(body {len(request.body)} bytes, {len(request.headers)} headers)"
    )


def _addresses(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


def _loopback_only(addresses: Sequence[str]) -> bool:
    return bool(addresses) and all(ipaddress.ip_address(a).is_loopback for a in addresses)


def _only_global(addresses: Sequence[str]) -> bool:
    return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses)


class _Policy:
    """The connection policy; shared by the real transport and the dry run."""

    def __init__(
        self,
        guard: EgressGuard,
        settings: Settings,
        resolver: Callable[[str], Sequence[str]],
        clock: Callable[[], float],
    ) -> None:
        self._guard = guard
        self._settings = settings
        self._resolver = resolver
        self._clock = clock
        self._resolved: dict[str, tuple[float, tuple[str, ...]]] = {}

    def provider_of(self, ticket: EgressTicket) -> ProviderSettings:
        provider = self._settings.llm.providers.get(ticket.provider)
        if provider is None or not provider.enabled or provider.kind.value in _OFFLINE_KINDS:
            raise TransportRefused(Refusal.PROVIDER)
        return provider

    def _addresses_of(self, host: str) -> tuple[str, ...]:
        now = self._clock()
        cached = self._resolved.get(host)
        if cached is not None and now - cached[0] < _RESOLUTION_TTL_SECONDS:
            return cached[1]
        try:
            found = tuple(self._resolver(host))
        except OSError:
            raise TransportRefused(Refusal.HOST) from None
        self._resolved[host] = (now, found)
        return found

    def check_url(self, url: str, provider: ProviderSettings) -> None:
        try:
            parts = urlsplit(url)
            host = parts.hostname
            parts.port  # noqa: B018 - raises ValueError for a bad port
        except ValueError:
            raise TransportRefused(Refusal.URL) from None
        if not host or parts.username is not None or parts.password is not None or parts.fragment:
            raise TransportRefused(Refusal.URL)
        local = provider.effective_trust_tier is TrustTier.LOCAL
        literal = _is_ip_literal(host)
        if literal and not local:
            raise TransportRefused(Refusal.IP_LITERAL)
        if parts.scheme == "https":
            pass
        elif parts.scheme == "http":
            if not (local and is_loopback_host(host)):
                raise TransportRefused(Refusal.SCHEME)
        else:
            raise TransportRefused(Refusal.SCHEME)
        if local:
            if (
                parts.scheme == "http"
                and not literal
                and not _loopback_only(self._addresses_of(host))
            ):
                raise TransportRefused(Refusal.SCHEME)
            return
        allowlist = self._settings.privacy.egress.provider_host_allowlist
        if not host_allowed(host, allowlist) and host != provider.preset_host:
            raise TransportRefused(Refusal.HOST)
        if provider.effective_trust_tier is TrustTier.PUBLIC and not _only_global(
            self._addresses_of(host)
        ):
            raise TransportRefused(Refusal.PRIVATE_ADDRESS)

    @staticmethod
    def check_headers(headers: Mapping[str, str]) -> None:
        for name in headers:
            lowered = name.lower()
            if lowered not in ALLOWED_HEADERS and not _VERSION_HEADER.match(lowered):
                raise TransportRefused(Refusal.HEADER)

    def verify(
        self, request: OutboundRequest, ticket: EgressTicket, payload_text: str | None
    ) -> ProviderSettings:
        """Every check that does not consume the ticket; raises ``TransportRefused``."""
        if request.method.upper() not in ALLOWED_METHODS:
            raise TransportRefused(Refusal.METHOD)
        provider = self.provider_of(ticket)
        self.check_url(request.url, provider)
        self.check_headers(request.headers)
        if not _hash_in_body(request.body, ticket, payload_text):
            raise TransportRefused(Refusal.BODY_HASH)
        return provider

    def redeem(self, ticket: EgressTicket) -> None:
        self._guard.redeem(
            ticket,
            payload_hash=ticket.payload_hash,
            provider=ticket.provider,
            level=ticket.level,
        )


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _hash_in_body(body: bytes, ticket: EgressTicket, payload_text: str | None) -> bool:
    # The guard's own test, applied to the bytes that are about to leave.
    meta = EgressMeta(
        provider=ticket.provider,
        model="-",
        level=ticket.level,
        payload_hash=ticket.payload_hash,
    )
    return payload_in_body(body, meta, payload_text)


class Transport:
    """Sends a ticketed request to a model endpoint; see the module docstring."""

    def __init__(
        self,
        guard: EgressGuard,
        settings: Settings,
        *,
        http_transport: httpx.BaseTransport | None = None,
        resolver: Callable[[str], Sequence[str]] = _addresses,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._settings = settings
        self._policy = _Policy(guard, settings, resolver, clock)
        self._clock = clock
        self._sleep = sleep
        self._rng = rng if rng is not None else random.Random()  # noqa: S311 - jitter, not security
        self._http_transport = http_transport
        self._clients: dict[bool, httpx.Client] = {}

    def attestation(self) -> TransportAttestation:
        """Whether a proxy is in the path, and what it may do."""
        egress = self._settings.privacy.egress
        return TransportAttestation(egress.proxy_url is not None, egress.proxy_trust)

    def close(self) -> None:
        """Close the connection pools."""
        for client in self._clients.values():
            client.close()
        self._clients.clear()

    # ------------------------------------------------------------------ sending

    def send(
        self, request: OutboundRequest, ticket: EgressTicket, *, payload_text: str | None = None
    ) -> OutboundResponse:
        """Send ``request`` under ``ticket`` and return the response.

        Raises:
            TransportRefused: the connection policy refused the request; the ticket is kept.
            EgressBlocked: the ticket is unknown, expired, consumed or altered; nothing was sent.
            TransportError: the request failed on the way (``kind`` says how).
        """
        return self.deliver(request, ticket, payload_text=payload_text)[0]

    def deliver(
        self, request: OutboundRequest, ticket: EgressTicket, *, payload_text: str | None = None
    ) -> tuple[OutboundResponse, Delivery]:
        """Like ``send``, also returning what the caller needs for its ledger entry."""
        provider = self._policy.verify(request, ticket, payload_text)
        self._policy.redeem(ticket)
        started = self._clock()
        try:
            response = self._perform(request, provider)
        except TransportError as error:
            self._log(request, ticket, None, 0, started)
            raise TransportError(error.kind) from None
        elapsed = (self._clock() - started) * 1000.0
        self._log(request, ticket, response.status, len(response.body), started)
        delivery = Delivery(
            ticket.provider,
            ticket.payload_hash,
            len(request.body),
            len(response.body),
            response.status,
            elapsed,
            dry_run=False,
        )
        return response, delivery

    def send_with_retries(
        self,
        request: OutboundRequest,
        issue_ticket: Callable[[], EgressTicket],
        *,
        payload_text: str | None = None,
        max_retries: int | None = None,
        is_refusal: Callable[[OutboundResponse], bool] = lambda _response: False,
    ) -> OutboundResponse:
        """Send, retrying only a connection error or a transient status.

        ``issue_ticket`` is called before every attempt, the first included, and must return a
        fresh ticket (it runs the guard again), so a retried body is scanned again. A response
        that ``is_refusal`` calls a content-policy refusal is returned and never retried.
        """
        attempts = 1 + (self._settings.llm.max_retries if max_retries is None else max_retries)
        for attempt in range(attempts):
            last = attempt == attempts - 1
            ticket = issue_ticket()
            try:
                response = self.send(request, ticket, payload_text=payload_text)
            except TransportError as error:
                if last or error.kind not in {"connect", "timeout"}:
                    raise
            else:
                if last or response.status not in TRANSIENT_STATUSES or is_refusal(response):
                    return response
            self._sleep(self._backoff(attempt))
        raise TransportError("retries_exhausted")  # pragma: no cover - the loop always returns

    def _backoff(self, attempt: int) -> float:
        base = min(_BACKOFF_CAP_SECONDS, _BACKOFF_BASE_SECONDS * (2**attempt))
        return float(base * self._rng.uniform(0.5, 1.5))

    def probe(
        self,
        provider_id: str,
        issue_ticket: Callable[[bytes, str], EgressTicket],
        *,
        record: Callable[[Delivery], None],
    ) -> OutboundResponse:
        """A fixed, content-free request to ``provider_id``, ticketed like any other.

        ``issue_ticket(body, payload_hash)`` runs the guard on the probe body and returns its
        ticket (or raises ``EgressBlocked``). ``record`` is called with the delivery so that the
        caller writes the ledger entry: a diagnostic call appears in the audit trail too.
        """
        provider = self._settings.llm.providers.get(provider_id)
        if provider is None or provider.base_url is None:
            raise TransportRefused(Refusal.PROVIDER)
        body = PROBE_TEXT.encode("ascii")
        digest = _sha256(PROBE_TEXT)
        request = SimpleRequest(
            "POST", str(provider.base_url), {"content-type": "text/plain"}, body + digest.encode()
        )
        ticket = issue_ticket(request.body, digest)
        try:
            response, delivery = self.deliver(request, ticket)
        except TransportError as error:
            record(
                Delivery(provider_id, digest, len(request.body), 0, None, 0.0, False, error.kind)
            )
            raise
        record(delivery)
        return response

    # ------------------------------------------------------------------ internals

    def _client(self, provider: ProviderSettings) -> httpx.Client:
        proxied = provider.effective_trust_tier is not TrustTier.LOCAL
        client = self._clients.get(proxied)
        if client is not None:
            return client
        egress = self._settings.privacy.egress
        total = float(self._settings.llm.timeout_seconds)
        client = httpx.Client(
            transport=self._http_transport,
            proxy=egress.proxy_url if proxied else None,
            trust_env=False,
            follow_redirects=False,
            http2=False,
            timeout=httpx.Timeout(total, connect=min(_CONNECT_TIMEOUT_SECONDS, total)),
        )
        self._clients[proxied] = client
        return client

    def _perform(self, request: OutboundRequest, provider: ProviderSettings) -> OutboundResponse:
        total = float(self._settings.llm.timeout_seconds)
        started = self._clock()
        client = self._client(provider)
        try:
            with client.stream(
                request.method.upper(),
                request.url,
                headers=dict(request.headers),
                content=request.body,
            ) as reply:
                if 300 <= reply.status_code < 400:
                    raise TransportError("redirect")
                chunks: list[bytes] = []
                size = 0
                for chunk in reply.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise TransportError("response_too_large")
                    if self._clock() - started > total:
                        raise TransportError("timeout")
                    chunks.append(chunk)
                headers = {name.lower(): value for name, value in reply.headers.items()}
                status = reply.status_code
        except TransportError:
            raise
        except httpx.TimeoutException:
            raise TransportError("timeout") from None
        except httpx.ConnectError as error:
            raise TransportError("tls" if _is_tls(error) else "connect") from None
        except httpx.HTTPError:
            raise TransportError("protocol") from None
        elapsed = (self._clock() - started) * 1000.0
        return OutboundResponse(status, headers, b"".join(chunks), elapsed)

    def _log(
        self,
        request: OutboundRequest,
        ticket: EgressTicket,
        status: int | None,
        bytes_in: int,
        started: float,
    ) -> None:
        parts = urlsplit(request.url)
        _log.info(
            "egress_send",
            provider=ticket.provider,
            method=request.method.upper(),
            host=parts.hostname,
            path=path_template(parts.path),
            status=status,
            bytes_out=len(request.body),
            bytes_in=bytes_in,
            elapsed_ms=round((self._clock() - started) * 1000.0),
            payload_hash_prefix=ticket.payload_hash[:12],
        )


def _is_tls(error: httpx.ConnectError) -> bool:
    return "CERTIFICATE" in str(error).upper() or "SSL" in str(error).upper()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class DryRunTransport:
    """Runs every check of ``Transport.send`` and sends nothing (``--no-send``).

    The ticket is redeemed, as in a real send, so the dry run exercises the same path; the answer
    is a synthetic ``204`` flagged ``dry_run``. ``deliveries`` holds what a real send would have
    reported, for the ledger entry the caller writes. No socket is opened.
    """

    def __init__(
        self,
        guard: EgressGuard,
        settings: Settings,
        *,
        resolver: Callable[[str], Sequence[str]] = _addresses,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = _Policy(guard, settings, resolver, clock)
        self.deliveries: list[Delivery] = []

    def send(
        self, request: OutboundRequest, ticket: EgressTicket, *, payload_text: str | None = None
    ) -> OutboundResponse:
        """Check, redeem, record and answer with a synthetic response."""
        self._policy.verify(request, ticket, payload_text)
        self._policy.redeem(ticket)
        self.deliveries.append(
            Delivery(
                ticket.provider,
                ticket.payload_hash,
                len(request.body),
                0,
                None,
                0.0,
                dry_run=True,
            )
        )
        return OutboundResponse(204, {"x-codekavach-dry-run": "1"}, b"", 0.0, dry_run=True)
